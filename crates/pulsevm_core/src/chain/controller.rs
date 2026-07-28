use core::fmt;
use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    sync::LazyLock,
};

use crate::{
    PULSE_NAME,
    block::{BlockStatus, SignedBlock},
    chain::{
        apply_context::ApplyContext,
        authorization_manager::AuthorizationManager,
        block::BlockHeader,
        config::{
            DELETEAUTH_NAME, LINKAUTH_NAME, NEWACCOUNT_NAME, SETABI_NAME, SETCODE_NAME,
            UNLINKAUTH_NAME, UPDATEAUTH_NAME, eos_percent,
        },
        id::Id,
        mempool::Mempool,
        name::Name,
        pulse_contract::{
            deleteauth, linkauth, newaccount, setabi, setcode, unlinkauth, updateauth,
        },
        resource_limits::ResourceLimitsManager,
        state_history::StateHistoryLog,
        transaction::{PackedTransaction, TransactionReceipt, TransactionTrace},
        transaction_context::{TransactionContext, TransactionResult},
        utils::make_ratio,
        wasm_runtime::WasmRuntime,
    },
    config::NodeConfig,
    transaction::Action,
};

use pulsevm_constants::{
    BLOCK_CPU_USAGE_AVERAGE_WINDOW_MS, BLOCK_INTERVAL_MS, BLOCK_SIZE_AVERAGE_WINDOW_MS,
    MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER,
};
use pulsevm_crypto::{Digest, merkle};
use pulsevm_error::ChainError;
use cxx::UniquePtr;
use pulsevm_ffi::{
    BlockTimestamp, CxxGenesisState, Database, ElasticLimitParameters, GlobalPropertyObject,
    TimePoint, UndoSession, seconds,
};
use pulsevm_grpc::vm;
use pulsevm_serialization::{Read, Write};
use spdlog::{debug, error, info, warn};

pub type ApplyHandlerFn = fn(&mut ApplyContext, &mut Database, &Action) -> Result<(), ChainError>;
pub type ApplyHandlerMap = HashMap<
    (Name, Name, Name), // (receiver, contract, action)
    ApplyHandlerFn,
>;

pub static APPLY_HANDLERS: LazyLock<ApplyHandlerMap> = LazyLock::new(|| {
    let mut m: ApplyHandlerMap = HashMap::new();
    m.insert((PULSE_NAME, PULSE_NAME, NEWACCOUNT_NAME), newaccount);
    m.insert((PULSE_NAME, PULSE_NAME, SETCODE_NAME), setcode);
    m.insert((PULSE_NAME, PULSE_NAME, SETABI_NAME), setabi);
    m.insert((PULSE_NAME, PULSE_NAME, UPDATEAUTH_NAME), updateauth);
    m.insert((PULSE_NAME, PULSE_NAME, DELETEAUTH_NAME), deleteauth);
    m.insert((PULSE_NAME, PULSE_NAME, LINKAUTH_NAME), linkauth);
    m.insert((PULSE_NAME, PULSE_NAME, UNLINKAUTH_NAME), unlinkauth);
    m
});

pub struct Controller {
    wasm_runtime: WasmRuntime,
    last_accepted_block: SignedBlock,
    last_accepted_block_id: Id,
    preferred_id: Id,
    db: Database,
    verified_blocks: HashMap<Id, SignedBlock>,
    chain_id: Id,
    state: vm::State,

    block_log: Option<StateHistoryLog>,
    trace_log: Option<StateHistoryLog>,
    chain_state_log: Option<StateHistoryLog>,
    node_config: Option<NodeConfig>,

    // The chain of blocks that have been executed (during build or verify) but
    // not yet accepted, ordered oldest first. Their state is materialized on the
    // live database as a stack of chainbase undo sessions on top of
    // `last_accepted_block_id`: `pending_chain[0].parent == last_accepted_block_id`
    // and `pending_chain[i].parent == pending_chain[i-1].id`. Retaining these lets
    // `replay_accepted_state_to` reuse an already-executed prefix instead of
    // re-running every unaccepted ancestor, and lets `accept_block` commit the
    // front block without re-executing it.
    pending_chain: Vec<PendingBlock>,

    // Count of `execute_block` invocations, for measuring how much re-execution
    // the pending-chain reuse actually avoids. Not consensus state.
    blocks_executed: u64,
}

struct PendingBlock {
    id: Id,
    // Parent block id. For the front of the chain this equals the last accepted
    // block; for later entries it is the previous entry's id.
    parent: Id,
    // Live chainbase undo session holding this block's state mutations. Kept
    // alive (neither pushed nor undone) so the state stays applied; accepting the
    // block pushes+commits it, unwinding undoes it.
    session: UniquePtr<UndoSession>,
    // Transaction traces produced during execution, needed by `store_traces` at
    // accept time. Retaining them avoids recomputing via a second execution.
    traces: Vec<TransactionTrace>,
}

impl Drop for Controller {
    fn drop(&mut self) {
        // The pending sessions form a chainbase undo stack and must be released in
        // reverse (LIFO) order. Letting the `Vec<PendingBlock>` drop naturally would
        // destroy them oldest-first, undoing the stack out of order and corrupting
        // it. Pop from the tip so each session's destructor undoes the top state.
        while self.pending_chain.pop().is_some() {}
    }
}

#[derive(Debug)]
pub enum ControllerError {
    GenesisError(String),
}

impl fmt::Display for ControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControllerError::GenesisError(msg) => write!(f, "Genesis error: {}", msg),
        }
    }
}

impl Controller {
    pub fn new() -> Self {
        // Create a temporary database
        let wasm_runtime = WasmRuntime::new().unwrap();

        Controller {
            wasm_runtime,
            last_accepted_block: SignedBlock::default(),
            last_accepted_block_id: Id::default(),
            preferred_id: Id::default(),
            db: Database::default(),
            verified_blocks: HashMap::new(),
            chain_id: Id::default(),
            state: vm::State::Unspecified,

            block_log: None,
            trace_log: None,
            chain_state_log: None,
            node_config: None,

            pending_chain: Vec::new(),
            blocks_executed: 0,
        }
    }

    // The id of the block whose state is currently live on the database: the tip
    // of the pending chain, or the last accepted block when the chain is empty.
    fn pending_tip_id(&self) -> Id {
        self.pending_chain
            .last()
            .map(|p| p.id)
            .unwrap_or(self.last_accepted_block_id)
    }

    // Undo and drop pending-chain entries from the tip down until only `len`
    // remain, restoring the live database to that prefix. Entries are undone in
    // reverse order to respect chainbase's LIFO undo stack.
    fn unwind_pending_to(&mut self, len: usize) -> Result<(), ChainError> {
        while self.pending_chain.len() > len {
            let mut entry = self.pending_chain.pop().unwrap();
            entry.session.pin_mut().undo().map_err(|e| {
                ChainError::DatabaseError(format!(
                    "failed to undo pending block {}: {}",
                    entry.id, e
                ))
            })?;
        }
        Ok(())
    }

    // Discard the whole pending chain, restoring the database to the last
    // accepted state. Paths that must execute against the plain accepted base
    // call this first.
    fn clear_pending(&mut self) -> Result<(), ChainError> {
        self.unwind_pending_to(0)
    }

    pub fn initialize(
        &mut self,
        chain_id: &Id,
        config_bytes: &Vec<u8>,
        genesis_bytes: &Vec<u8>,
        db_path: &str,
    ) -> Result<(), ChainError> {
        info!("initializing controller with DB path: {}", db_path);
        // Parse config bytes
        let config_json = std::str::from_utf8(config_bytes).map_err(|e| {
            ChainError::ParseError(format!("failed to parse config bytes as UTF-8: {}", e))
        })?;
        self.node_config = Some(serde_json::from_str(config_json).map_err(|e| {
            ChainError::ParseError(format!(
                "failed to parse node config JSON: {} - {}",
                e, config_json
            ))
        })?);

        // Initialize database
        self.db = Database::new(&db_path, self.node_config.as_ref().unwrap().db_size)
            .map_err(|e| ChainError::InternalError(format!("failed to open database: {}", e)))?;
        self.db.add_indices()?;

        // Parse genesis bytes
        let genesis_json = std::str::from_utf8(genesis_bytes).map_err(|e| {
            ChainError::ParseError(format!("failed to parse genesis bytes as UTF-8: {}", e))
        })?;
        let genesis = CxxGenesisState::new(genesis_json)
            .map_err(|e| ChainError::ParseError(format!("failed to parse genesis: {}", e)))?;
        // TODO: Validate genesis state
        self.chain_id = chain_id.clone();
        self.block_log = Some(
            StateHistoryLog::open_with_magic(&db_path, "block_log", 0).map_err(|e| {
                ChainError::InternalError(format!("failed to open block log: {}", e))
            })?,
        );
        self.trace_log = Some(
            StateHistoryLog::open_with_magic(&db_path, "trace_log", 0).map_err(|e| {
                ChainError::InternalError(format!("failed to open trace log: {}", e))
            })?,
        );
        self.chain_state_log = Some(
            StateHistoryLog::open_with_magic(&db_path, "chain_state_log", 0).map_err(|e| {
                ChainError::InternalError(format!("failed to open chain state log: {}", e))
            })?,
        );

        // Set our last accepted block to the genesis block
        self.last_accepted_block = SignedBlock::new(
            Id::default(),
            genesis.get_initial_timestamp().into(),
            PULSE_NAME, // Use the provided producer name from genesis
            VecDeque::new(),
            Digest::default(),
            Digest::default(), // Placeholder action merkle root
        );
        self.last_accepted_block_id = self.last_accepted_block.id()?;
        self.preferred_id = self.last_accepted_block.id()?;

        let revision = self.db.revision();
        info!("database revision: {}", revision);

        if revision <= 0 {
            // Initialize the database with the genesis state
            info!("initializing database with genesis state");
            self.db.initialize_database(&genesis).map_err(|e| {
                ChainError::GenesisError(format!("failed to initialize database: {}", e))
            })?;
            self.db
                .set_revision(self.last_accepted_block.block_num() as i64)?;
            info!("database initialized successfully");
        }

        let revision = self.db.revision();
        let block_log_range = self.block_log.as_ref().unwrap().range();

        match block_log_range {
            None => {
                self.block_log
                    .as_ref()
                    .unwrap()
                    .append(
                        self.last_accepted_block.id()?,
                        &self.last_accepted_block.pack().map_err(|e| {
                            ChainError::GenesisError(format!(
                                "failed to pack genesis block for block log: {}",
                                e
                            ))
                        })?,
                    )
                    .map_err(|e| {
                        ChainError::GenesisError(format!(
                            "failed to append genesis block to block log: {}",
                            e
                        ))
                    })?;
            }
            Some((start, end)) => {
                if revision > end as i64 {
                    error!(
                        "database revision {} does not match block log end {}",
                        revision, end
                    );

                    return Err(ChainError::DatabaseError(format!(
                        "database revision {} does not match block log end {}",
                        revision, end
                    )));
                }

                info!("block log contains blocks from {} to {}", start, end);

                self.last_accepted_block = self.get_block_by_height(end)?.ok_or_else(|| {
                    ChainError::DatabaseError(format!(
                        "failed to retrieve last block from block log at height {}",
                        end
                    ))
                })?;
                self.last_accepted_block_id = self.last_accepted_block.id()?;
                self.preferred_id = self.last_accepted_block.id()?;
            }
        }

        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), ChainError> {
        // Release the pending chain's live undo sessions before the database is
        // torn down. `close()` destroys the chainbase indices the sessions point
        // into, so leaving them live would make their destructors (and `Drop`)
        // touch freed memory.
        self.clear_pending()?;

        // Explicitly close the database
        info!("shutting down controller and closing database");
        self.db.close()?;
        info!("database closed successfully");
        Ok(())
    }

    pub async fn build_block(&mut self, mempool: &mut Mempool) -> Result<SignedBlock, ChainError> {
        let mut transaction_receipts: VecDeque<TransactionReceipt> = VecDeque::new();
        let mut transaction_traces: Vec<TransactionTrace> = Vec::new();
        let mut action_receipt_digests: VecDeque<Digest> = VecDeque::new();
        let timestamp: BlockTimestamp = TimePoint::now().into();
        let block_status = BlockStatus::Building;

        // Transactions already present in a verified-but-not-yet-accepted block
        // must not be included again. At build time the earlier block has not
        // committed its `transaction_object` dedup record yet, so a re-gossiped
        // copy of one of its transactions passes `record_transaction` here and
        // gets packed into this block too. The duplicate is only detected later,
        // when this block is verified after the earlier one is accepted — at
        // which point `record_transaction` fails permanently and the block can
        // never validate, halting the chain (it is retried forever by consensus).
        // Defer such transactions instead of dropping them: if the pending block
        // is accepted they are removed from the mempool then; if it is rejected
        // on a fork they remain available for a later block.
        let pending_tx_ids: HashSet<Id> = self
            .verified_blocks
            .values()
            .flat_map(|b| b.transactions.iter().map(|r| r.trx().id().clone()))
            .collect();
        let mut deferred: Vec<PackedTransaction> = Vec::new();

        // Build on top of preferred: reconcile the pending chain so the database
        // holds the preferred state, reusing any already-executed prefix.
        self.replay_accepted_state_to(self.preferred_id, &block_status, mempool)?;

        let mut db = self.db.clone();
        let mut block_session = db.create_undo_session(true)?;

        // Expiry clearing is part of the block's state, so it belongs inside the
        // block's session rather than before it.
        db.clear_expired_input_transactions(&timestamp.into())?;

        // Get transactions from the mempool
        while let Some(transaction) = mempool.pop_transaction() {
            if pending_tx_ids.contains(transaction.id()) {
                deferred.push(transaction);
                continue;
            }

            let mut child_session = db.create_undo_session(true)?;
            let transaction_result =
                self.execute_transaction(&transaction, &timestamp, &block_status);

            match transaction_result {
                Ok(result) => {
                    child_session.pin_mut().squash().map_err(|e| {
                        ChainError::DatabaseError(format!(
                            "failed to commit transaction changes: {}",
                            e
                        ))
                    })?; // Push changes to upstream session

                    // Add the transaction to the block
                    transaction_traces.push(result.trace.clone());
                    let receipt = TransactionReceipt::new(result.trace.receipt, transaction);
                    transaction_receipts.push_back(receipt);
                    action_receipt_digests.extend(result.action_receipt_digests);
                }
                Err(e) => {
                    warn!(
                        "transaction {} failed to execute, dropping: {}",
                        transaction.id(),
                        e
                    );

                    child_session.pin_mut().undo().map_err(|e| {
                        ChainError::DatabaseError(format!("failed to undo changes: {}", e))
                    })?; // Revert changes made during this transaction
                }
            }
        }

        // Return deferred transactions to the mempool for a later block.
        for tx in deferred {
            mempool.add_transaction(tx);
        }

        // Don't build a block if we have no transactions
        if transaction_receipts.len() == 0 {
            block_session.pin_mut().undo().map_err(|e| {
                ChainError::DatabaseError(format!("failed to undo changes: {}", e))
            })?;
            return Err(ChainError::NetworkError(format!(
                "built block has no transactions"
            )));
        }

        // Create a new block
        let transaction_mroot = self.calculate_trx_merkle(&transaction_receipts)?;
        let action_mroot = self.calculate_action_merkle(&mut action_receipt_digests)?;
        let block = SignedBlock::new(
            self.preferred_id,
            timestamp,
            self.node_config.as_ref().unwrap().producer_name, // Use producer name from config
            transaction_receipts,
            transaction_mroot,
            action_mroot,
        );

        // We built this block so no need to verify it again
        let block_id = block.id()?;
        self.verified_blocks.insert(block_id, block.clone());

        // Match the end-of-block bookkeeping that `execute_block` applies at
        // verify/accept, so the retained state is identical to what a re-execution
        // would commit, then retain the block on the pending chain (it was built
        // on the current tip).
        self.finalize_block_resources(block.block_num())?;
        self.pending_chain.push(PendingBlock {
            id: block_id,
            parent: self.preferred_id,
            session: block_session,
            traces: transaction_traces,
        });

        Ok(block)
    }

    pub async fn verify_block(
        &mut self,
        block: &SignedBlock,
        mempool: &mut Mempool,
    ) -> Result<(), ChainError> {
        if self.verified_blocks.contains_key(&block.id()?) {
            return Ok(());
        } else if let Some(block_log) = &self.block_log {
            if let Ok(existing_block) = block_log.read_block(block.block_num()) {
                let existing_block = SignedBlock::read(existing_block.as_slice(), &mut 0)?;

                if existing_block.id()? == block.id()? {
                    self.verified_blocks.insert(block.id()?, block.clone());
                    warn!(
                        "block {} already exists in block log, skipping verification",
                        block.id()?
                    );
                    return Ok(());
                } else {
                    warn!(
                        "block {} has same block number as existing block in block log but different id, rejecting",
                        block.id()?
                    );
                    return Err(ChainError::NetworkError(format!(
                        "block with id {} has same block number as existing block in block log but different id",
                        block.id()?
                    )));
                }
            }
        }

        // Verify the block
        block.validate_syntactically(&self.db)?;

        let parent_block_id = block.previous_id().clone();
        let block_status = BlockStatus::Verifying;
        // Reconcile the pending chain to the parent, reusing any already-executed
        // prefix instead of re-running every unaccepted ancestor.
        self.replay_accepted_state_to(parent_block_id.clone(), &block_status, mempool)?;

        // This block's own session sits on top of the reconciled parent state. If
        // execution or validation below fails, `?` drops the session and chainbase
        // undoes it, leaving the pending chain at the parent.
        let block_session = self.db.create_undo_session(true)?;
        let (transaction_traces, transaction_mroot, action_mroot) =
            self.execute_block(block, &block_status, mempool)?;

        block.validate_semantically(transaction_mroot, action_mroot)?;

        let block_id = block.id()?;
        self.verified_blocks.insert(block_id, block.clone());

        // Retain the executed block on the pending chain so `accept_block` can
        // commit it without re-executing.
        self.pending_chain.push(PendingBlock {
            id: block_id,
            parent: parent_block_id,
            session: block_session,
            traces: transaction_traces,
        });

        Ok(())
    }

    pub fn accept_block(&mut self, block_id: &Id, mempool: &mut Mempool) -> Result<(), ChainError> {
        let block = {
            self.verified_blocks
                .get(block_id)
                .cloned()
                .ok_or(ChainError::NetworkError(format!(
                    "block with id {} not verified",
                    block_id
                )))?
        };

        // Pack the block before touching the pending chain. In the fast path below
        // the front session is `remove`d from the chain but only detached from
        // auto-undo by `push()` afterwards; a fallible step in between (like this
        // pack) that bailed via `?` would drop the front session and wrongly undo
        // the chain *tip* (the front is the stack bottom). Doing it here keeps the
        // remove(0)→push() window free of fallible operations.
        let packed_block = block.pack().map_err(|e| {
            ChainError::TransactionError(format!("failed to pack block {}: {}", block_id, e))
        })?;

        // Fast path: consensus accepts blocks in order, so the accepted block is
        // the front of the pending chain (its parent is the last accepted block,
        // which the chain invariant guarantees). Commit that retained session and
        // reuse its traces rather than re-executing. The rest of the chain stays
        // live: chainbase commits only the oldest undo state.
        let front_matches = self
            .pending_chain
            .first()
            .map(|p| p.id == *block_id)
            .unwrap_or(false);

        let (mut session, transaction_traces) = if front_matches {
            let front = self.pending_chain.remove(0);
            // `execute_block` removes accepted transactions from the mempool as it
            // runs; the retained pass did not (build pops them while assembling,
            // verify never touches the mempool), so mirror that here.
            for receipt in &block.transactions {
                mempool.remove_transaction(receipt.trx().id());
            }
            (front.session, front.traces)
        } else {
            // Fallback: the block is not the retained front (e.g. a fork sibling
            // won, or nothing is pending). Discard the pending chain and execute
            // the block fresh on top of the last accepted state.
            if block.previous_id() != &self.last_accepted_block_id {
                return Err(ChainError::NetworkError(format!(
                    "cannot accept block {} out of order: its parent is not the last accepted block",
                    block_id
                )));
            }
            self.clear_pending()?;
            let session = self.db.create_undo_session(true)?;
            let block_status = BlockStatus::Accepting;
            let (transaction_traces, _transaction_mroot, _action_mroot) = self
                .execute_block(&block, &block_status, mempool)
                .map_err(|e| {
                    ChainError::DatabaseError(format!(
                        "failed to execute block {}: {}",
                        block_id, e
                    ))
                })?;
            (session, transaction_traces)
        };

        session
            .pin_mut()
            .push()
            .map_err(|e| ChainError::TransactionError(format!("failed to commit block: {}", e)))?;
        self.block_log
            .as_ref()
            .map(|log| log.append(block_id.clone(), &packed_block));
        self.store_traces(block_id, &transaction_traces)?;
        self.store_chain_state(block_id)?;
        self.verified_blocks.remove(block_id);
        self.last_accepted_block = block.clone();
        self.last_accepted_block_id = block.id()?;
        self.db.commit(block.block_num() as i64)?;

        if self.get_state() == &vm::State::NormalOp {
            info!(
                "block {} accepted successfully with {} transactions",
                block_id,
                block.transactions.len()
            );
        } else if block.block_num() % 1000 == 0 {
            info!(
                "block {} accepted successfully with {} transactions, current state: {:?}",
                block_id,
                block.transactions.len(),
                self.get_state()
            );
        }

        Ok(())
    }

    pub fn reject_block(&mut self, block_id: &Id, mempool: &mut Mempool) -> Result<(), ChainError> {
        // If the rejected block is on the pending chain, unwind it and everything
        // built on top of it (its descendants can no longer be accepted either),
        // restoring the live database to the state below it.
        if let Some(idx) = self.pending_chain.iter().position(|p| &p.id == block_id) {
            self.unwind_pending_to(idx)?;
        }

        let block = {
            self.verified_blocks
                .get(block_id)
                .cloned()
                .ok_or(ChainError::NetworkError(format!(
                    "block with id {} not verified",
                    block_id
                )))?
        };

        // Add transactions back to the mempool
        for receipt in &block.transactions {
            mempool.add_transaction(receipt.trx().clone());
        }

        self.verified_blocks.remove(block_id);

        Ok(())
    }

    pub fn execute_block(
        &mut self,
        block: &SignedBlock,
        block_status: &BlockStatus,
        mempool: &mut Mempool,
    ) -> Result<(Vec<TransactionTrace>, Digest, Digest), ChainError> {
        let mut transaction_traces: Vec<TransactionTrace> = Vec::new();
        let mut transaction_receipts: VecDeque<TransactionReceipt> = VecDeque::new();
        let mut action_receipt_digests: VecDeque<Digest> = VecDeque::new();

        self.blocks_executed += 1;

        self.db
            .clear_expired_input_transactions(&block.timestamp().to_time_point())?;

        for receipt in &block.transactions {
            // Verify the transaction
            let result = self.execute_transaction(
                receipt.trx(),
                &block.signed_block_header.header.timestamp,
                block_status,
            )?;

            // Add trace to traces
            transaction_traces.push(result.trace.clone());
            transaction_receipts.push_back(TransactionReceipt::new(
                result.trace.receipt,
                receipt.trx().clone(),
            ));
            action_receipt_digests.extend(result.action_receipt_digests);

            // Remove from mempool if we have it
            if block_status == &BlockStatus::Accepting {
                mempool.remove_transaction(receipt.trx().id());
            }
        }

        let transaction_mroot = self.calculate_trx_merkle(&transaction_receipts)?;
        let action_mroot = self.calculate_action_merkle(&mut action_receipt_digests)?;

        self.finalize_block_resources(block.block_num())?;

        Ok((transaction_traces, transaction_mroot, action_mroot))
    }

    // Apply the end-of-block resource-limit bookkeeping. This is part of the
    // block's committed state and must run identically whether the block is
    // executed via `execute_block` (verify/accept) or assembled in `build_block`,
    // otherwise a retained build session would commit state that diverges from
    // what validators compute.
    fn finalize_block_resources(&mut self, block_num: u32) -> Result<(), ChainError> {
        let global_property = Controller::get_global_properties(&self.db)?;
        let chain_config = global_property.get_chain_config();
        let cpu_target = eos_percent(
            chain_config.get_max_block_cpu_usage() as u64,
            chain_config.get_target_block_cpu_usage_pct(),
        );
        let cpu_elastic_parameters = ElasticLimitParameters::new(
            cpu_target,
            chain_config.get_max_block_cpu_usage() as u64,
            BLOCK_CPU_USAGE_AVERAGE_WINDOW_MS / BLOCK_INTERVAL_MS,
            MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER,
            make_ratio(99, 100),
            make_ratio(1000, 999),
        );
        let net_elastic_parameters = ElasticLimitParameters::new(
            eos_percent(
                chain_config.get_max_block_net_usage() as u64,
                chain_config.get_target_block_net_usage_pct(),
            ),
            chain_config.get_max_block_net_usage() as u64,
            BLOCK_SIZE_AVERAGE_WINDOW_MS / BLOCK_INTERVAL_MS,
            MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER,
            make_ratio(99, 100),
            make_ratio(1000, 999),
        );
        ResourceLimitsManager::process_account_limit_updates(&mut self.db)?;
        ResourceLimitsManager::set_block_parameters(
            &mut self.db,
            &cpu_elastic_parameters,
            &net_elastic_parameters,
        )?;
        ResourceLimitsManager::process_block_usage(&mut self.db, block_num)?;

        Ok(())
    }

    // This function will execute a transaction and roll it back instantly
    // This is useful for checking if a transaction is valid
    pub fn push_transaction(
        &mut self,
        transaction: &PackedTransaction,
        pending_block_timestamp: &BlockTimestamp,
        block_status: &BlockStatus,
    ) -> Result<TransactionResult, ChainError> {
        let mut db = self.db.clone();
        let _undo_session = db.create_undo_session(true)?;
        let result =
            self.execute_transaction(transaction, pending_block_timestamp, block_status)?;
        return Ok(result);
    }

    // This function will execute a transaction and commit it to the database
    // This is useful for applying a transaction to the blockchain
    pub fn execute_transaction(
        &mut self,
        packed_transaction: &PackedTransaction,
        pending_block_timestamp: &BlockTimestamp,
        block_status: &BlockStatus,
    ) -> Result<TransactionResult, ChainError> {
        let signed_transaction = packed_transaction.get_signed_transaction();

        // Verify basic transaction validity
        signed_transaction
            .transaction()
            .validate(pending_block_timestamp)?;

        // Verify authority
        AuthorizationManager::check_authorization(
            &mut self.db,
            &signed_transaction.transaction().actions,
            &signed_transaction.recovered_keys(&self.chain_id)?,
            &BTreeSet::new(),
            seconds(signed_transaction.transaction().header.delay_sec.into()),
            &BTreeSet::new(),
        )?;

        let mut trx_context = TransactionContext::new(
            self.db.clone(),
            self.wasm_runtime.clone(),
            self.last_accepted_block().block_num() + 1,
            pending_block_timestamp.clone(),
            packed_transaction.id(),
            *block_status,
            packed_transaction.clone(),
        );

        let trx = packed_transaction.get_transaction();
        trx_context.init_for_input_trx(
            packed_transaction.get_unprunable_size()?,
            packed_transaction.get_prunable_size()?,
            &trx,
        )?;
        trx_context.exec(&trx)?;
        let result = trx_context.finalize()?;

        Ok(result)
    }

    pub fn last_accepted_block(&self) -> &SignedBlock {
        &self.last_accepted_block
    }

    pub fn get_block_by_height(&self, height: u32) -> Result<Option<SignedBlock>, ChainError> {
        if height == self.last_accepted_block.block_num() {
            return Ok(Some(self.last_accepted_block.clone()));
        }

        // Query DB
        let res = match self.block_log()?.read_block(height) {
            Ok(block) => Some(SignedBlock::read(block.as_slice(), &mut 0)?),
            Err(_) => None,
        };

        return Ok(res);
    }

    pub fn get_block_id_for_num(&self, height: u32) -> Result<Option<Id>, ChainError> {
        let block = self.get_block_by_height(height)?;

        match block {
            None => Ok(None),
            Some(block) => Ok(Some(block.id()?)),
        }
    }

    pub fn get_block(&self, id: Id) -> Result<Option<SignedBlock>, ChainError> {
        if self.verified_blocks.contains_key(&id) {
            return Ok(self.verified_blocks.get(&id).cloned());
        }

        let num = BlockHeader::num_from_id(&id);

        self.get_block_by_height(num)
    }

    pub fn parse_block(&self, bytes: &Vec<u8>) -> Result<SignedBlock, ControllerError> {
        let mut pos = 0;
        let block = SignedBlock::read(bytes, &mut pos)
            .map_err(|e| ControllerError::GenesisError(format!("Failed to parse block: {}", e)))?;
        Ok(block)
    }

    pub fn set_preferred_id(&mut self, id: Id) {
        self.preferred_id = id;
    }

    pub fn find_apply_handler(receiver: &Name, scope: &Name, act: &Name) -> Option<ApplyHandlerFn> {
        if let Some(handler) = APPLY_HANDLERS.get(&(*receiver, *scope, *act)) {
            return Some(*handler);
        }
        None
    }

    pub fn get_wasm_runtime(&self) -> &WasmRuntime {
        &self.wasm_runtime
    }

    pub fn get_global_properties(db: &Database) -> Result<&GlobalPropertyObject, ChainError> {
        let res = db.get_global_properties().map_err(|e| {
            ChainError::DatabaseError(format!("failed to get global properties: {}", e))
        })?;

        Ok(unsafe { &*res })
    }

    pub fn database(&self) -> Database {
        self.db.clone()
    }

    pub fn chain_id(&self) -> &Id {
        &self.chain_id
    }

    pub fn calculate_trx_merkle(
        &self,
        receipts: &VecDeque<TransactionReceipt>,
    ) -> Result<Digest, ChainError> {
        let mut trx_digests = VecDeque::new();

        for receipt in receipts {
            let digest = receipt.digest().map_err(|e| {
                ChainError::TransactionError(format!(
                    "failed to calculate transaction digest: {}",
                    e
                ))
            })?;
            trx_digests.push_back(digest);
        }

        Ok(merkle(&mut trx_digests))
    }

    pub fn calculate_action_merkle(
        &self,
        digests: &mut VecDeque<Digest>,
    ) -> Result<Digest, ChainError> {
        Ok(merkle(digests))
    }

    pub fn trace_log(&self) -> Option<&StateHistoryLog> {
        self.trace_log.as_ref()
    }

    pub fn chain_state_log(&self) -> Option<&StateHistoryLog> {
        self.chain_state_log.as_ref()
    }

    pub async fn get_block_id(&self, block_num: u32) -> Result<Option<Id>, ChainError> {
        let trace_log = self.trace_log();
        let chain_state_log = self.chain_state_log();
        let block_log = self.block_log()?;

        if let Some(log) = trace_log {
            if let Some(entry) = log.get_block_id(block_num).ok() {
                return Ok(Some(entry));
            }
        }

        if let Some(log) = chain_state_log {
            if let Some(entry) = log.get_block_id(block_num).ok() {
                return Ok(Some(entry));
            }
        }

        if let Some(entry) = block_log.get_block_id(block_num).ok() {
            return Ok(Some(entry));
        }

        Err(ChainError::InternalError(format!(
            "failed to get block id from logs"
        )))
    }

    pub fn block_log(&self) -> Result<&StateHistoryLog, ChainError> {
        self.block_log
            .as_ref()
            .ok_or_else(|| ChainError::InternalError("block log not initialized".to_string()))
    }

    pub fn store_traces(
        &mut self,
        block_id: &Id,
        transaction_traces: &Vec<TransactionTrace>,
    ) -> Result<(), ChainError> {
        match &self.trace_log {
            None => {
                return Err(ChainError::InternalError(
                    "trace log not initialized".to_string(),
                ));
            }
            Some(trace_log) => {
                let packed_transaction_traces = transaction_traces.pack().map_err(|e| {
                    ChainError::TransactionError(format!(
                        "failed to pack transaction traces for block {}: {}",
                        block_id, e
                    ))
                })?;

                trace_log
                    .append(block_id.clone(), &packed_transaction_traces)
                    .map_err(|e| {
                        ChainError::InternalError(format!("failed to append to trace log: {}", e))
                    })?;

                return Ok(());
            }
        }
    }

    pub fn store_chain_state(&mut self, block_id: &Id) -> Result<(), ChainError> {
        match &self.chain_state_log {
            None => {
                return Err(ChainError::InternalError(
                    "chain state log not initialized".to_string(),
                ));
            }
            Some(chain_state_log) => {
                let fresh = chain_state_log.range().is_none();
                let chain_state = self.db.pack_deltas(fresh)?;

                chain_state_log
                    .append(block_id.clone(), &chain_state)
                    .map_err(|e| {
                        ChainError::InternalError(format!(
                            "failed to append to chain state log: {}",
                            e
                        ))
                    })?;

                return Ok(());
            }
        }
    }

    pub fn set_state(&mut self, state: vm::State) {
        self.state = state;
    }

    pub fn get_state(&self) -> &vm::State {
        &self.state
    }

    // Make the live database hold the state at `block_id` (which must be the last
    // accepted block or one of its verified descendants), leaving the pending
    // chain equal to the path from the last accepted block up to `block_id`.
    //
    // Rather than re-executing every block on that path, this reuses the longest
    // prefix already materialized on the pending chain: it unwinds only the
    // entries that diverge from the target path and executes only the blocks not
    // already applied. When the pending chain already matches the target path
    // (the common case — building or verifying on the current tip) it is a no-op.
    pub fn replay_accepted_state_to(
        &mut self,
        block_id: Id,
        block_status: &BlockStatus,
        mempool: &mut Mempool,
    ) -> Result<(), ChainError> {
        // Desired path from last_accepted (exclusive) up to the target (inclusive),
        // oldest first.
        let mut path: Vec<SignedBlock> = Vec::new();
        let mut cursor = block_id;
        while cursor != self.last_accepted_block_id {
            let block = self
                .verified_blocks
                .get(&cursor)
                .ok_or_else(|| {
                    ChainError::NetworkError(format!(
                        "block {} not found in verified blocks",
                        cursor
                    ))
                })?
                .clone();
            let prev = block.previous_id().clone();
            path.push(block);
            cursor = prev;
        }
        path.reverse();

        // Longest prefix of the pending chain that already matches the target path.
        let mut common = 0;
        while common < self.pending_chain.len()
            && common < path.len()
            && self.pending_chain[common].id == path[common].id()?
        {
            common += 1;
        }

        // Drop the divergent tail, then execute and retain the blocks not yet applied.
        self.unwind_pending_to(common)?;
        for block in &path[common..] {
            debug!(
                "replaying block {} onto pending chain (tip {})",
                block.id()?,
                self.pending_tip_id()
            );
            let session = self.db.create_undo_session(true)?;
            let (traces, _transaction_mroot, _action_mroot) =
                self.execute_block(block, block_status, mempool)?;
            self.pending_chain.push(PendingBlock {
                id: block.id()?,
                parent: block.previous_id().clone(),
                session,
                traces,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, str::FromStr, sync::Arc, vec};

    use pulsevm_ffi::{Authority, KeyWeight, TimePointSec};
    use pulsevm_proc_macros::{NumBytes, Read, Write};
    use pulsevm_serialization::Write;
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::runtime;

    use crate::{
        ACTIVE_NAME,
        chain::{
            asset::{Asset, Symbol},
            authority::PermissionLevel,
            pulse_contract::{NewAccount, SetCode},
            transaction::{Action, Transaction, TransactionHeader},
        },
        crypto::PrivateKey,
    };

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
    struct Create {
        issuer: Name,
        max_supply: Asset,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
    struct Transfer {
        from: Name,
        to: Name,
        quantity: Asset,
        memo: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
    struct Issue {
        to: Name,
        quantity: Asset,
        memo: String,
    }

    fn get_temp_dir() -> TempDir {
        tempfile::tempdir().expect("failed to create temp dir")
    }

    fn generate_genesis(private_key: &PrivateKey) -> Vec<u8> {
        let genesis = json!(
        {
            "initial_timestamp": "2023-01-01T00:00:00",
            "initial_key": private_key.get_public_key().to_string(),
            "initial_configuration": {
                "max_block_net_usage": 1048576,
                "target_block_net_usage_pct": 1000,
                "max_transaction_net_usage": 524288,
                "base_per_transaction_net_usage": 12,
                "net_usage_leeway": 500,
                "context_free_discount_net_usage_num": 20,
                "context_free_discount_net_usage_den": 100,
                "max_block_cpu_usage": 200000,
                "target_block_cpu_usage_pct": 2500,
                "max_transaction_cpu_usage": 150000,
                "min_transaction_cpu_usage": 100,
                // The test transaction builders use TimePointSec::maximum() as the
                // expiration ("never expires"); allow that by widening the lifetime
                // window well past the default one hour.
                "max_transaction_lifetime": 4294967295u32,
                "max_inline_action_size": 4096,
                "max_inline_action_depth": 6,
                "max_authority_depth": 6,
                "max_action_return_value_size": 256
            }
        });
        genesis.to_string().into_bytes()
    }

    fn create_account(
        private_key: &PrivateKey,
        account: Name,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        create_account_with_expiration(private_key, account, chain_id, TimePointSec::maximum())
    }

    fn create_account_with_expiration(
        private_key: &PrivateKey,
        account: Name,
        chain_id: Id,
        expiration: TimePointSec,
    ) -> Result<PackedTransaction, ChainError> {
        let trx = Transaction::new(
            TransactionHeader::new(expiration, 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                Name::from_str("pulse")?,
                Name::from_str("newaccount")?,
                NewAccount {
                    creator: Name::from_str("pulse")?,
                    name: account,
                    owner: Authority::new(
                        1,
                        vec![KeyWeight::new(private_key.get_public_key().into(), 1)],
                        vec![],
                        vec![],
                    ),
                    active: Authority::new(
                        1,
                        vec![KeyWeight::new(private_key.get_public_key().into(), 1)],
                        vec![],
                        vec![],
                    ),
                }
                .pack()
                .unwrap(),
                vec![PermissionLevel::new(
                    PULSE_NAME.as_u64(),
                    ACTIVE_NAME.as_u64(),
                )],
            )],
        )
        .sign(&private_key, &chain_id)?;
        let packed_trx = PackedTransaction::from_signed_transaction(trx)?;
        Ok(packed_trx)
    }

    fn set_code(
        private_key: &PrivateKey,
        account: Name,
        wasm_bytes: Vec<u8>,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                Name::from_str("pulse").unwrap(),
                Name::from_str("setcode").unwrap(),
                SetCode {
                    account,
                    vm_type: 0,
                    vm_version: 0,
                    code: Arc::new(wasm_bytes.into()),
                }
                .pack()
                .unwrap(),
                vec![PermissionLevel::new(account.as_u64(), ACTIVE_NAME.as_u64())],
            )],
        )
        .sign(&private_key, &chain_id)?;
        let packed_trx = PackedTransaction::from_signed_transaction(trx)?;
        Ok(packed_trx)
    }

    fn call_contract<T: Write>(
        private_key: &PrivateKey,
        account: Name,
        action: Name,
        action_data: &T,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                account,
                action,
                action_data.pack().unwrap(),
                vec![PermissionLevel::new(account.as_u64(), ACTIVE_NAME.as_u64())],
            )],
        )
        .sign(&private_key, &chain_id)?;
        let packed_trx = PackedTransaction::from_signed_transaction(trx)?;
        Ok(packed_trx)
    }

    #[tokio::test]
    async fn test_initialize() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mut controller = Controller::new();
        let genesis_bytes = generate_genesis(&private_key);
        let temp_path = get_temp_dir();
        let config_bytes = json!({
            "producer_name": "pulse",
            "producer_key": private_key.to_string(),
        })
        .to_string()
        .into_bytes();
        controller.initialize(
            &chain_id,
            &config_bytes,
            &genesis_bytes.to_vec(),
            temp_path.path().to_str().unwrap(),
        )?;
        assert_eq!(controller.last_accepted_block().block_num(), 1);
        let pending_block_timestamp = controller.last_accepted_block().timestamp().clone();
        let chain_id = controller.chain_id().clone();
        let block_status = BlockStatus::Building;
        controller.execute_transaction(
            &create_account(&private_key, Name::from_str("glenn")?, chain_id)?,
            &pending_block_timestamp,
            &block_status,
        )?;
        controller.execute_transaction(
            &create_account(&private_key, Name::from_str("marshall")?, chain_id)?,
            &pending_block_timestamp,
            &block_status,
        )?;

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let pulse_token_contract =
            fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
        controller.execute_transaction(
            &set_code(
                &private_key,
                Name::from_str("glenn")?,
                pulse_token_contract,
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("glenn")?,
                Name::from_str("create")?,
                &Create {
                    issuer: Name::from_str("glenn")?,
                    max_supply: Asset::new(1000000, Symbol(1162826500)),
                },
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("glenn")?,
                Name::from_str("issue")?,
                &Issue {
                    to: Name::from_str("glenn")?,
                    quantity: Asset {
                        amount: 1000000,
                        symbol: Symbol(1162826500), // "PLUS" in ASCII
                    },
                    memo: "Initial transfer".to_string(),
                },
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("glenn")?,
                Name::from_str("transfer")?,
                &Transfer {
                    from: Name::from_str("glenn")?,
                    to: Name::from_str("marshall")?,
                    quantity: Asset {
                        amount: 5000,
                        symbol: Symbol(1162826500), // "PLUS" in ASCII
                    },
                    memo: "Initial transfer".to_string(),
                },
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        Ok(())
    }

    fn init_test_controller() -> Result<(Controller, PrivateKey, Id, TempDir), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mut controller = Controller::new();
        let genesis_bytes = generate_genesis(&private_key);
        let temp_path = get_temp_dir();
        let config_bytes = json!({
            "producer_name": "pulse",
            "producer_key": private_key.to_string(),
        })
        .to_string()
        .into_bytes();
        controller.initialize(
            &chain_id,
            &config_bytes,
            &genesis_bytes.to_vec(),
            temp_path.path().to_str().unwrap(),
        )?;
        Ok((controller, private_key, chain_id, temp_path))
    }

    // A block built directly on the last accepted block retains its executed
    // state, and accept_block commits that retained state without re-executing.
    #[tokio::test]
    async fn test_build_accept_reuses_pending_state() -> Result<(), ChainError> {
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;

        // build_block validates transaction lifetime against the real clock, so
        // use an expiration a minute out rather than the far-future default.
        let expiration = TimePointSec::new(TimePointSec::now().sec_since_epoch() + 60);
        let glenn = Name::from_str("glenn")?;
        let mut mempool = Mempool::new();
        mempool.add_transaction(create_account_with_expiration(
            &private_key,
            glenn,
            chain_id,
            expiration,
        )?);

        let base_block_num = controller.last_accepted_block().block_num();

        let block = controller.build_block(&mut mempool).await?;
        let block_id = block.id()?;

        // Build retained the executed state on top of the accepted base.
        assert_eq!(controller.pending_chain.len(), 1);
        let pending = &controller.pending_chain[0];
        assert_eq!(pending.id, block_id);
        assert_eq!(pending.parent, controller.last_accepted_block_id);

        controller.accept_block(&block_id, &mut mempool)?;

        // The fast path consumed the retained state rather than leaving it live.
        assert!(controller.pending_chain.is_empty());
        assert_eq!(controller.last_accepted_block_id, block_id);
        assert_eq!(controller.last_accepted_block().block_num(), base_block_num + 1);

        // The account created by the block is present in committed state, proving
        // the retained session was committed rather than discarded.
        let account = controller.database().find_account(glenn.as_u64())?;
        assert!(
            !account.is_null(),
            "accepted account should exist in committed state"
        );

        Ok(())
    }

    // Rejecting a retained pending block undoes its state and restores the base.
    #[tokio::test]
    async fn test_reject_discards_pending_state() -> Result<(), ChainError> {
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;

        let expiration = TimePointSec::new(TimePointSec::now().sec_since_epoch() + 60);
        let glenn = Name::from_str("glenn")?;
        let mut mempool = Mempool::new();
        mempool.add_transaction(create_account_with_expiration(
            &private_key,
            glenn,
            chain_id,
            expiration,
        )?);

        let base_block_id = controller.last_accepted_block_id;

        let block = controller.build_block(&mut mempool).await?;
        let block_id = block.id()?;
        assert!(!controller.pending_chain.is_empty());

        controller.reject_block(&block_id, &mut mempool)?;

        assert!(controller.pending_chain.is_empty());
        assert_eq!(controller.last_accepted_block_id, base_block_id);
        let account = controller.database().find_account(glenn.as_u64())?;
        assert!(
            account.is_null(),
            "rejected block's state must not persist in the database"
        );

        Ok(())
    }

    // Verifying a second block on top of a still-pending first block reuses the
    // first block's already-executed state instead of re-running it, and both can
    // then be accepted in order without further execution.
    #[tokio::test]
    async fn test_pending_chain_reuses_executed_prefix() -> Result<(), ChainError> {
        // Producer builds two chained blocks (b3 on top of the still-pending b2).
        let (mut producer, private_key, chain_id, _p_temp) = init_test_controller()?;
        let mut p_mempool = Mempool::new();
        p_mempool.add_transaction(create_account(&private_key, Name::from_str("aaa")?, chain_id)?);
        let b2 = producer.build_block(&mut p_mempool).await?;
        producer.set_preferred_id(b2.id()?);
        p_mempool.add_transaction(create_account(&private_key, Name::from_str("bbb")?, chain_id)?);
        let b3 = producer.build_block(&mut p_mempool).await?;
        assert_eq!(b3.previous_id(), &b2.id()?);

        // Validator verifies both, then accepts them in order.
        let (mut validator, _pk, _cid, _v_temp) = init_test_controller()?;
        let mut v_mempool = Mempool::new();

        validator.verify_block(&b2, &mut v_mempool).await?;
        assert_eq!(validator.pending_chain.len(), 1);
        assert_eq!(validator.blocks_executed, 1);

        validator.verify_block(&b3, &mut v_mempool).await?;
        assert_eq!(validator.pending_chain.len(), 2);
        // b2 was NOT re-executed to establish b3's parent state — only b3 ran.
        // The old replay-from-last-accepted behavior would have made this 3.
        assert_eq!(validator.blocks_executed, 2);

        validator.accept_block(&b2.id()?, &mut v_mempool)?;
        assert_eq!(validator.pending_chain.len(), 1);
        validator.accept_block(&b3.id()?, &mut v_mempool)?;
        assert!(validator.pending_chain.is_empty());

        // Acceptance committed the retained state without any extra execution.
        assert_eq!(validator.blocks_executed, 2);
        assert_eq!(validator.last_accepted_block_id, b3.id()?);
        assert_eq!(validator.last_accepted_block().block_num(), 3);

        // Both accounts are present in committed state.
        let db = validator.database();
        assert!(!db.find_account(Name::from_str("aaa")?.as_u64())?.is_null());
        assert!(!db.find_account(Name::from_str("bbb")?.as_u64())?.is_null());

        Ok(())
    }

    // Verifying a block on a competing fork reuses the common prefix, unwinds only
    // the divergent suffix, and executes only the new block. After accepting the
    // winning fork, the losing branch's state is absent.
    #[tokio::test]
    async fn test_pending_chain_reconciles_fork() -> Result<(), ChainError> {
        // Producer builds A, then two children of A: B and C (siblings).
        let (mut producer, private_key, chain_id, _p_temp) = init_test_controller()?;
        let mut p_mempool = Mempool::new();
        p_mempool.add_transaction(create_account(&private_key, Name::from_str("aaa")?, chain_id)?);
        let a = producer.build_block(&mut p_mempool).await?;

        producer.set_preferred_id(a.id()?);
        p_mempool.add_transaction(create_account(&private_key, Name::from_str("bbb")?, chain_id)?);
        let b = producer.build_block(&mut p_mempool).await?;

        // Re-prefer A so the next build reconciles back to A (unwinding B) and
        // builds C as B's sibling.
        producer.set_preferred_id(a.id()?);
        p_mempool.add_transaction(create_account(&private_key, Name::from_str("ccc")?, chain_id)?);
        let c = producer.build_block(&mut p_mempool).await?;
        assert_eq!(b.previous_id(), &a.id()?);
        assert_eq!(c.previous_id(), &a.id()?);
        assert_ne!(b.id()?, c.id()?);

        // Validator verifies A, then B, then diverges to C.
        let (mut validator, _pk, _cid, _v_temp) = init_test_controller()?;
        let mut v_mempool = Mempool::new();

        validator.verify_block(&a, &mut v_mempool).await?;
        validator.verify_block(&b, &mut v_mempool).await?;
        assert_eq!(validator.pending_chain.len(), 2);
        assert_eq!(validator.blocks_executed, 2);

        // Verifying C reuses A (no re-execution), unwinds B, and executes C.
        validator.verify_block(&c, &mut v_mempool).await?;
        assert_eq!(validator.pending_chain.len(), 2);
        assert_eq!(validator.pending_chain[0].id, a.id()?);
        assert_eq!(validator.pending_chain[1].id, c.id()?);
        assert_eq!(validator.blocks_executed, 3); // A, B, C — each once, A not re-run.

        // Accept the winning fork A -> C.
        validator.accept_block(&a.id()?, &mut v_mempool)?;
        validator.accept_block(&c.id()?, &mut v_mempool)?;
        assert!(validator.pending_chain.is_empty());
        assert_eq!(validator.last_accepted_block_id, c.id()?);

        // aaa and ccc are committed; bbb (the losing branch) is not.
        let db = validator.database();
        assert!(!db.find_account(Name::from_str("aaa")?.as_u64())?.is_null());
        assert!(!db.find_account(Name::from_str("ccc")?.as_u64())?.is_null());
        assert!(db.find_account(Name::from_str("bbb")?.as_u64())?.is_null());

        Ok(())
    }

    // Rejecting a block on the pending chain unwinds it and every descendant built
    // on top of it, restoring the last accepted state.
    #[tokio::test]
    async fn test_reject_unwinds_descendants() -> Result<(), ChainError> {
        let (mut producer, private_key, chain_id, _p_temp) = init_test_controller()?;
        let mut p_mempool = Mempool::new();
        p_mempool.add_transaction(create_account(&private_key, Name::from_str("aaa")?, chain_id)?);
        let a = producer.build_block(&mut p_mempool).await?;
        producer.set_preferred_id(a.id()?);
        p_mempool.add_transaction(create_account(&private_key, Name::from_str("bbb")?, chain_id)?);
        let b = producer.build_block(&mut p_mempool).await?;

        let (mut validator, _pk, _cid, _v_temp) = init_test_controller()?;
        let genesis_id = validator.last_accepted_block_id;
        let mut v_mempool = Mempool::new();
        validator.verify_block(&a, &mut v_mempool).await?;
        validator.verify_block(&b, &mut v_mempool).await?;
        assert_eq!(validator.pending_chain.len(), 2);

        // Rejecting A must also unwind B, which was built on top of it.
        validator.reject_block(&a.id()?, &mut v_mempool)?;
        assert!(validator.pending_chain.is_empty());
        assert_eq!(validator.last_accepted_block_id, genesis_id);

        let db = validator.database();
        assert!(db.find_account(Name::from_str("aaa")?.as_u64())?.is_null());
        assert!(db.find_account(Name::from_str("bbb")?.as_u64())?.is_null());

        Ok(())
    }

    #[tokio::test]
    async fn test_api_db() -> Result<(), ChainError> {
        let (mut controller, private_key, _chain_id, _temp) = init_test_controller()?;
        let pending_block_timestamp = controller.last_accepted_block().timestamp().clone();
        let chain_id = controller.chain_id().clone();
        let block_status = BlockStatus::Building;
        controller.execute_transaction(
            &create_account(&private_key, Name::from_str("testapi")?, chain_id)?,
            &pending_block_timestamp,
            &block_status,
        )?;
        controller.execute_transaction(
            &create_account(&private_key, Name::from_str("testapi2")?, chain_id)?,
            &pending_block_timestamp,
            &block_status,
        )?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let contract =
            fs::read(root.join(Path::new("reference_contracts/test_api_db.wasm"))).unwrap();
        controller.execute_transaction(
            &set_code(
                &private_key,
                Name::from_str("testapi")?,
                contract.clone(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;
        controller.execute_transaction(
            &set_code(
                &private_key,
                Name::from_str("testapi2")?,
                contract,
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("pg")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;
        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("pl")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;
        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("pu")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;
        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s1g")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;
        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s1l")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;
        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s1u")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        // Access checks
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
        struct TestInvalidAccess {
            code: Name,
            val: u64,
            index: u32,
            store: bool,
        }
        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("tia")?,
                &TestInvalidAccess {
                    code: Name::from_str("testapi")?,
                    val: 10,
                    index: 0,
                    store: true,
                },
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        let mut result = controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi2")?,
                Name::from_str("tia")?,
                &TestInvalidAccess {
                    code: Name::from_str("testapi")?,
                    val: 20,
                    index: 0,
                    store: true,
                },
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        );

        assert!(result.is_err());

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("tia")?,
                &TestInvalidAccess {
                    code: Name::from_str("testapi")?,
                    val: 10,
                    index: 0,
                    store: false,
                },
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;
        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("tia")?,
                &TestInvalidAccess {
                    code: Name::from_str("testapi")?,
                    val: 10,
                    index: 1,
                    store: true,
                },
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        result = controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi2")?,
                Name::from_str("tia")?,
                &TestInvalidAccess {
                    code: Name::from_str("testapi")?,
                    val: 20,
                    index: 1,
                    store: true,
                },
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        );

        assert!(result.is_err());

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("tia")?,
                &TestInvalidAccess {
                    code: Name::from_str("testapi")?,
                    val: 10,
                    index: 1,
                    store: false,
                },
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        Ok(())
    }

    #[test]
    fn test_multi_index() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let runtime = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mut controller = Controller::new();
        let genesis_bytes = generate_genesis(&private_key);
        let temp_path = get_temp_dir();
        let config_bytes = json!({
            "producer_name": "pulse",
            "producer_key": private_key.to_string(),
        })
        .to_string()
        .into_bytes();
        controller.initialize(
            &chain_id,
            &config_bytes,
            &genesis_bytes.to_vec(),
            temp_path.path().to_str().unwrap(),
        )?;
        let pending_block_timestamp = controller.last_accepted_block().timestamp().clone();
        let chain_id = controller.chain_id().clone();
        let block_status = BlockStatus::Building;
        controller.execute_transaction(
            &create_account(&private_key, Name::from_str("testapi")?, chain_id)?,
            &pending_block_timestamp,
            &block_status,
        )?;
        controller.execute_transaction(
            &create_account(&private_key, Name::from_str("testapi2")?, chain_id)?,
            &pending_block_timestamp,
            &block_status,
        )?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let contract =
            fs::read(root.join(Path::new("reference_contracts/test_api_multi_index.wasm")))
                .unwrap();
        controller.execute_transaction(
            &set_code(
                &private_key,
                Name::from_str("testapi")?,
                contract.clone(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s1g")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s1store")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s1check")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s2g")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s2store")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s2check")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s2autoinc")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s2autoinc1")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s2autoinc2")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s3g")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("sdg")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("sldg")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        let check_failure = |controller: &mut Controller, action: &str, expected_error: &str| {
            let result = controller.execute_transaction(
                &call_contract(
                    &private_key,
                    Name::from_str("testapi").unwrap(),
                    Name::from_str(action).unwrap(),
                    &Vec::<u8>::new(),
                    chain_id,
                )
                .unwrap(),
                &pending_block_timestamp,
                &block_status,
            );

            assert!(result.is_err());
            assert_eq!(result.err().unwrap().to_string(), expected_error);
        };

        check_failure(
            &mut controller,
            "s1pkend",
            "apply error: eosio assert failed: cannot increment end iterator",
        );
        check_failure(
            &mut controller,
            "s1skend",
            "apply error: eosio assert failed: cannot increment end iterator",
        );
        check_failure(
            &mut controller,
            "s1pkbegin",
            "apply error: eosio assert failed: cannot decrement iterator at beginning of table",
        );
        check_failure(
            &mut controller,
            "s1skbegin",
            "apply error: eosio assert failed: cannot decrement iterator at beginning of index",
        );
        check_failure(
            &mut controller,
            "s1pkref",
            "apply error: eosio assert failed: object passed to iterator_to is not in multi_index",
        );
        check_failure(
            &mut controller,
            "s1skref",
            "apply error: eosio assert failed: object passed to iterator_to is not in multi_index",
        );
        check_failure(
            &mut controller,
            "s1pkitrto",
            "apply error: eosio assert failed: object passed to iterator_to is not in multi_index",
        );
        check_failure(
            &mut controller,
            "s1pkmodify",
            "apply error: eosio assert failed: cannot pass end iterator to modify",
        );
        check_failure(
            &mut controller,
            "s1pkerase",
            "apply error: eosio assert failed: cannot pass end iterator to erase",
        );
        check_failure(
            &mut controller,
            "s1skitrto",
            "apply error: eosio assert failed: object passed to iterator_to is not in multi_index",
        );
        check_failure(
            &mut controller,
            "s1skmodify",
            "apply error: eosio assert failed: cannot pass end iterator to modify",
        );
        check_failure(
            &mut controller,
            "s1skerase",
            "apply error: eosio assert failed: cannot pass end iterator to erase",
        );
        check_failure(
            &mut controller,
            "s1modpk",
            "apply error: eosio assert failed: updater cannot change primary key when modifying an object",
        );
        check_failure(
            &mut controller,
            "s1exhaustpk",
            "apply error: eosio assert failed: next primary key in table is at autoincrement limit",
        );
        check_failure(
            &mut controller,
            "s1findfail1",
            "apply error: eosio assert failed: unable to find key",
        );
        check_failure(
            &mut controller,
            "s1findfail2",
            "apply error: eosio assert failed: unable to find primary key in require_find",
        );
        check_failure(
            &mut controller,
            "s1findfail3",
            "apply error: eosio assert failed: unable to find secondary key",
        );
        check_failure(
            &mut controller,
            "s1findfail4",
            "apply error: eosio assert failed: unable to find sec key",
        );

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s1skcache")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        controller.execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("testapi")?,
                Name::from_str("s1pkcache")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
            &block_status,
        )?;

        Ok(())
    }

    #[tokio::test]
    async fn test_verify_block() -> Result<(), ChainError> {
        // Build a valid block (with correct merkle roots) on a producer.
        let (mut producer, private_key, chain_id, _p_temp) = init_test_controller()?;
        let mut p_mempool = Mempool::new();
        p_mempool
            .add_transaction(create_account(&private_key, Name::from_str("testapi")?, chain_id)?);
        let block = producer.build_block(&mut p_mempool).await?;

        // A validator verifies it, accepts it, then a repeat verify short-circuits
        // because the block is now in the block log.
        let (mut validator, _pk, _cid, _v_temp) = init_test_controller()?;
        let mut v_mempool = Mempool::new();

        validator.verify_block(&block, &mut v_mempool).await?;
        assert_eq!(validator.pending_chain.len(), 1);

        validator.accept_block(&block.id()?, &mut v_mempool)?;
        assert!(validator.pending_chain.is_empty());
        assert_eq!(validator.last_accepted_block_id, block.id()?);

        validator.verify_block(&block, &mut v_mempool).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_push_transaction() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mut controller = Controller::new();
        let genesis_bytes = generate_genesis(&private_key);
        let temp_path = get_temp_dir();
        let config_bytes = json!({
            "producer_name": "pulse",
            "producer_key": private_key.to_string(),
        })
        .to_string()
        .into_bytes();
        controller.initialize(
            &chain_id,
            &config_bytes,
            &genesis_bytes.to_vec(),
            temp_path.path().to_str().unwrap(),
        )?;
        assert_eq!(controller.last_accepted_block().block_num(), 1);
        let pending_block_timestamp = controller.last_accepted_block().timestamp().clone();
        let chain_id = controller.chain_id().clone();
        let block_status = BlockStatus::Building;
        let result = controller.push_transaction(
            &create_account(&private_key, Name::from_str("testapi")?, chain_id)?,
            &pending_block_timestamp,
            &block_status,
        )?;
        assert_eq!(
            result.trace.receipt.status,
            crate::transaction::TransactionStatus::Executed
        );
        let digest = result.trace.id.to_digest()?;
        let found = controller
            .database()
            .is_known_unexpired_transaction(&digest)?;
        assert!(!found);

        Ok(())
    }
}
