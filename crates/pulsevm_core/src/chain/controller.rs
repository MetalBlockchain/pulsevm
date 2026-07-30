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
use pulsevm_ffi::{
    BlockTimestamp, CxxGenesisState, Database, ElasticLimitParameters, GlobalPropertyObject,
    TimePoint, seconds,
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
        }
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
        // Bring up the arena mirror now, before any write, so every ported
        // mutation is reflected. A no-op unless the arena-shadow feature is on.
        self.db.enable_shadow()?;

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

    pub fn shutdown(&self) -> Result<(), ChainError> {
        // Explicitly close the database
        info!("shutting down controller and closing database");
        self.db.close()?;
        info!("database closed successfully");
        Ok(())
    }

    pub async fn build_block(&mut self, mempool: &mut Mempool) -> Result<SignedBlock, ChainError> {
        let mut db = self.db.clone();
        let mut root_session = db.create_undo_session(true)?; // As we are building the block, drop the changes once built
        db.arena_start_undo_session(); // mirror the root session
        let mut transaction_receipts: VecDeque<TransactionReceipt> = VecDeque::new();
        let mut action_receipt_digests: VecDeque<Digest> = VecDeque::new();
        let timestamp: BlockTimestamp = TimePoint::now().into();
        let block_status = BlockStatus::Building;

        // Clear expired transactions from the database
        db.clear_expired_input_transactions(&timestamp.into())?;

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

        // We need to build on top of preferred id, so rollback state if needed
        self.replay_accepted_state_to(self.preferred_id, &BlockStatus::Building, mempool)?;

        // Get transactions from the mempool
        while let Some(transaction) = mempool.pop_transaction() {
            if pending_tx_ids.contains(transaction.id()) {
                deferred.push(transaction);
                continue;
            }

            let mut child_session = db.create_undo_session(true)?;
            db.arena_start_undo_session(); // mirror the per-transaction session
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
                    db.arena_squash(); // fold the tx into the block on both

                    // Add the transaction to the block
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
                    db.arena_undo(); // a failed tx leaves no trace on either
                }
            }
        }

        // Return deferred transactions to the mempool for a later block.
        for tx in deferred {
            mempool.add_transaction(tx);
        }

        // Don't build a block if we have no transactions
        if transaction_receipts.len() == 0 {
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
        self.verified_blocks.insert(
            block.signed_block_header.header.calculate_id()?,
            block.clone(),
        );

        root_session
            .pin_mut()
            .undo()
            .map_err(|e| ChainError::DatabaseError(format!("failed to undo changes: {}", e)))?; // Revert changes made during this transaction
        db.arena_undo(); // the built block is speculative; discard on both

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

        let mut root_session = self.db.create_undo_session(true)?;
        self.db.arena_start_undo_session(); // mirror the verify root session
        let parent_block_id = block.previous_id();
        let block_status = BlockStatus::Verifying;
        self.replay_accepted_state_to(parent_block_id.clone(), &block_status, mempool)?;
        let (_transaction_traces, transaction_mroot, action_mroot) =
            self.execute_block(block, &block_status, mempool)?;

        // Validate the block's transaction and action merkle roots
        block.validate_semantically(transaction_mroot, action_mroot)?;

        self.verified_blocks.insert(block.id()?, block.clone());

        root_session
            .pin_mut()
            .undo()
            .map_err(|e| ChainError::DatabaseError(format!("failed to undo changes: {}", e)))?; // Revert changes made during this transaction
        self.db.arena_undo(); // verification is speculative; discard on both

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

        let mut root_session = self.db.create_undo_session(true)?;
        self.db.arena_start_undo_session(); // mirror the accept root session; committed below
        let block_status = BlockStatus::Accepting;
        let parent_block_id = block.previous_id();
        self.replay_accepted_state_to(parent_block_id.clone(), &block_status, mempool)?;
        let (transaction_traces, _transaction_mroot, _action_mroot) = self
            .execute_block(&block, &block_status, mempool)
            .map_err(|e| {
                ChainError::DatabaseError(format!("failed to execute block {}: {}", block_id, e))
            })?;
        let packed_block = block.pack().map_err(|e| {
            ChainError::TransactionError(format!("failed to pack block {}: {}", block_id, e))
        })?;
        root_session
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

        // Accept boundary: commit the arena mirror in lockstep and surface its
        // root. The full session lockstep across build/verify is still to come;
        // for now this commits and logs the ported subset the shadow carries.
        self.db.arena_commit(block.block_num() as i64);
        if let Some(root) = self.db.arena_state_root() {
            debug!(
                "arena shadow root at block {}: {}",
                block.block_num(),
                hex::encode(root)
            );
        }

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

        self.db
            .clear_expired_input_transactions(&block.timestamp().to_time_point())?;

        for receipt in &block.transactions {
            // Verify the transaction
            let result = self.execute_transaction_billed(
                receipt.trx(),
                &block.signed_block_header.header.timestamp,
                block_status,
                Some((receipt.cpu_usage_us(), receipt.net_usage_words())),
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

        // Update resource limits
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
        ResourceLimitsManager::process_block_usage(&mut self.db, block.block_num())?;

        Ok((transaction_traces, transaction_mroot, action_mroot))
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
        db.arena_start_undo_session();
        let result = self.execute_transaction(transaction, pending_block_timestamp, block_status);
        // Mempool admission is advisory: `_undo_session` reverts chainbase when
        // it drops, so revert the arena in lockstep on both the ok and err path.
        db.arena_undo();
        result
    }

    // This function will execute a transaction and commit it to the database
    // This is useful for applying a transaction to the blockchain
    pub fn execute_transaction(
        &mut self,
        packed_transaction: &PackedTransaction,
        pending_block_timestamp: &BlockTimestamp,
        block_status: &BlockStatus,
    ) -> Result<TransactionResult, ChainError> {
        self.execute_transaction_billed(packed_transaction, pending_block_timestamp, block_status, None)
    }

    /// As `execute_transaction`, but when `explicit_billed` is set (applying an
    /// already-accepted block) it bills the block-recorded cpu/net and skips the
    /// objective resource-limit checks — Antelope light/replay validation.
    pub fn execute_transaction_billed(
        &mut self,
        packed_transaction: &PackedTransaction,
        pending_block_timestamp: &BlockTimestamp,
        block_status: &BlockStatus,
        explicit_billed: Option<(u32, u32)>,
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

        // Applying an already-accepted block: bill the recorded cpu/net and
        // skip the objective limit checks (Antelope light/replay validation).
        if let Some((cpu_us, net_words)) = explicit_billed {
            trx_context.set_explicit_billed(cpu_us, net_words)?;
        }

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

    // This function will replay the accepted state from the last accepted block to the given block id
    // This is useful for switching forks and making sure we have the correct state for the preferred block
    // In the future we should optimize chainbase so we can replay deltas instead of executing blocks, but for now this is simpler to implement and works fine for our use case
    pub fn replay_accepted_state_to(
        &mut self,
        block_id: Id,
        block_status: &BlockStatus,
        mempool: &mut Mempool,
    ) -> Result<(), ChainError> {
        // Build the path from target back to last_accepted, then reverse.
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

        // path is target..=first-child; replay oldest first
        for block in path.into_iter().rev() {
            debug!(
                "replaying accepted state from block {} to block {}",
                self.last_accepted_block_id,
                block.id()?
            );
            self.execute_block(&block, block_status, mempool)?;
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
    use tokio::{runtime, sync::RwLock};

    use crate::{
        ACTIVE_NAME,
        chain::{
            asset::{Asset, Symbol},
            authority::PermissionLevel,
            abi::AbiDefinition,
            pulse_contract::{
                DeleteAuth, LinkAuth, NewAccount, SetAbi, SetCode, UnlinkAuth, UpdateAuth,
            },
            transaction::{Action, Transaction, TransactionHeader},
        },
        crypto::PrivateKey,
        transaction::TransactionReceiptHeader,
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
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
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

    fn set_abi(
        private_key: &PrivateKey,
        account: Name,
        abi_bytes: Vec<u8>,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                Name::from_str("pulse").unwrap(),
                Name::from_str("setabi").unwrap(),
                SetAbi {
                    account,
                    abi: Arc::new(abi_bytes.into()),
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

    fn update_auth(
        private_key: &PrivateKey,
        account: Name,
        permission: Name,
        parent: Name,
        threshold: u32,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                Name::from_str("pulse").unwrap(),
                Name::from_str("updateauth").unwrap(),
                UpdateAuth {
                    account,
                    permission,
                    parent,
                    auth: Authority::new(
                        threshold,
                        vec![KeyWeight::new(private_key.get_public_key().into(), 1)],
                        vec![],
                        vec![],
                    ),
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

    fn link_auth(
        private_key: &PrivateKey,
        account: Name,
        code: Name,
        message_type: Name,
        requirement: Name,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                Name::from_str("pulse").unwrap(),
                Name::from_str("linkauth").unwrap(),
                LinkAuth {
                    account,
                    code,
                    message_type,
                    requirement,
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

    fn unlink_auth(
        private_key: &PrivateKey,
        account: Name,
        code: Name,
        message_type: Name,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                Name::from_str("pulse").unwrap(),
                Name::from_str("unlinkauth").unwrap(),
                UnlinkAuth {
                    account,
                    code,
                    message_type,
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

    fn delete_auth(
        private_key: &PrivateKey,
        account: Name,
        permission: Name,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                Name::from_str("pulse").unwrap(),
                Name::from_str("deleteauth").unwrap(),
                DeleteAuth {
                    account,
                    permission,
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

    /// Oracle harness (step 1): run a real newaccount transaction through the
    /// controller and check the arena mirror agrees with chainbase on the new
    /// account's metadata. Executing the action drives the same `create_account`
    /// / `create_account_metadata` paths that carry the mirror hooks. This is the
    /// feedback loop the session-lockstep work is built against.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_newaccount_mirrors_into_arena() -> Result<(), ChainError> {
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
        let ts = controller.last_accepted_block().timestamp().clone();
        let chain_id = controller.chain_id().clone();
        let status = BlockStatus::Building;

        controller.execute_transaction(
            &create_account(&private_key, Name::from_str("glenn")?, chain_id)?,
            &ts,
            &status,
        )?;

        let db = controller.database();
        let name = Name::from_str("glenn")?.as_u64();
        // chainbase created the account_metadata...
        assert!(
            !db.find_account_metadata(name)?.is_null(),
            "chainbase is missing glenn's account_metadata"
        );
        // ...and the arena mirror must carry the same row.
        assert_eq!(
            db.arena_account_metadata_privileged(name),
            Some(false),
            "arena did not mirror glenn's account_metadata"
        );
        Ok(())
    }

    /// Oracle harness (step 2): the arena's undo session must track chainbase's.
    /// Run a newaccount inside an undo session, mirror the session on the arena,
    /// then undo both — chainbase discards the account and the arena must too.
    /// Omitting the `arena_*` lockstep calls makes the final assert fail (the
    /// arena keeps a row chainbase discarded), which is the divergence the full
    /// controller wiring must avoid.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_undone_tx_leaves_no_trace_in_arena() -> Result<(), ChainError> {
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
        let ts = controller.last_accepted_block().timestamp().clone();
        let chain_id = controller.chain_id().clone();
        let status = BlockStatus::Building;
        let name = Name::from_str("glenn")?.as_u64();

        // A clone shares the same chainbase and the same arena mirror.
        let mut db = controller.database();
        let mut session = db.create_undo_session(true)?;
        db.arena_start_undo_session();

        controller.execute_transaction(
            &create_account(&private_key, Name::from_str("glenn")?, chain_id)?,
            &ts,
            &status,
        )?;
        // Inside the session, both sides have the account.
        assert!(!db.find_account_metadata(name)?.is_null());
        assert_eq!(db.arena_account_metadata_privileged(name), Some(false));

        // Undo the session on both.
        session
            .pin_mut()
            .undo()
            .map_err(|e| ChainError::DatabaseError(format!("{}", e)))?;
        db.arena_undo();

        // Both must now agree the account is gone.
        assert!(
            db.find_account_metadata(name)?.is_null(),
            "chainbase kept the undone account"
        );
        assert_eq!(
            db.arena_account_metadata_privileged(name),
            None,
            "arena kept a row chainbase undid — session desync"
        );
        Ok(())
    }

    /// Oracle harness (step 3): the real block path. verify_block executes a
    /// block speculatively and undoes it, so the arena must not retain the
    /// block's writes; accept_block commits, so the arena must then match
    /// chainbase. This exercises the arena session lockstep wired into
    /// build/verify/accept.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_block_accept_mirrors_into_arena() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let name = Name::from_str("glenn")?.as_u64();

        // build_block produces a valid block (correct merkle roots) and undoes
        // its speculative state, so afterwards the arena must not keep the
        // account it created while building.
        mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("glenn")?,
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        assert_eq!(
            controller.database().arena_account_metadata_privileged(name),
            None,
            "build_block left a speculative account in the arena"
        );

        // accept_block commits: both sides must now hold the account.
        controller.accept_block(&block.id()?, &mut mempool)?;
        let db = controller.database();
        assert!(
            !db.find_account_metadata(name)?.is_null(),
            "chainbase is missing the accepted account"
        );
        assert_eq!(
            db.arena_account_metadata_privileged(name),
            Some(false),
            "accept_block did not commit the account into the arena"
        );
        Ok(())
    }

    /// Full-field oracle for account_metadata: a block that creates an account,
    /// sets its code, then sets its abi must leave the arena's
    /// account_metadata_object matching chainbase field-for-field. code_sequence
    /// (setcode), abi_sequence (setabi) and auth_sequence (glenn authorizes all
    /// three actions) each advance through a path the mirror drives via the
    /// get_name accessor added to the FFI.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_setcode_mirrors_account_metadata_fields() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let name = Name::from_str("glenn")?.as_u64();

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let wasm =
            fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();

        // One block: create glenn, then set its code. Both must be committed by
        // accept_block for the metadata comparison to be against durable state.
        mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("glenn")?,
            chain_id,
        )?);
        mempool.add_transaction(set_code(
            &private_key,
            Name::from_str("glenn")?,
            wasm,
            chain_id,
        )?);
        // A minimal but valid ABI — setabi parses it before storing, so an empty
        // blob would be rejected. The mirror only has to track the sequence bump
        // and the stored bytes, not the ABI's meaning.
        let abi = AbiDefinition {
            version: "eosio::abi/1.2".to_string(),
            types: vec![],
            structs: vec![],
            actions: vec![],
            tables: vec![],
            ricardian_clauses: vec![],
            error_messages: vec![],
            abi_extensions: vec![],
            variants: vec![],
            action_results: vec![],
        };
        mempool.add_transaction(set_abi(
            &private_key,
            Name::from_str("glenn")?,
            abi.pack().unwrap(),
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let ptr = db.find_account_metadata(name)?;
        assert!(
            !ptr.is_null(),
            "chainbase is missing the account after setcode"
        );
        // Safe: the pointer is non-null and the metadata object outlives this
        // read (no mutation happens between the find and the accessor calls).
        let chain_meta = unsafe { &*ptr };
        let arena = db
            .arena_account_metadata(name)
            .expect("arena is missing the account after setcode");

        assert_eq!(arena.privileged, chain_meta.is_privileged());
        assert_eq!(arena.code_sequence, chain_meta.get_code_sequence());
        assert_eq!(arena.abi_sequence, chain_meta.get_abi_sequence());
        assert_eq!(arena.recv_sequence, chain_meta.get_recv_sequence());
        assert_eq!(arena.auth_sequence, chain_meta.get_auth_sequence());
        assert_eq!(arena.vm_type, chain_meta.get_vm_type());
        assert_eq!(arena.vm_version, chain_meta.get_vm_version());
        assert!(
            arena.code_sequence >= 1,
            "setcode did not advance code_sequence in the mirror"
        );
        assert!(
            arena.abi_sequence >= 1,
            "setabi did not advance abi_sequence in the mirror"
        );
        assert!(
            arena.auth_sequence >= 1,
            "authorizing the actions did not advance auth_sequence in the mirror"
        );
        Ok(())
    }

    /// Permission oracle: updateauth creating a new named permission under an
    /// existing account must mirror into the arena. The permission is keyed by
    /// (owner, name) — no opaque handle — so the check is presence plus the
    /// stored parent id (must equal chainbase's) and the authority threshold
    /// (must equal what the action set, proving the auth blob round-trips).
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_updateauth_mirrors_permission() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;
        let perm = Name::from_str("claude")?;

        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        // A new "claude" permission parented on active. Threshold 1 with the one
        // available key keeps the authority satisfiable (updateauth rejects an
        // authority whose threshold exceeds its total key weight).
        mempool.add_transaction(update_auth(
            &private_key,
            glenn,
            perm,
            ACTIVE_NAME,
            1,
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let owner = glenn.as_u64();
        let perm_u = perm.as_u64();
        let ptr = db.find_permission_by_actor_and_permission(owner, perm_u)?;
        assert!(!ptr.is_null(), "chainbase is missing the new permission");
        // Safe: non-null, and no mutation happens before the accessor read.
        let chain_perm = unsafe { &*ptr };
        let (parent, threshold) = db
            .arena_permission(owner, perm_u)
            .expect("arena is missing the new permission");

        assert_eq!(
            parent,
            chain_perm.get_parent_id(),
            "mirrored permission parent id diverged from chainbase"
        );
        assert_eq!(threshold, 1, "mirrored authority threshold did not round-trip");
        Ok(())
    }

    /// Permission-link oracle: linkauth binding an action to a permission must
    /// mirror into the arena. The link is keyed by (account, code, message_type)
    /// and the mirrored required_permission must equal chainbase's, read back
    /// through the find_permission_link accessor added to the FFI.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_linkauth_mirrors_permission_link() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;
        let perm = Name::from_str("claude")?;
        let msg_type = Name::from_str("transfer")?;

        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        // Create the target permission, then link glenn's "transfer" actions on
        // its own scope to require it.
        mempool.add_transaction(update_auth(
            &private_key,
            glenn,
            perm,
            ACTIVE_NAME,
            1,
            chain_id,
        )?);
        mempool.add_transaction(link_auth(
            &private_key,
            glenn,
            glenn,
            msg_type,
            perm,
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let (account, code, mtype) = (glenn.as_u64(), glenn.as_u64(), msg_type.as_u64());
        let ptr = db.find_permission_link(account, code, mtype)?;
        assert!(!ptr.is_null(), "chainbase is missing the permission link");
        // Safe: non-null, and no mutation happens before the accessor read.
        let chain_link = unsafe { &*ptr };
        let required = db
            .arena_permission_link(account, code, mtype)
            .expect("arena is missing the permission link");

        assert_eq!(
            required,
            chain_link.get_required_permission(),
            "mirrored permission link required_permission diverged from chainbase"
        );
        assert_eq!(required, perm.as_u64(), "link did not point at the new permission");
        Ok(())
    }

    /// Removal oracle: unlinkauth then deleteauth must drop the mirrored rows in
    /// step with chainbase. A permission cannot be deleted while a link points at
    /// it, so the link is removed first. Afterwards both the link and the
    /// permission must be absent on both sides.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_unlink_and_delete_auth_remove_from_arena() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;
        let perm = Name::from_str("claude")?;
        let msg_type = Name::from_str("transfer")?;

        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        mempool.add_transaction(update_auth(
            &private_key,
            glenn,
            perm,
            ACTIVE_NAME,
            1,
            chain_id,
        )?);
        mempool.add_transaction(link_auth(
            &private_key,
            glenn,
            glenn,
            msg_type,
            perm,
            chain_id,
        )?);
        mempool.add_transaction(unlink_auth(&private_key, glenn, glenn, msg_type, chain_id)?);
        mempool.add_transaction(delete_auth(&private_key, glenn, perm, chain_id)?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let (account, code, mtype) = (glenn.as_u64(), glenn.as_u64(), msg_type.as_u64());

        assert!(
            db.find_permission_link(account, code, mtype)?.is_null(),
            "chainbase kept the unlinked permission link"
        );
        assert_eq!(
            db.arena_permission_link(account, code, mtype),
            None,
            "arena kept the unlinked permission link"
        );
        assert!(
            db.find_permission_by_actor_and_permission(account, perm.as_u64())?
                .is_null(),
            "chainbase kept the deleted permission"
        );
        assert_eq!(
            db.arena_permission(account, perm.as_u64()),
            None,
            "arena kept the deleted permission"
        );
        Ok(())
    }

    /// RAM oracle: after a block that creates an account and sets its code and
    /// abi, the mirrored resource_usage.ram_usage must equal chainbase's. Every
    /// RAM delta funnels through add_pending_ram_usage, which the mirror
    /// accumulates, so this exercises the whole billing path end to end without
    /// duplicating any billing rules — the mirror only replays the same deltas.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_ram_usage_mirrors_chainbase() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let wasm =
            fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
        let abi = AbiDefinition {
            version: "eosio::abi/1.2".to_string(),
            types: vec![],
            structs: vec![],
            actions: vec![],
            tables: vec![],
            ricardian_clauses: vec![],
            error_messages: vec![],
            abi_extensions: vec![],
            variants: vec![],
            action_results: vec![],
        };

        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        mempool.add_transaction(set_code(&private_key, glenn, wasm, chain_id)?);
        mempool.add_transaction(set_abi(&private_key, glenn, abi.pack().unwrap(), chain_id)?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let name = glenn.as_u64();
        let chain_ram = db.get_account_ram_usage(name)?;
        let arena_ram = db
            .arena_account_ram_usage(name)
            .expect("arena is missing the resource_usage row");
        assert_eq!(
            arena_ram as i64, chain_ram,
            "mirrored ram_usage diverged from chainbase"
        );
        assert!(chain_ram > 0, "expected the block to charge RAM");
        Ok(())
    }

    /// Net/CPU usage oracle: authorizing transactions bills the account's
    /// windowed net/cpu usage accumulators. After a create+setcode+setabi block
    /// the mirrored accumulator value_ex (the pre-multiplied state, the exact
    /// thing that persists) must equal chainbase's — proving the ported EMA
    /// accumulator math and the config-window plumbing match bit for bit.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_net_cpu_usage_mirrors_chainbase() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let wasm =
            fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
        let abi = AbiDefinition {
            version: "eosio::abi/1.2".to_string(),
            types: vec![],
            structs: vec![],
            actions: vec![],
            tables: vec![],
            ricardian_clauses: vec![],
            error_messages: vec![],
            abi_extensions: vec![],
            variants: vec![],
            action_results: vec![],
        };

        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        mempool.add_transaction(set_code(&private_key, glenn, wasm, chain_id)?);
        mempool.add_transaction(set_abi(&private_key, glenn, abi.pack().unwrap(), chain_id)?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let name = glenn.as_u64();
        let chain_net = db.get_account_net_usage_value_ex(name)?;
        let chain_cpu = db.get_account_cpu_usage_value_ex(name)?;
        let arena_net = db
            .arena_account_net_usage_value_ex(name)
            .expect("arena is missing net usage");
        let arena_cpu = db
            .arena_account_cpu_usage_value_ex(name)
            .expect("arena is missing cpu usage");

        assert_eq!(arena_net, chain_net, "mirrored net_usage value_ex diverged");
        assert_eq!(arena_cpu, chain_cpu, "mirrored cpu_usage value_ex diverged");
        assert!(
            chain_cpu > 0 && chain_net > 0,
            "expected the block to bill net and cpu"
        );
        Ok(())
    }

    /// Resource-limits oracle: creating an account initializes its committed
    /// resource_limits row to unlimited (-1). The mirrored effective limits must
    /// equal chainbase's get_account_limits after a newaccount block. (The
    /// pending/commit cycle is exercised at the Database boundary in the ffi
    /// arena_shadow tests, since no action in this chain calls set_account_limits.)
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_account_limits_mirror_defaults() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;

        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let name = glenn.as_u64();
        let (mut ram, mut net, mut cpu) = (0i64, 0i64, 0i64);
        db.get_account_limits(name, &mut ram, &mut net, &mut cpu)?;
        let arena = db
            .arena_account_limits(name)
            .expect("arena is missing the resource_limits row");
        assert_eq!(arena, (ram, net, cpu), "mirrored account limits diverged");
        assert_eq!(arena, (-1, -1, -1), "expected unlimited defaults at init");
        Ok(())
    }

    /// Dynamic-global-property oracle: every applied action advances the
    /// global_action_sequence on the singleton dynamic_global_property_object.
    /// After a newaccount block the mirrored sequence must equal chainbase's.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_global_action_sequence_mirrors() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();

        mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("glenn")?,
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let chain_seq = db.get_global_action_sequence()?;
        let arena_seq = db
            .arena_global_action_sequence()
            .expect("arena is missing the dynamic_global_property row");
        assert_eq!(arena_seq, chain_seq, "mirrored global_action_sequence diverged");
        assert!(chain_seq > 0, "expected applied actions to advance the sequence");
        Ok(())
    }

    /// Elastic virtual-limit oracle: process_block_usage recomputes the global
    /// virtual cpu/net limits every block from the block's pending usage and the
    /// windowed averages. After a block the mirrored virtual limits — produced by
    /// the ported EMA plus update_elastic_limit, fed the same config parameters —
    /// must equal chainbase's exactly.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_virtual_limits_mirror_chainbase() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();

        mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("glenn")?,
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let chain = (db.get_virtual_cpu_limit()?, db.get_virtual_net_limit()?);
        let arena = db
            .arena_virtual_limits()
            .expect("arena is missing the resource_limits state row");
        assert_eq!(arena, chain, "mirrored virtual limits diverged from chainbase");
        assert!(
            chain.0 > 0 && chain.1 > 0,
            "expected non-zero virtual limits after a block"
        );
        Ok(())
    }

    /// Transaction-dedupe oracle: applying a transaction records it in the
    /// per-block dedupe set (transaction_object). After the block the mirror must
    /// agree with chainbase's is_known_unexpired_transaction — present for the
    /// applied trx id, absent for an unrelated one.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_transaction_dedupe_mirrors() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();

        let tx = create_account(&private_key, Name::from_str("glenn")?, chain_id)?;
        let trx_digest = tx.id().to_digest()?;
        mempool.add_transaction(tx);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        assert!(
            db.is_known_unexpired_transaction(&trx_digest)?,
            "chainbase is missing the dedupe record"
        );
        assert!(
            db.arena_transaction_exists(&trx_digest),
            "arena is missing the dedupe record"
        );
        // Negative control: an unrelated id is absent on both sides.
        let unknown = Id::default().to_digest()?;
        assert!(!db.is_known_unexpired_transaction(&unknown)?);
        assert!(!db.arena_transaction_exists(&unknown));
        Ok(())
    }

    /// Full-state cross-check: one block exercising the whole write surface
    /// (newaccount, setcode, setabi, updateauth, linkauth) must leave every
    /// mirrored table agreeing with chainbase at once — not just table by table
    /// in isolation. This is the closest thing to a full-state diff over the
    /// surface the FFI exposes reads for, and it guards against cross-table
    /// interactions the per-table oracles miss.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_full_state_cross_check() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;
        let perm = Name::from_str("claude")?;
        let msg_type = Name::from_str("transfer")?;

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let wasm =
            fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
        let abi = AbiDefinition {
            version: "eosio::abi/1.2".to_string(),
            types: vec![],
            structs: vec![],
            actions: vec![],
            tables: vec![],
            ricardian_clauses: vec![],
            error_messages: vec![],
            abi_extensions: vec![],
            variants: vec![],
            action_results: vec![],
        };

        let create_tx = create_account(&private_key, glenn, chain_id)?;
        let create_digest = create_tx.id().to_digest()?;
        mempool.add_transaction(create_tx);
        mempool.add_transaction(set_code(&private_key, glenn, wasm, chain_id)?);
        mempool.add_transaction(set_abi(&private_key, glenn, abi.pack().unwrap(), chain_id)?);
        mempool.add_transaction(update_auth(&private_key, glenn, perm, ACTIVE_NAME, 1, chain_id)?);
        mempool.add_transaction(link_auth(&private_key, glenn, glenn, msg_type, perm, chain_id)?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let name = glenn.as_u64();

        // account_object + account_metadata_object, field for field.
        assert!(!db.find_account(name)?.is_null(), "chainbase account missing");
        assert!(db.arena_account_exists(name), "arena account missing");
        let ptr = db.find_account_metadata(name)?;
        assert!(!ptr.is_null());
        let meta = unsafe { &*ptr };
        let arena_meta = db.arena_account_metadata(name).expect("arena metadata missing");
        assert_eq!(arena_meta.privileged, meta.is_privileged());
        assert_eq!(arena_meta.recv_sequence, meta.get_recv_sequence());
        assert_eq!(arena_meta.auth_sequence, meta.get_auth_sequence());
        assert_eq!(arena_meta.code_sequence, meta.get_code_sequence());
        assert_eq!(arena_meta.abi_sequence, meta.get_abi_sequence());
        assert_eq!(arena_meta.vm_type, meta.get_vm_type());
        assert_eq!(arena_meta.vm_version, meta.get_vm_version());

        // resource_usage: RAM + net/cpu accumulators.
        assert_eq!(
            db.arena_account_ram_usage(name).map(|r| r as i64),
            Some(db.get_account_ram_usage(name)?),
        );
        assert_eq!(
            db.arena_account_net_usage_value_ex(name),
            Some(db.get_account_net_usage_value_ex(name)?),
        );
        assert_eq!(
            db.arena_account_cpu_usage_value_ex(name),
            Some(db.get_account_cpu_usage_value_ex(name)?),
        );

        // resource_limits + global elastic virtual limits.
        let (mut ram, mut net, mut cpu) = (0i64, 0i64, 0i64);
        db.get_account_limits(name, &mut ram, &mut net, &mut cpu)?;
        assert_eq!(db.arena_account_limits(name), Some((ram, net, cpu)));
        assert_eq!(
            db.arena_virtual_limits(),
            Some((db.get_virtual_cpu_limit()?, db.get_virtual_net_limit()?)),
        );

        // permission + permission_link created by updateauth/linkauth.
        let perm_ptr = db.find_permission_by_actor_and_permission(name, perm.as_u64())?;
        assert!(!perm_ptr.is_null());
        let (parent, _threshold) = db.arena_permission(name, perm.as_u64()).expect("arena perm");
        assert_eq!(parent, unsafe { &*perm_ptr }.get_parent_id());
        let link_ptr = db.find_permission_link(name, name, msg_type.as_u64())?;
        assert!(!link_ptr.is_null());
        assert_eq!(
            db.arena_permission_link(name, name, msg_type.as_u64()),
            Some(unsafe { &*link_ptr }.get_required_permission()),
        );

        // dynamic_global_property + transaction dedupe.
        assert_eq!(
            db.arena_global_action_sequence(),
            Some(db.get_global_action_sequence()?),
        );
        assert!(db.is_known_unexpired_transaction(&create_digest)?);
        assert!(db.arena_transaction_exists(&create_digest));

        // The mirrored state has a populated root.
        let root_hash = db.arena_state_root().expect("state root");
        assert_ne!(root_hash, [0u8; 32], "arena state root is empty");
        Ok(())
    }

    /// True cross-implementation state root for account_metadata: both the arena
    /// mirror and chainbase serialize the whole table into the same canonical
    /// byte layout in name order, independently, and their SHA-256 roots must
    /// match. Unlike the per-account point-read oracles, this enumerates the
    /// entire table — every genesis account plus the ones this block creates — so
    /// a missed or mis-serialized row anywhere is caught.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_cross_impl_account_metadata_root() -> Result<(), ChainError> {
        use sha2::{Digest, Sha256};

        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let wasm =
            fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
        let abi = AbiDefinition {
            version: "eosio::abi/1.2".to_string(),
            types: vec![],
            structs: vec![],
            actions: vec![],
            tables: vec![],
            ricardian_clauses: vec![],
            error_messages: vec![],
            abi_extensions: vec![],
            variants: vec![],
            action_results: vec![],
        };

        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        mempool.add_transaction(set_code(&private_key, glenn, wasm, chain_id)?);
        mempool.add_transaction(set_abi(&private_key, glenn, abi.pack().unwrap(), chain_id)?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let chain_bytes = db.account_metadata_state_bytes()?;
        let arena_bytes = db
            .arena_account_metadata_state_bytes()
            .expect("shadow enabled");

        // Byte-for-byte first (pinpoints any diverging row/field), then the root.
        assert_eq!(
            chain_bytes, arena_bytes,
            "canonical account_metadata serialization diverged between chainbase and the mirror"
        );
        let chain_root: [u8; 32] = Sha256::digest(&chain_bytes).into();
        let arena_root: [u8; 32] = Sha256::digest(&arena_bytes).into();
        assert_eq!(
            chain_root, arena_root,
            "cross-impl account_metadata state root diverged"
        );

        // 75 bytes per row; the block enumerates more than just glenn (genesis
        // accounts are covered too).
        const ROW: usize = 75;
        assert_eq!(chain_bytes.len() % ROW, 0, "unexpected canonical row size");
        assert!(
            chain_bytes.len() / ROW >= 2,
            "expected genesis accounts plus glenn in the enumeration"
        );
        Ok(())
    }

    /// Cross-impl state root for account_object: the whole table (including the
    /// system account's non-empty genesis abi and glenn's abi from setabi) must
    /// serialize identically on both sides and hash to the same root. Exercises
    /// the blob path of the cross-impl mechanism.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_cross_impl_account_root() -> Result<(), ChainError> {
        use sha2::{Digest, Sha256};

        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;
        let abi = AbiDefinition {
            version: "eosio::abi/1.2".to_string(),
            types: vec![],
            structs: vec![],
            actions: vec![],
            tables: vec![],
            ricardian_clauses: vec![],
            error_messages: vec![],
            abi_extensions: vec![],
            variants: vec![],
            action_results: vec![],
        };

        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        mempool.add_transaction(set_abi(&private_key, glenn, abi.pack().unwrap(), chain_id)?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let chain_bytes = db.account_state_bytes()?;
        let arena_bytes = db.arena_account_state_bytes().expect("shadow enabled");
        assert_eq!(
            chain_bytes, arena_bytes,
            "canonical account_object serialization diverged between chainbase and the mirror"
        );
        let chain_root: [u8; 32] = Sha256::digest(&chain_bytes).into();
        let arena_root: [u8; 32] = Sha256::digest(&arena_bytes).into();
        assert_eq!(chain_root, arena_root, "cross-impl account_object state root diverged");
        assert!(chain_bytes.len() > 16, "expected multiple accounts with abi data");
        Ok(())
    }

    /// Cross-impl state root for the permission table — the hardest one:
    /// composite (owner, perm_name) key, a variable authority blob, and a parent
    /// id reference. Both sides serialize owner + perm_name + parent id +
    /// length-prefixed authority (re-encoded identically) in key order and must
    /// hash equal over the full set: genesis permissions (owner/active for the
    /// native accounts plus the producer permissions, all hydrated) and glenn's
    /// owner/active/claude created live by newaccount and updateauth.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_cross_impl_permission_root() -> Result<(), ChainError> {
        use sha2::{Digest, Sha256};

        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;

        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        mempool.add_transaction(update_auth(
            &private_key,
            glenn,
            Name::from_str("claude")?,
            ACTIVE_NAME,
            1,
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let chain_bytes = db.permission_state_bytes()?;
        let arena_bytes = db.arena_permission_state_bytes().expect("shadow enabled");
        assert_eq!(
            chain_bytes, arena_bytes,
            "canonical permission serialization diverged between chainbase and the mirror"
        );
        let chain_root: [u8; 32] = Sha256::digest(&chain_bytes).into();
        let arena_root: [u8; 32] = Sha256::digest(&arena_bytes).into();
        assert_eq!(chain_root, arena_root, "cross-impl permission state root diverged");
        assert!(!chain_bytes.is_empty(), "expected permissions in the enumeration");
        Ok(())
    }

    /// Unified full-state cross-impl root across every mirrored table that a
    /// normal block populates. A rich block (create, setcode, setabi, updateauth,
    /// linkauth) exercises each table, then each table's canonical serialization
    /// is compared byte-for-byte (so a mismatch names the table) and a single
    /// SHA-256 over all of them — the full-state root — must match. The seven
    /// contract tables are empty in this flow (no WASM db writes) and are covered
    /// against chainbase separately in diff_contract_iter.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_cross_impl_full_state_root() -> Result<(), ChainError> {
        use sha2::{Digest, Sha256};

        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;
        let perm = Name::from_str("claude")?;
        let msg_type = Name::from_str("transfer")?;

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let wasm =
            fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
        let abi = AbiDefinition {
            version: "eosio::abi/1.2".to_string(),
            types: vec![],
            structs: vec![],
            actions: vec![],
            tables: vec![],
            ricardian_clauses: vec![],
            error_messages: vec![],
            abi_extensions: vec![],
            variants: vec![],
            action_results: vec![],
        };

        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        mempool.add_transaction(set_code(&private_key, glenn, wasm, chain_id)?);
        mempool.add_transaction(set_abi(&private_key, glenn, abi.pack().unwrap(), chain_id)?);
        mempool.add_transaction(update_auth(&private_key, glenn, perm, ACTIVE_NAME, 1, chain_id)?);
        mempool.add_transaction(link_auth(&private_key, glenn, glenn, msg_type, perm, chain_id)?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        // (table name, chainbase bytes, arena bytes)
        let tables: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
            ("account_metadata", db.account_metadata_state_bytes()?, db.arena_account_metadata_state_bytes().unwrap()),
            ("account", db.account_state_bytes()?, db.arena_account_state_bytes().unwrap()),
            ("permission", db.permission_state_bytes()?, db.arena_permission_state_bytes().unwrap()),
            ("permission_link", db.permission_link_state_bytes()?, db.arena_permission_link_state_bytes().unwrap()),
            ("code", db.code_state_bytes()?, db.arena_code_state_bytes().unwrap()),
            ("transaction", db.transaction_state_bytes()?, db.arena_transaction_state_bytes().unwrap()),
            ("resource_usage", db.resource_usage_state_bytes()?, db.arena_resource_usage_state_bytes().unwrap()),
            ("resource_limits", db.account_limits_state_bytes()?, db.arena_account_limits_state_bytes().unwrap()),
            ("resource_state", db.resource_state_bytes()?, db.arena_resource_state_bytes().unwrap()),
            ("dynamic_global_property", db.get_global_action_sequence()?.to_le_bytes().to_vec(), db.arena_global_action_sequence().unwrap().to_le_bytes().to_vec()),
        ];

        let mut chain_root = Sha256::new();
        let mut arena_root = Sha256::new();
        for (name, chain_bytes, arena_bytes) in &tables {
            assert_eq!(
                chain_bytes, arena_bytes,
                "cross-impl state diverged for table {name}"
            );
            chain_root.update(name.as_bytes());
            chain_root.update(chain_bytes);
            arena_root.update(name.as_bytes());
            arena_root.update(arena_bytes);
        }
        let chain_root: [u8; 32] = chain_root.finalize().into();
        let arena_root: [u8; 32] = arena_root.finalize().into();
        assert_eq!(chain_root, arena_root, "full-state cross-impl root diverged");

        // Sanity: the populated tables are non-empty on both sides.
        for name in ["account_metadata", "account", "permission", "code", "resource_usage"] {
            let (_, chain_bytes, _) = tables.iter().find(|t| t.0 == name).unwrap();
            assert!(!chain_bytes.is_empty(), "expected {name} to be populated");
        }
        Ok(())
    }

    /// Cross-impl root for the contract primary tables. A block deploys the
    /// token contract and runs its `create` action, which stores a currency-stats
    /// row — populating table_id_object and key_value_object through the mirrored
    /// create path. Both sides serialize the two tables (the arena resolves the
    /// table identity from t_id so its own ids never leak into the bytes) and the
    /// roots must match. Contract row UPDATES (issue/transfer) are not mirrored
    /// yet — update_key_value_object reaches the row by an opaque handle whose
    /// table id is not resolvable through the FFI — so this covers the create
    /// path only; the full contract db is separately diff-tested vs C++ in
    /// diff_contract_iter.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_cross_impl_contract_root() -> Result<(), ChainError> {
        use sha2::{Digest, Sha256};

        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let wasm =
            fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();

        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        mempool.add_transaction(set_code(&private_key, glenn, wasm, chain_id)?);
        mempool.add_transaction(call_contract(
            &private_key,
            glenn,
            Name::from_str("create")?,
            &Create {
                issuer: glenn,
                max_supply: Asset::new(1000000, Symbol(1162826500)),
            },
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let tables: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
            ("table_id", db.contract_table_state_bytes()?, db.arena_contract_table_state_bytes().unwrap()),
            ("key_value", db.contract_kv_state_bytes()?, db.arena_contract_kv_state_bytes().unwrap()),
        ];
        let mut chain_root = Sha256::new();
        let mut arena_root = Sha256::new();
        for (name, chain_bytes, arena_bytes) in &tables {
            assert_eq!(chain_bytes, arena_bytes, "cross-impl contract state diverged for {name}");
            chain_root.update(chain_bytes);
            arena_root.update(arena_bytes);
        }
        assert_eq!(
            <[u8; 32]>::from(chain_root.finalize()),
            <[u8; 32]>::from(arena_root.finalize()),
            "cross-impl contract root diverged"
        );
        assert!(!tables[0].1.is_empty(), "expected the create action to make a table");
        assert!(!tables[1].1.is_empty(), "expected the create action to store a row");
        Ok(())
    }

    /// Every cross-impl table as `(name, chainbase bytes, arena bytes)` for the
    /// full-state root — the 10 block-populated tables plus the two contract
    /// primary tables (empty unless a contract wrote rows).
    #[cfg(feature = "arena-shadow")]
    fn cross_impl_tables(db: &Database) -> Result<Vec<(&'static str, Vec<u8>, Vec<u8>)>, ChainError> {
        Ok(vec![
            ("account_metadata", db.account_metadata_state_bytes()?, db.arena_account_metadata_state_bytes().unwrap_or_default()),
            ("account", db.account_state_bytes()?, db.arena_account_state_bytes().unwrap_or_default()),
            ("permission", db.permission_state_bytes()?, db.arena_permission_state_bytes().unwrap_or_default()),
            ("permission_link", db.permission_link_state_bytes()?, db.arena_permission_link_state_bytes().unwrap_or_default()),
            ("code", db.code_state_bytes()?, db.arena_code_state_bytes().unwrap_or_default()),
            ("transaction", db.transaction_state_bytes()?, db.arena_transaction_state_bytes().unwrap_or_default()),
            ("resource_usage", db.resource_usage_state_bytes()?, db.arena_resource_usage_state_bytes().unwrap_or_default()),
            ("resource_limits", db.account_limits_state_bytes()?, db.arena_account_limits_state_bytes().unwrap_or_default()),
            ("resource_state", db.resource_state_bytes()?, db.arena_resource_state_bytes().unwrap_or_default()),
            ("dynamic_global_property", db.get_global_action_sequence()?.to_le_bytes().to_vec(), db.arena_global_action_sequence().unwrap_or(0).to_le_bytes().to_vec()),
            ("contract_table", db.contract_table_state_bytes()?, db.arena_contract_table_state_bytes().unwrap_or_default()),
            ("contract_key_value", db.contract_kv_state_bytes()?, db.arena_contract_kv_state_bytes().unwrap_or_default()),
        ])
    }

    /// Replay a real node's block_log against the shadow. Ignored by default:
    /// run a local pulsevm node (optionally bootstrapped from the testnet) to
    /// produce a block_log, then point this at it —
    ///
    ///   PULSEVM_REPLAY_BLOCK_LOG_DIR=<node data dir with block_log> \
    ///   PULSEVM_REPLAY_GENESIS=<genesis.json> \
    ///   PULSEVM_REPLAY_CHAIN_ID=<hex chain id> \
    ///   cargo test -p pulsevm_core --features arena-shadow \
    ///     replay_local_block_log -- --ignored --nocapture
    ///
    /// It replays into a fresh db from genesis, so it re-derives state from the
    /// block history with the shadow mirroring alongside, and after every block
    /// asserts the cross-impl full-state root — reporting the first block/table
    /// that diverges. Requires our node to be able to execute every real block;
    /// a replay failure there is a node-completeness gap, not a mirror gap.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    #[ignore]
    async fn replay_local_block_log() -> Result<(), ChainError> {
        let (Ok(src_dir), Ok(genesis_path), Ok(chain_id_hex)) = (
            std::env::var("PULSEVM_REPLAY_BLOCK_LOG_DIR"),
            std::env::var("PULSEVM_REPLAY_GENESIS"),
            std::env::var("PULSEVM_REPLAY_CHAIN_ID"),
        ) else {
            eprintln!("replay_local_block_log: set PULSEVM_REPLAY_{{BLOCK_LOG_DIR,GENESIS,CHAIN_ID}} to run");
            return Ok(());
        };

        let chain_id = Id::from_str(&chain_id_hex).expect("PULSEVM_REPLAY_CHAIN_ID must be hex");
        let genesis_bytes = fs::read(&genesis_path).expect("cannot read genesis file");
        let config_bytes = json!({
            "producer_name": "pulse",
            "producer_key": "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez",
        })
        .to_string()
        .into_bytes();

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
        let mut controller = Controller::new();
        let temp_path = get_temp_dir();
        controller.initialize(&chain_id, &config_bytes, &genesis_bytes, temp_path.path().to_str().unwrap())?;

        // Open the source node's block_log (separate from our fresh one).
        let src = crate::chain::state_history::StateHistoryLog::open_with_magic(&src_dir, "block_log", 0)
            .map_err(|e| ChainError::InternalError(format!("open source block_log: {e:?}")))?;
        let (log_start, log_end) = src
            .range()
            .ok_or_else(|| ChainError::InternalError("source block_log is empty".into()))?;
        let start = controller.last_accepted_block().block_num() + 1;
        eprintln!("replaying blocks {start}..={log_end} (log range {log_start}..={log_end})");

        for n in start..=log_end {
            let packed = src
                .read_block(n)
                .map_err(|e| ChainError::InternalError(format!("read block {n}: {e:?}")))?;
            let block = SignedBlock::read(packed.as_slice(), &mut 0)?;
            controller.verify_block(&block, &mut mempool).await?;
            controller.accept_block(&block.id()?, &mut mempool)?;
            controller.set_preferred_id(block.id()?);

            let tables = cross_impl_tables(&controller.database())?;
            for (name, chain_bytes, arena_bytes) in &tables {
                assert_eq!(
                    chain_bytes, arena_bytes,
                    "cross-impl state diverged at block {n}, table {name}"
                );
            }
        }
        eprintln!("replayed to block {log_end}; cross-impl full-state root matched every block");
        Ok(())
    }

    /// Self-contained replay test: one node builds a rich block, and a fresh
    /// node replays it from its packed bytes — the same pack → SignedBlock::read
    /// → verify → accept path a block_log replay uses — with the shadow on. The
    /// replaying node must re-derive the full state so its arena and chainbase
    /// agree on the cross-impl root. This proves the replay path end to end
    /// without a live node; real testnet blocks drop into replay_local_block_log.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn replay_packed_block_keeps_shadow_in_sync() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let config_bytes = json!({
            "producer_name": "pulse",
            "producer_key": private_key.to_string(),
        })
        .to_string()
        .into_bytes();
        let genesis = generate_genesis(&private_key);

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let wasm =
            fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
        let glenn = Name::from_str("glenn")?;

        // Node A builds a rich block and packs it — the "fixture".
        let packed = {
            let mempool = Arc::new(RwLock::new(Mempool::new()));
            let mut mempool = mempool.write().await;
            let mut a = Controller::new();
            let dir = get_temp_dir();
            a.initialize(&chain_id, &config_bytes, &genesis, dir.path().to_str().unwrap())?;
            let cid = a.chain_id().clone();
            mempool.add_transaction(create_account(&private_key, glenn, cid)?);
            mempool.add_transaction(set_code(&private_key, glenn, wasm, cid)?);
            mempool.add_transaction(update_auth(
                &private_key,
                glenn,
                Name::from_str("claude")?,
                ACTIVE_NAME,
                1,
                cid,
            )?);
            let block = a.build_block(&mut mempool).await?;
            a.accept_block(&block.id()?, &mut mempool)?;
            block.pack().unwrap()
        };

        // Node B replays the packed block from scratch and must match.
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
        let mut b = Controller::new();
        let dir = get_temp_dir();
        b.initialize(&chain_id, &config_bytes, &genesis, dir.path().to_str().unwrap())?;
        let block = SignedBlock::read(packed.as_slice(), &mut 0)?;
        b.verify_block(&block, &mut mempool).await?;
        b.accept_block(&block.id()?, &mut mempool)?;

        for (name, chain_bytes, arena_bytes) in cross_impl_tables(&b.database())? {
            assert_eq!(
                chain_bytes, arena_bytes,
                "replayed cross-impl state diverged for table {name}"
            );
        }
        Ok(())
    }

    /// Same as the packed-block replay, but routed through a real StateHistoryLog
    /// block_log on disk — append the built block, reopen the log, read it back,
    /// and replay. This exercises the exact open_with_magic/append/range/read_block
    /// path that replay_local_block_log uses against a node's block_log, so it
    /// de-risks that harness independently of the (fixture-less) log unit tests.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn replay_via_block_log_keeps_shadow_in_sync() -> Result<(), ChainError> {
        use crate::chain::state_history::StateHistoryLog;

        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let config_bytes = json!({
            "producer_name": "pulse",
            "producer_key": private_key.to_string(),
        })
        .to_string()
        .into_bytes();
        let genesis = generate_genesis(&private_key);
        let glenn = Name::from_str("glenn")?;

        // Node A builds a block and writes it to a block_log on disk.
        let log_dir = get_temp_dir();
        let (built_id, built_packed) = {
            let mempool = Arc::new(RwLock::new(Mempool::new()));
            let mut mempool = mempool.write().await;
            let mut a = Controller::new();
            let dir = get_temp_dir();
            a.initialize(&chain_id, &config_bytes, &genesis, dir.path().to_str().unwrap())?;
            let cid = a.chain_id().clone();
            mempool.add_transaction(create_account(&private_key, glenn, cid)?);
            mempool.add_transaction(update_auth(
                &private_key,
                glenn,
                Name::from_str("claude")?,
                ACTIVE_NAME,
                1,
                cid,
            )?);
            let block = a.build_block(&mut mempool).await?;
            a.accept_block(&block.id()?, &mut mempool)?;

            let log = StateHistoryLog::open_with_magic(log_dir.path(), "block_log", 0)
                .map_err(|e| ChainError::InternalError(format!("open log: {e:?}")))?;
            log.append(block.id()?, &block.pack().unwrap())
                .map_err(|e| ChainError::InternalError(format!("append: {e:?}")))?;
            (block.id()?, block.pack().unwrap())
        };

        // Reopen the log fresh, read the block back, and replay it on node B.
        let src = StateHistoryLog::open_with_magic(log_dir.path(), "block_log", 0)
            .map_err(|e| ChainError::InternalError(format!("reopen log: {e:?}")))?;
        let (_start, end) = src.range().expect("block_log is empty after append");
        let packed = src
            .read_block(end)
            .map_err(|e| ChainError::InternalError(format!("read_block: {e:?}")))?;
        assert_eq!(packed, built_packed, "block_log round-trip corrupted the block");

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
        let mut b = Controller::new();
        let dir = get_temp_dir();
        b.initialize(&chain_id, &config_bytes, &genesis, dir.path().to_str().unwrap())?;
        let block = SignedBlock::read(packed.as_slice(), &mut 0)?;
        assert_eq!(block.id()?, built_id, "read block id mismatch");
        b.verify_block(&block, &mut mempool).await?;
        b.accept_block(&block.id()?, &mut mempool)?;

        for (name, chain_bytes, arena_bytes) in cross_impl_tables(&b.database())? {
            assert_eq!(
                chain_bytes, arena_bytes,
                "block_log-replayed cross-impl state diverged for table {name}"
            );
        }
        Ok(())
    }

    /// Proves we can reconstruct a real testnet block header from the getBlock
    /// JSON: rebuild block 2's header from `a-chain-alpine-rpc` (timestamp slot =
    /// (unix_ms - 946684800000)/500, hex digests, defaults for the unused header
    /// fields) and check calculate_id() reproduces the block's real id. This
    /// nails the timestamp round-trip — the only fiddly part of feeding real
    /// blocks into replay + the cross-impl diff.
    #[test]
    fn reconstruct_testnet_block2_header_id() {
        let hexd = |s: &str| -> [u8; 32] { hex::decode(s).unwrap().try_into().unwrap() };
        let header = BlockHeader {
            timestamp: pulsevm_ffi::BlockTimestamp { slot: 1676935919 },
            producer: Name::from_str("pulse").unwrap(),
            confirmed: 0,
            previous: Id::from_str(
                "000000017ba27a5af30bd801863775add48d21100c72ba8904ee8c88fa98ec23",
            )
            .unwrap(),
            transaction_mroot: Digest(hexd(
                "2c120a750efa0e284ff1650c510aa39e7a9238d85b5827ba2f09f728a7fb6af7",
            )),
            action_mroot: Digest(hexd(
                "ba245130138acfc919e5aa1ad4aeadc100a4b420598931f6ef88f6d987de481e",
            )),
            schedule_version: 0,
            new_producers: None,
            header_extensions: vec![],
        };
        let got = header.calculate_id().unwrap();
        let expected = Id::from_str(
            "000000020aacb295ab19375a5c59dbdd5678f8287cdf7395bc42f73fcdc820b4",
        )
        .unwrap();
        assert_eq!(got, expected, "reconstructed block 2 id mismatch: got {got}");
    }

    /// ISO block timestamp -> Antelope slot (500ms interval, 2000-01-01 epoch).
    #[cfg(feature = "arena-shadow")]
    fn iso_to_slot(iso: &str) -> u32 {
        let fmt = if iso.contains('.') {
            "%Y-%m-%dT%H:%M:%S%.f"
        } else {
            "%Y-%m-%dT%H:%M:%S"
        };
        let dt = chrono::NaiveDateTime::parse_from_str(iso.trim_end_matches('Z'), fmt).unwrap();
        let epoch = chrono::NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        ((dt - epoch).num_milliseconds() / 500) as u32
    }

    /// Reconstruct a SignedBlock from the getBlock JSON `result` object — the
    /// header (proven id-exact) plus every transaction rebuilt from its wire
    /// data (signatures, compression, packed_trx, packed_context_free_data), so
    /// the block re-derives the same merkle roots on replay.
    #[cfg(feature = "arena-shadow")]
    fn reconstruct_block(r: &serde_json::Value) -> Result<SignedBlock, ChainError> {
        use crate::chain::block::SignedBlockHeader;
        use crate::chain::crypto::Signature;
        use crate::chain::transaction::{
            PackedTransaction, TransactionCompression, TransactionReceipt,
            TransactionReceiptHeader, TransactionStatus,
        };
        use pulsevm_crypto::Bytes;
        use pulsevm_serialization::VarUint32;
        use std::collections::{BTreeSet, VecDeque};

        let hexd32 = |s: &str| -> [u8; 32] { hex::decode(s).unwrap().try_into().unwrap() };
        let header = BlockHeader {
            timestamp: pulsevm_ffi::BlockTimestamp {
                slot: iso_to_slot(r["timestamp"].as_str().unwrap()),
            },
            producer: Name::from_str(r["producer"].as_str().unwrap())?,
            confirmed: r["confirmed"].as_u64().unwrap() as u16,
            previous: Id::from_str(r["previous"].as_str().unwrap())
                .map_err(|_| ChainError::BlockError("bad previous id".into()))?,
            transaction_mroot: Digest(hexd32(r["transaction_mroot"].as_str().unwrap())),
            action_mroot: Digest(hexd32(r["action_mroot"].as_str().unwrap())),
            schedule_version: 0,
            new_producers: None,
            header_extensions: vec![],
        };

        let mut txs: VecDeque<TransactionReceipt> = VecDeque::new();
        for t in r["transactions"].as_array().unwrap() {
            let status = match t["status"].as_str().unwrap() {
                "executed" => TransactionStatus::Executed,
                other => {
                    return Err(ChainError::BlockError(format!("unhandled tx status {other}")));
                }
            };
            let cpu = t["cpu_usage_us"].as_u64().unwrap() as u32;
            let net = t["net_usage_words"].as_u64().unwrap() as u32;
            let trx = &t["trx"];
            if !trx.is_object() {
                return Err(ChainError::BlockError("pruned transaction (id only)".into()));
            }
            let mut sigs = BTreeSet::new();
            for s in trx["signatures"].as_array().unwrap() {
                sigs.insert(
                    Signature::from_str(s.as_str().unwrap())
                        .map_err(|e| ChainError::BlockError(format!("signature parse: {e:?}")))?,
                );
            }
            let compression = match trx["compression"].as_str().unwrap() {
                "none" | "0" => TransactionCompression::None,
                "zlib" | "1" => TransactionCompression::Zlib,
                other => return Err(ChainError::BlockError(format!("compression: {other}"))),
            };
            let packed_trx: Bytes = hex::decode(trx["packed_trx"].as_str().unwrap()).unwrap().into();
            let cfd: Bytes = hex::decode(trx["packed_context_free_data"].as_str().unwrap())
                .unwrap()
                .into();
            let packed = PackedTransaction::new(sigs, compression, cfd, packed_trx)?;
            let receipt_header = TransactionReceiptHeader::new(status, cpu, VarUint32(net));
            txs.push_back(TransactionReceipt::new(receipt_header, packed));
        }

        Ok(SignedBlock {
            signed_block_header: SignedBlockHeader {
                header,
                signature: Signature::default(),
            },
            transactions: txs,
            block_extensions: vec![],
        })
    }

    /// Replay real testnet blocks (fetched via scripts/fetch-blocks.sh into
    /// PULSEVM_RPC_BLOCKS_DIR) into a fresh node with the arena shadow on, and
    /// after every block assert the cross-impl full-state root — C++ chainbase
    /// vs the Rust arena — over all twelve tables. Ignored by default; reports
    /// exactly how far it stays 1:1 and the first divergence (mirror mismatch,
    /// merkle-root mismatch, or an unexecutable tx) if any.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    #[ignore]
    async fn replay_testnet_blocks() -> Result<(), ChainError> {
        let Ok(dir) = std::env::var("PULSEVM_RPC_BLOCKS_DIR") else {
            eprintln!("set PULSEVM_RPC_BLOCKS_DIR (see scripts/fetch-blocks.sh) to run");
            return Ok(());
        };
        let chain_id = Id::from_str(
            "531a7002b4a4b67987f8706c01b965c76ffc3ad301608ac61a1f738cba6c3a9a",
        )
        .unwrap();
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
        let config_bytes = json!({"producer_name":"pulse","producer_key":"PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez"})
            .to_string()
            .into_bytes();

        let mut files: Vec<_> = fs::read_dir(&dir)
            .expect("blocks dir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
            .collect();
        files.sort();

        // The genesis initial_timestamp is block 1's timestamp; the committed
        // genesis.json may carry a placeholder, so patch it to the real one so
        // our genesis block (and the genesis accounts' creation dates) match.
        let b1: serde_json::Value =
            serde_json::from_slice(&fs::read(files.first().expect("no block fixtures")).unwrap())
                .unwrap();
        assert_eq!(b1["result"]["block_num"].as_u64(), Some(1), "first fixture must be block 1");
        let ts = b1["result"]["timestamp"].as_str().unwrap().trim_end_matches(".000");
        let mut g: serde_json::Value =
            serde_json::from_slice(&fs::read(repo_root.join("genesis.json")).unwrap()).unwrap();
        g["initial_timestamp"] = json!(ts);

        // The committed genesis.json also carries a placeholder initial_key, so
        // recover the real system-account key from the first signed transaction
        // (using the real chain_id) and patch it in — otherwise pulse@active
        // won't have the key its transactions are signed with.
        for f in &files {
            let v: serde_json::Value = serde_json::from_slice(&fs::read(f).unwrap()).unwrap();
            let r = &v["result"];
            if r["transactions"].as_array().map(|a| !a.is_empty()).unwrap_or(false) {
                let b = reconstruct_block(r)?;
                let keys = b.transactions[0]
                    .trx()
                    .get_signed_transaction()
                    .recovered_keys(&chain_id)?;
                if let Some(k) = keys.iter().next() {
                    g["initial_key"] = json!(k.to_string());
                }
                break;
            }
        }
        let genesis_bytes = serde_json::to_vec(&g).unwrap();

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
        let mut controller = Controller::new();
        let temp = get_temp_dir();
        controller.initialize(&chain_id, &config_bytes, &genesis_bytes, temp.path().to_str().unwrap())?;

        // Our genesis (block 1) must match the testnet's, or block 2 won't chain.
        let genesis_id = controller.last_accepted_block().id()?;
        let start = controller.last_accepted_block().block_num() + 1;
        assert_eq!(
            genesis_id.to_string(),
            b1["result"]["id"].as_str().unwrap(),
            "our genesis block id != testnet block 1 id — genesis mismatch"
        );

        let mut replayed = 0u32;
        for f in &files {
            let v: serde_json::Value = serde_json::from_slice(&fs::read(f).unwrap()).unwrap();
            let r = &v["result"];
            let n = r["block_num"].as_u64().unwrap_or(0) as u32;
            if n < start {
                continue;
            }
            let block = reconstruct_block(r)?;
            if let Err(e) = controller.verify_block(&block, &mut mempool).await {
                eprintln!("stalled applying block {n}: {e:?}");
                break;
            }
            controller.accept_block(&block.id()?, &mut mempool)?;
            controller.set_preferred_id(block.id()?);

            let mut diverged = None;
            for (name, chain_bytes, arena_bytes) in cross_impl_tables(&controller.database())? {
                if chain_bytes != arena_bytes {
                    diverged = Some(name);
                    break;
                }
            }
            if let Some(name) = diverged {
                eprintln!("cross-impl diverged at block {n}, table {name} (matched blocks up to {replayed})");
                break;
            }
            replayed = n;
        }
        eprintln!(
            "replayed real testnet blocks up to {replayed}; C++ chainbase and the Rust arena matched the cross-impl full-state root at every block"
        );
        Ok(())
    }

    /// Block-sequence fuzzer: random sequences of blocks — each with a few
    /// newaccount transactions, then either accepted or discarded — must keep
    /// the arena mirror in step with chainbase. After every block, for every
    /// account name used so far, the arena and chainbase must agree on whether
    /// it exists, and that must match the set committed by accepted blocks. This
    /// stresses the session lockstep (speculative build/discard, accept/commit,
    /// revision advancing across blocks) under random inputs — chainbase is the
    /// C++ oracle.
    #[cfg(feature = "arena-shadow")]
    #[test]
    fn fuzz_block_sequence_keeps_arena_in_sync() {
        use std::collections::HashSet;

        // A distinct, always-valid account name (6 lowercase letters) per index.
        fn nth_name(i: usize) -> Name {
            let mut s = String::from("z");
            let mut n = i;
            for _ in 0..5 {
                s.push((b'a' + (n % 26) as u8) as char);
                n /= 26;
            }
            Name::from_str(&s).unwrap()
        }

        proptest::proptest!(
            proptest::prelude::ProptestConfig::with_cases(200),
            |(specs in proptest::collection::vec((1usize..=2, proptest::prelude::any::<bool>()), 1..=5))| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let chain_id = Id::from_str(
                    "c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6",
                )
                .unwrap();
                let private_key = PrivateKey::from_str(
                    "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez",
                )?;
                let mempool = Arc::new(RwLock::new(Mempool::new()));
                let mut mempool = mempool.write().await;
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
                let chain_id = controller.chain_id().clone();

                let mut expected: HashSet<u64> = HashSet::new();
                let mut used: Vec<u64> = Vec::new();
                let mut counter = 0usize;

                for (n, accept) in specs {
                    let mut names = Vec::new();
                    for _ in 0..n {
                        let nm = nth_name(counter);
                        counter += 1;
                        mempool.add_transaction(create_account(&private_key, nm, chain_id)?);
                        names.push(nm.as_u64());
                        used.push(nm.as_u64());
                    }
                    let block = controller.build_block(&mut mempool).await?;
                    if accept {
                        controller.accept_block(&block.id()?, &mut mempool)?;
                        controller.set_preferred_id(block.id()?);
                        expected.extend(names.iter().copied());
                    }
                    // After each block, arena and chainbase must agree, and match
                    // the committed set.
                    let db = controller.database();
                    for &u in &used {
                        let want = expected.contains(&u);
                        // account_metadata table
                        let meta_chain = !db.find_account_metadata(u)?.is_null();
                        let meta_arena = db.arena_account_metadata_privileged(u);
                        assert_eq!(meta_chain, want, "chainbase account_metadata disagrees with committed set");
                        assert_eq!(
                            meta_arena.is_some(),
                            meta_chain,
                            "arena account_metadata diverged from chainbase"
                        );
                        // account_object table
                        let acct_chain = !db.find_account(u)?.is_null();
                        let acct_arena = db.arena_account_exists(u);
                        assert_eq!(acct_chain, want, "chainbase account disagrees with committed set");
                        assert_eq!(acct_arena, acct_chain, "arena account table diverged from chainbase");
                        // a committed account is never privileged when just created
                        if want {
                            assert_eq!(meta_arena, Some(false), "arena privileged flag diverged");
                        }
                    }
                    // Cross-impl state root over the whole account_metadata table
                    // after every block: the canonical serializations must stay
                    // byte-identical through the speculative build/undo and commit
                    // sessions, not just for the names this sequence touched.
                    assert_eq!(
                        db.account_metadata_state_bytes()?,
                        db.arena_account_metadata_state_bytes().expect("shadow enabled"),
                        "cross-impl account_metadata state diverged after a block"
                    );
                }
                Ok::<(), ChainError>(())
            })
            .unwrap();
        });
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

    #[tokio::test]
    async fn test_api_db() -> Result<(), ChainError> {
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
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
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
        let chain_id = controller.chain_id().clone();
        let mut txs = VecDeque::new();
        txs.push_back(TransactionReceipt::new(
            TransactionReceiptHeader::new(
                crate::transaction::TransactionStatus::Executed,
                1,
                1.into(),
            ),
            create_account(&private_key, Name::from_str("testapi")?, chain_id)?,
        ));
        let block = SignedBlock::new(
            controller.last_accepted_block().id()?,
            TimePoint::now().into(),
            "pulse".parse().unwrap(),
            txs,
            Digest::default(), // TODO: Validate this when we implement merkle root calculation
            Digest::default(),
        );
        controller.verify_block(&block, &mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;
        controller.verify_block(&block, &mut mempool).await?;

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
