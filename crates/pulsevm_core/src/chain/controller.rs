use core::fmt;
use std::{
    collections::{
        BTreeSet,
        HashMap,
        HashSet,
        VecDeque,
    },
    sync::LazyLock,
};

use crate::{
    ACTIVE_NAME,
    MAJORITY_PRODUCERS_PERMISSION_NAME,
    MINORITY_PRODUCERS_PERMISSION_NAME,
    PRODS_NAME,
    PULSE_NAME,
    block::{
        BlockStatus,
        SignedBlock,
    },
    chain::{
        apply_context::ApplyContext,
        authority::PermissionLevel,
        authorization_manager::AuthorizationManager,
        block::BlockHeader,
        config::{
            DELETEAUTH_NAME,
            LINKAUTH_NAME,
            NEWACCOUNT_NAME,
            ONBLOCK_NAME,
            SETABI_NAME,
            SETCODE_NAME,
            UNLINKAUTH_NAME,
            UPDATEAUTH_NAME,
            eos_percent,
        },
        crypto::PublicKey,
        id::Id,
        mempool::Mempool,
        name::Name,
        producer_schedule::{
            ProducerKey,
            ProducerSchedule,
        },
        pulse_contract::{
            deleteauth,
            linkauth,
            newaccount,
            setabi,
            setcode,
            unlinkauth,
            updateauth,
        },
        resource_limits::ResourceLimitsManager,
        state_history::StateHistoryLog,
        state_sync,
        transaction::{
            PackedTransaction,
            SignedTransaction,
            Transaction,
            TransactionHeader,
            TransactionReceipt,
            TransactionTrace,
        },
        transaction_context::{
            TransactionContext,
            TransactionResult,
        },
        utils::make_ratio,
        wasm_runtime::WasmRuntime,
    },
    config::NodeConfig,
    transaction::Action,
};

use cxx::UniquePtr;
use pulsevm_constants::{
    BLOCK_CPU_USAGE_AVERAGE_WINDOW_MS,
    BLOCK_INTERVAL_MS,
    BLOCK_SIZE_AVERAGE_WINDOW_MS,
    MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER,
};
use pulsevm_crypto::{
    Digest,
    merkle,
};
use pulsevm_error::ChainError;
use pulsevm_ffi::{
    Authority,
    BlockTimestamp,
    CxxGenesisState,
    Database,
    ElasticLimitParameters,
    PermissionLevelWeight,
    TimePoint,
    UndoSession,
    seconds,
};
use pulsevm_grpc::vm;
use pulsevm_serialization::{
    Read,
    Write,
};
use spdlog::{
    debug,
    error,
    info,
    warn,
};

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

    // The data directory the database and logs live in. Retained so state-sync
    // accept can persist the synced producer schedule beside them.
    db_path: Option<String>,

    // The snapshot last advertised via `produce_state_summary`, cached so this
    // node can serve download chunks to a syncing peer. `None` until a summary
    // is produced or after a sync is applied.
    snapshot_cache: Option<CachedSnapshot>,

    // Active block producers and their signing keys. A block validates only if
    // signed by the key its producer holds here. Seeded from genesis, changed by
    // a block whose header carries `new_producers`, and reconstructed from the
    // block log on restart — it is never read from an out-of-band source.
    active_schedule: ProducerSchedule,

    // The producer schedule in force for the block currently being executed —
    // the schedule active as of that block's parent. Set at the top of the build,
    // verify, and standalone push paths so a transaction's `get_active_producers`
    // / `set_proposed_producers` see the same active set the block is signed
    // against. Not persisted; a per-execution scratch value.
    block_active_schedule: ProducerSchedule,

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
    // A producer schedule proposed by a `set_proposed_producers` in this block,
    // if any. Activated when the block is accepted, so a rejected/forked block
    // never changes the schedule.
    proposed_schedule: Option<Vec<ProducerKey>>,
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

/// An Avalanche state summary: a commitment the engine agrees on (`id`, the
/// accepted block id, canonical across nodes) plus small `bytes` describing what
/// to fetch — the active schedule, the snapshot's block, and the snapshot's
/// length and hash. The snapshot payload itself is downloaded separately over
/// AppRequest (see `crate::chain::state_sync`).
pub struct StateSummary {
    pub id: Id,
    pub height: u64,
    pub bytes: Vec<u8>,
}

/// The producer schedule in force at a synced snapshot, persisted beside the
/// logs so a restart-after-sync can recover it (see `apply_state_snapshot`).
const SYNCED_SCHEDULE_FILE: &str = "synced_schedule.bin";

/// The snapshot a node last advertised in a summary, kept so it can serve the
/// download chunks without re-snapshotting the arena on every request.
struct CachedSnapshot {
    height: u32,
    hash: [u8; 32],
    envelope: Vec<u8>,
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
            db_path: None,
            snapshot_cache: None,
            active_schedule: ProducerSchedule::default(),
            block_active_schedule: ProducerSchedule::default(),

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
            self.db.arena_undo(); // pop the mirror's matching session in lockstep
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

        self.db_path = Some(db_path.to_string());

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

        // Seed the active producer schedule from genesis: the sole producer is
        // the configured producer_name, and it signs blocks with the genesis
        // initial key. On restart this is the base the block log is replayed onto
        // (see `reconstruct_schedule_from_log` below).
        let initial_key =
            <PublicKey as std::str::FromStr>::from_str(&genesis.get_initial_key().to_string_rust())
                .map_err(|e| ChainError::GenesisError(format!("invalid genesis key: {}", e)))?;
        self.active_schedule = ProducerSchedule {
            version: 0,
            producers: vec![ProducerKey {
                producer_name: self.node_config.as_ref().unwrap().producer_name,
                block_signing_key: initial_key,
            }],
        };
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
            // initialize_database seeds the resource-limits config from the C++
            // struct defaults (default_max_block_cpu_usage), not from genesis, so
            // the very first block would run under those tiny defaults until the
            // end-of-block set_block_parameters first fires. Push the genesis-derived
            // block parameters in now so block 1 already has the real CPU/NET
            // ceilings — otherwise a genesis-configured budget silently doesn't
            // apply to the block that bootstraps the chain.
            let (cpu_elastic_parameters, net_elastic_parameters) =
                self.block_elastic_parameters()?;
            ResourceLimitsManager::set_block_parameters(
                &mut self.db,
                &cpu_elastic_parameters,
                &net_elastic_parameters,
            )?;
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

                // A state-synced node's schedule base isn't in its (re-based) log:
                // the pre-sync block that set the schedule was never downloaded, so
                // the log tip may not carry it. Accept persisted the schedule in
                // force at the snapshot height beside the logs; load it as the base
                // before reconstruct overlays any newer in-log change. Absent on a
                // normally-grown chain, where the genesis seed is the base.
                if let Some(synced) = Self::load_synced_schedule(db_path) {
                    self.active_schedule = synced;
                }

                // Rebuild the active schedule from the committed chain rather than
                // trusting an out-of-band file: the last block that carried a
                // `new_producers` names the schedule in force, and if none did the
                // base above still stands.
                self.reconstruct_schedule_from_log(start, end)?;
            }
        }

        Ok(())
    }

    // Walk the block log back from the tip for the most recent block that changed
    // the producer schedule; its header carries the schedule now in force. Runs
    // once at startup. It is O(blocks since the last schedule change), which is
    // the whole log when the schedule never changed — acceptable while chains are
    // short; a cached height pointer is the obvious optimization if it gets hot.
    fn reconstruct_schedule_from_log(&mut self, start: u32, end: u32) -> Result<(), ChainError> {
        let mut height = end;
        loop {
            if let Some(block) = self.get_block_by_height(height)? {
                if let Some(schedule) = block.signed_block_header.header.new_schedule()? {
                    info!(
                        "reconstructed producer schedule version {} from block {}",
                        schedule.version, height
                    );
                    self.active_schedule = schedule;
                    return Ok(());
                }
            }
            if height <= start {
                break;
            }
            height -= 1;
        }
        // No block changed the schedule: the genesis seed is the active schedule.
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
        db.arena_start_undo_session(); // mirror the block session; retained on the pending chain

        // Expiry clearing is part of the block's state, so it belongs inside the
        // block's session rather than before it.
        db.clear_expired_input_transactions(&timestamp.into())?;

        // The last producer schedule proposed by any transaction in this block,
        // activated when the block is accepted.
        let mut proposed_schedule: Option<Vec<ProducerKey>> = None;

        // The schedule active for this block (as of its parent) governs what
        // onblock and every transaction see through get_active_producers, and the
        // version set_proposed_producers reports.
        self.block_active_schedule = self.schedule_active_for_parent(&self.preferred_id)?;

        // onblock heads the block, before any mempool transaction, so its action
        // digests come first in the action merkle — matching what validators
        // recompute in `execute_block`.
        let producer = self.node_config.as_ref().unwrap().producer_name;
        let previous = self.preferred_id;
        let (onblock_digests, onblock_schedule) =
            self.run_onblock(&timestamp, producer, previous, &block_status)?;
        action_receipt_digests.extend(onblock_digests);
        // onblock's proposal counts like any transaction's (eosio.system elects
        // producers from there); a later transaction's proposal overrides it.
        proposed_schedule = onblock_schedule;

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
                    transaction_traces.push(result.trace.clone());
                    let receipt = TransactionReceipt::new(result.trace.receipt, transaction);
                    transaction_receipts.push_back(receipt);
                    action_receipt_digests.extend(result.action_receipt_digests);
                    if result.proposed_schedule.is_some() {
                        proposed_schedule = result.proposed_schedule;
                    }
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
            block_session
                .pin_mut()
                .undo()
                .map_err(|e| ChainError::DatabaseError(format!("failed to undo changes: {}", e)))?;
            db.arena_undo(); // discard the empty block's session on both
            return Err(ChainError::NetworkError(format!(
                "built block has no transactions"
            )));
        }

        // Create a new block
        let transaction_mroot = self.calculate_trx_merkle(&transaction_receipts)?;
        let action_mroot = self.calculate_action_merkle(&mut action_receipt_digests)?;
        let mut block = SignedBlock::new(
            self.preferred_id,
            timestamp,
            self.node_config.as_ref().unwrap().producer_name, // Use producer name from config
            transaction_receipts,
            transaction_mroot,
            action_mroot,
        );

        // The schedule in force for this block is the one active as of its parent
        // (the tip we build on), folding in any not-yet-accepted ancestor's
        // change. Refuse to produce a block this node isn't authorized to sign:
        // if our key isn't that schedule's key for our producer, the block would
        // fail verification everywhere (including here), so fail closed instead of
        // emitting an unverifiable block after a schedule change.
        let parent_schedule = self.schedule_active_for_parent(&self.preferred_id)?;
        let node = self.node_config.as_ref().unwrap();
        let producer = node.producer_name;
        let signing_key = node.producer_key.get_public_key();
        match parent_schedule.block_signing_key(&producer) {
            Some(scheduled) if *scheduled == signing_key => {}
            _ => {
                block_session.pin_mut().undo().map_err(|e| {
                    ChainError::DatabaseError(format!("failed to undo changes: {}", e))
                })?;
                return Err(ChainError::BlockError(format!(
                    "node key is not the active schedule key for producer {}; refusing to produce",
                    producer
                )));
            }
        }

        // If a transaction in this block proposed a new schedule, carry it in the
        // signed header (`new_producers` + `schedule_version`) so the change is
        // committed with the block and reconstructable from the block log. The new
        // version follows the parent schedule's.
        if let Some(ref producers) = proposed_schedule {
            let new_schedule = ProducerSchedule {
                version: parent_schedule.version + 1,
                producers: producers.clone(),
            };
            let packed = new_schedule
                .pack()
                .map_err(|e| ChainError::SerializationError(e.to_string()))?;
            block.signed_block_header.header.new_producers = Some(packed);
            block.signed_block_header.header.schedule_version = new_schedule.version;
        }

        // Sign the block with the producer's key over the full header — including
        // any schedule change — so validators authenticate it against the schedule.
        let sig_digest: crate::utils::Digest =
            block.signed_block_header.header.sig_digest()?.0.into();
        block.signed_block_header.signature = node.producer_key.sign(&sig_digest)?;

        // We built this block so no need to verify it again
        let block_id = block.id()?;
        self.verified_blocks.insert(block_id, block.clone());

        // A schedule change is part of the block's own state: rewrite the
        // pulse.prods producer permissions inside the block session, so the
        // change is tracked by the block's undo state (unwinding with the block
        // on a fork) and reaches the block's state-history deltas at accept.
        // `execute_block` applies the same write at the same point.
        if let Some(ref producers) = proposed_schedule {
            self.update_producers_authority(producers, block.timestamp())?;
        }

        // Match the end-of-block bookkeeping that `execute_block` applies at
        // verify/accept, so the retained state is identical to what a re-execution
        // would commit, then retain the block on the pending chain (it was built
        // on the current tip). The arena session opened with `block_session` stays
        // open in lockstep — committed if this block is accepted, undone if the
        // chain unwinds past it.
        self.finalize_block_resources(block.block_num())?;
        self.pending_chain.push(PendingBlock {
            id: block_id,
            parent: self.preferred_id,
            session: block_session,
            traces: transaction_traces,
            proposed_schedule,
        });

        Ok(block)
    }

    // The producer schedule active for a block whose parent is `parent_id`: the
    // schedule at the last accepted block, with every not-yet-accepted ancestor's
    // schedule change folded in, oldest first. This makes verification a function
    // of the parent alone, not of whether an ancestor happened to be accepted yet
    // — two nodes always resolve the same schedule for the same block. A later
    // proposal fully replaces an earlier one, matching activation on accept.
    fn schedule_active_for_parent(&self, parent_id: &Id) -> Result<ProducerSchedule, ChainError> {
        if *parent_id == self.last_accepted_block_id {
            return Ok(self.active_schedule.clone());
        }
        let mut version = self.active_schedule.version;
        let mut producers = self.active_schedule.producers.clone();
        for pending in &self.pending_chain {
            if let Some(proposed) = &pending.proposed_schedule {
                version += 1;
                producers = proposed.clone();
            }
            if pending.id == *parent_id {
                return Ok(ProducerSchedule { version, producers });
            }
        }
        // The parent is neither the last accepted block nor a pending ancestor, so
        // we can't resolve its schedule. In-order consensus verifies a parent
        // before its child, so this only happens for an unknown/detached parent.
        Err(ChainError::BlockError(format!(
            "cannot resolve producer schedule: parent {} is unknown",
            parent_id
        )))
    }

    // Test/helper: make a schedule the active one directly, bumping the version.
    // Production activation goes through `accept_block`, which reads the schedule
    // from the accepted block's header so it matches what the block log carries.
    #[cfg(test)]
    fn activate_producer_schedule(
        &mut self,
        producers: Vec<ProducerKey>,
    ) -> Result<(), ChainError> {
        self.active_schedule = ProducerSchedule {
            version: self.active_schedule.version + 1,
            producers,
        };
        info!(
            "activated producer schedule version {}",
            self.active_schedule.version
        );
        Ok(())
    }

    // Authenticate a block against a schedule: recover the signer from the
    // producer signature over the header's sig digest and require it to be the
    // block producer's key in `schedule`. The caller passes the schedule active as
    // of the block's parent (`schedule_active_for_parent`).
    fn verify_block_signature(
        &self,
        block: &SignedBlock,
        schedule: &ProducerSchedule,
    ) -> Result<(), ChainError> {
        let header = &block.signed_block_header.header;
        let expected = schedule
            .block_signing_key(&header.producer)
            .ok_or_else(|| {
                ChainError::BlockError(format!(
                    "block producer {} is not in the active schedule",
                    header.producer
                ))
            })?;
        let digest: crate::utils::Digest = header.sig_digest()?.0.into();
        let signer = block
            .signed_block_header
            .signature
            .recover_public_key(&digest)?;
        if &signer != expected {
            return Err(ChainError::BlockError(
                "block signature does not match the scheduled producer key".into(),
            ));
        }
        Ok(())
    }

    // Bind the schedule change advertised in a block header to what the block's
    // transactions actually did. Without this a producer could execute
    // `set_proposed_producers(X)` yet stamp `Y` in the (signed) header: validators
    // activate `Y` from the header on accept while resolving descendants against
    // `X`, forking the chain. `parent_schedule` is the schedule active as of the
    // block's parent, so the new version must be exactly one past it.
    fn check_schedule_consistency(
        &self,
        block: &SignedBlock,
        executed: &Option<Vec<ProducerKey>>,
        parent_schedule: &ProducerSchedule,
    ) -> Result<(), ChainError> {
        let header_schedule = block.signed_block_header.header.new_schedule()?;
        match (header_schedule, executed) {
            (None, None) => Ok(()),
            (Some(_), None) => Err(ChainError::BlockError(
                "block header carries a schedule change its transactions did not make".into(),
            )),
            (None, Some(_)) => Err(ChainError::BlockError(
                "block changed the schedule but its header carries no new_producers".into(),
            )),
            (Some(header_schedule), Some(executed)) => {
                if &header_schedule.producers != executed {
                    return Err(ChainError::BlockError(
                        "block header schedule does not match the executed schedule".into(),
                    ));
                }
                if header_schedule.version != parent_schedule.version + 1 {
                    return Err(ChainError::BlockError(format!(
                        "block schedule version {} does not follow parent version {}",
                        header_schedule.version, parent_schedule.version
                    )));
                }
                Ok(())
            }
        }
    }

    /// Verify a block against the schedule active as of its parent, execute it
    /// speculatively, and require our re-derived action and transaction merkle
    /// roots to match the ones the header commits to. The VM reproduces block
    /// ids bit-for-bit (see `block_ids_replay_bit_for_bit_from_serialized_bytes`),
    /// so a divergent re-execution is rejected here rather than silently
    /// accepted — there is no path that skips the root check.
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

        // Verify the block. Authenticate the signature against the schedule active
        // as of this block's parent — folding in any pending ancestor's change —
        // rather than whatever happens to be accepted right now, so two nodes
        // reach the same verdict regardless of accept timing.
        block.validate_syntactically(&self.db)?;
        let parent_schedule = self.schedule_active_for_parent(block.previous_id())?;
        self.verify_block_signature(block, &parent_schedule)?;
        // Contracts in this block see the schedule active as of its parent.
        self.block_active_schedule = parent_schedule.clone();

        let parent_block_id = block.previous_id().clone();
        let block_status = BlockStatus::Verifying;
        // Reconcile the pending chain to the parent, reusing any already-executed
        // prefix instead of re-running every unaccepted ancestor.
        self.replay_accepted_state_to(parent_block_id.clone(), &block_status, mempool)?;

        // This block's own session sits on top of the reconciled parent state. If
        // execution or validation below fails, `?` drops the session and chainbase
        // undoes it, leaving the pending chain at the parent.
        let block_session = self.db.create_undo_session(true)?;
        self.db.arena_start_undo_session(); // mirror the block session; retained on the pending chain

        // On any failure below, `block_session` drops and chainbase undoes it via
        // RAII; the arena has no such hook, so mirror the undo explicitly before
        // returning, keeping the two session stacks the same depth.
        let (transaction_traces, transaction_mroot, action_mroot, proposed_schedule) =
            match self.execute_block(block, &block_status, mempool) {
                Ok(v) => v,
                Err(e) => {
                    self.db.arena_undo();
                    return Err(e);
                }
            };

        if let Err(e) = block.validate_semantically(transaction_mroot, action_mroot) {
            self.db.arena_undo();
            return Err(e);
        }

        // The schedule change the header advertises must match what the block's
        // transactions actually did, so the header can be trusted as the schedule
        // source on accept and restart.
        if let Err(e) = self.check_schedule_consistency(block, &proposed_schedule, &parent_schedule)
        {
            self.db.arena_undo();
            return Err(e);
        }

        let block_id = block.id()?;
        self.verified_blocks.insert(block_id, block.clone());

        // Retain the executed block on the pending chain so `accept_block` can
        // commit it without re-executing. The arena session stays open in lockstep.
        self.pending_chain.push(PendingBlock {
            id: block_id,
            parent: parent_block_id,
            session: block_session,
            traces: transaction_traces,
            proposed_schedule,
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
            self.db.arena_start_undo_session(); // mirror the fallback accept session; committed below
            let block_status = BlockStatus::Accepting;
            let (transaction_traces, _transaction_mroot, _action_mroot, _proposed_schedule) = self
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

        // Activate a schedule change carried by this block, now that it is
        // committed. The schedule is read from the accepted block's own (signed)
        // header, so what takes effect is exactly what the block log records and
        // what a restart reconstructs — never an out-of-band value. A block that
        // is rejected or loses a fork is never accepted, so it never changes the
        // producers. `verify_block` has already bound the header to execution.
        // Only the signer set flips here: the pulse.prods permission rewrite
        // already rode inside the block's session (build_block/execute_block),
        // so it was committed — and packed into the block's deltas — above.
        if let Some(schedule) = block.signed_block_header.header.new_schedule()? {
            info!("activated producer schedule version {}", schedule.version);
            self.active_schedule = schedule;
        }

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

    // Build and run the implicit `pulse::onblock` action that heads every block,
    // mirroring EOSIO. It is not a block transaction, so it never touches the
    // transaction merkle; it only contributes its action-receipt digests to the
    // action merkle, which the caller prepends ahead of the block's own actions.
    //
    // The action data is the pending block header with both merkle roots left at
    // zero (they aren't known until the block is assembled). `build_block` and
    // `execute_block` derive it from the same fields, so producer and validator
    // feed byte-identical data into the action digest.
    //
    // onblock is billed to nobody, needs no signature, and must never halt the
    // chain: it runs in its own child session that is discarded on failure, and
    // a failure yields no digests (identical on every node, since it is
    // deterministic), so the merkles still agree.
    //
    // Besides the digests, the result carries any producer schedule the onblock
    // action proposed. eosio.system calls set_proposed_producers exclusively
    // from onblock (update_elected_producers), so the caller must fold this into
    // the block's proposal like any transaction's — dropping it would sever the
    // voting path from the chain and the schedule would never change.
    // Hand the transaction context the producer schedule in force for this block
    // (names + version), so `get_active_producers` returns the active set and
    // `set_proposed_producers` reports the right next version.
    fn set_context_active_schedule(
        &self,
        trx_context: &TransactionContext,
    ) -> Result<(), ChainError> {
        trx_context.set_active_schedule(
            self.block_active_schedule.producers.clone(),
            self.block_active_schedule.version,
        )
    }

    fn run_onblock(
        &mut self,
        timestamp: &BlockTimestamp,
        producer: Name,
        previous: Id,
        block_status: &BlockStatus,
    ) -> Result<(VecDeque<Digest>, Option<Vec<ProducerKey>>), ChainError> {
        let header = BlockHeader {
            timestamp: timestamp.clone(),
            producer,
            confirmed: 0,
            previous,
            transaction_mroot: Digest::default(),
            action_mroot: Digest::default(),
            schedule_version: 0,
            new_producers: None,
            header_extensions: vec![],
        };
        let header_bytes = header.pack().map_err(|e| {
            ChainError::SerializationError(format!("failed to pack onblock header: {}", e))
        })?;

        let action = Action::new(
            PULSE_NAME,
            ONBLOCK_NAME,
            header_bytes,
            vec![PermissionLevel::new(
                PULSE_NAME.as_u64(),
                ACTIVE_NAME.as_u64(),
            )],
        );
        let trx = Transaction::new(TransactionHeader::default(), vec![], vec![action]);
        let packed = PackedTransaction::from_signed_transaction(SignedTransaction::new(
            trx.clone(),
            BTreeSet::new(),
            vec![],
        ))?;

        let trx_id = *packed.id();
        let mut session = self.db.create_undo_session(true)?;
        self.db.arena_start_undo_session(); // mirror the onblock session
        let mut trx_context = TransactionContext::new(
            self.db.clone(),
            self.wasm_runtime.clone(),
            self.last_accepted_block().block_num() + 1,
            timestamp.clone(),
            &trx_id,
            *block_status,
            packed,
            self.max_transaction_time_ms(),
        );
        self.set_context_active_schedule(&trx_context)?;

        let executed = (|| -> Result<TransactionResult, ChainError> {
            trx_context.init_for_implicit_trx(&trx)?;
            trx_context.exec(&trx)?;
            trx_context.finalize()
        })();

        match executed {
            Ok(result) => {
                session.pin_mut().squash().map_err(|e| {
                    ChainError::DatabaseError(format!("failed to commit onblock: {}", e))
                })?;
                self.db.arena_squash(); // fold onblock into the block on both
                Ok((result.action_receipt_digests, result.proposed_schedule))
            }
            Err(e) => {
                // A contract without an onblock handler rejects the implicit
                // action as unknown. That is an expected no-op on such chains;
                // other failures still deserve a warning.
                if e.to_string().contains("unknown action") {
                    debug!("onblock not implemented by the system contract, skipping");
                } else {
                    warn!("onblock failed, skipping: {}", e);
                }
                session.pin_mut().undo().map_err(|e| {
                    ChainError::DatabaseError(format!("failed to undo onblock: {}", e))
                })?;
                self.db.arena_undo(); // a failed onblock leaves no trace on either
                Ok((VecDeque::new(), None))
            }
        }
    }

    pub fn execute_block(
        &mut self,
        block: &SignedBlock,
        block_status: &BlockStatus,
        mempool: &mut Mempool,
    ) -> Result<
        (
            Vec<TransactionTrace>,
            Digest,
            Digest,
            Option<Vec<ProducerKey>>,
        ),
        ChainError,
    > {
        let mut transaction_traces: Vec<TransactionTrace> = Vec::new();
        let mut transaction_receipts: VecDeque<TransactionReceipt> = VecDeque::new();
        let mut action_receipt_digests: VecDeque<Digest> = VecDeque::new();
        let mut proposed_schedule: Option<Vec<ProducerKey>> = None;

        self.blocks_executed += 1;

        self.db
            .clear_expired_input_transactions(&block.timestamp().to_time_point())?;

        // onblock heads the block: its action digests precede every transaction's.
        let header = &block.signed_block_header.header;
        let (onblock_digests, onblock_schedule) = self.run_onblock(
            &header.timestamp,
            header.producer,
            header.previous,
            block_status,
        )?;
        action_receipt_digests.extend(onblock_digests);
        // Mirror build_block: onblock's proposal counts like any transaction's,
        // overridden by a later transaction's — keeping verify's re-execution in
        // agreement with what the producer folded into the header.
        proposed_schedule = onblock_schedule;

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
            if result.proposed_schedule.is_some() {
                proposed_schedule = result.proposed_schedule;
            }

            // Remove from mempool if we have it
            if block_status == &BlockStatus::Accepting {
                mempool.remove_transaction(receipt.trx().id());
            }
        }

        let transaction_mroot = self.calculate_trx_merkle(&transaction_receipts)?;
        let action_mroot = self.calculate_action_merkle(&mut action_receipt_digests)?;

        // Mirror build_block: a schedule change rewrites the pulse.prods
        // producer permissions inside the block's session, so verification
        // commits the same state the producer built and the change reaches the
        // block's state-history deltas at accept.
        if let Some(ref producers) = proposed_schedule {
            self.update_producers_authority(producers, block.timestamp())?;
        }

        self.finalize_block_resources(block.block_num())?;

        Ok((
            transaction_traces,
            transaction_mroot,
            action_mroot,
            proposed_schedule,
        ))
    }

    // Apply the end-of-block resource-limit bookkeeping. This is part of the
    // block's committed state and must run identically whether the block is
    // executed via `execute_block` (verify/accept) or assembled in `build_block`,
    // otherwise a retained build session would commit state that diverges from
    // what validators compute.
    // The elastic CPU/NET block parameters derived from the chain config: the
    // per-block ceiling (max) and the target the elastic limit relaxes toward.
    fn block_elastic_parameters(
        &self,
    ) -> Result<(ElasticLimitParameters, ElasticLimitParameters), ChainError> {
        let chain_config = self.db.chain_config()?;
        let cpu_elastic_parameters = ElasticLimitParameters::new(
            eos_percent(
                chain_config.max_block_cpu_usage as u64,
                chain_config.target_block_cpu_usage_pct,
            ),
            chain_config.max_block_cpu_usage as u64,
            BLOCK_CPU_USAGE_AVERAGE_WINDOW_MS / BLOCK_INTERVAL_MS,
            MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER,
            make_ratio(99, 100),
            make_ratio(1000, 999),
        );
        let net_elastic_parameters = ElasticLimitParameters::new(
            eos_percent(
                chain_config.max_block_net_usage,
                chain_config.target_block_net_usage_pct,
            ),
            chain_config.max_block_net_usage,
            BLOCK_SIZE_AVERAGE_WINDOW_MS / BLOCK_INTERVAL_MS,
            MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER,
            make_ratio(99, 100),
            make_ratio(1000, 999),
        );
        Ok((cpu_elastic_parameters, net_elastic_parameters))
    }

    fn finalize_block_resources(&mut self, block_num: u32) -> Result<(), ChainError> {
        let (cpu_elastic_parameters, net_elastic_parameters) = self.block_elastic_parameters()?;
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
        // Standalone (mempool) validation runs against the head schedule; there is
        // no pending block, so the active set a contract reads is the accepted one.
        self.block_active_schedule = self.active_schedule.clone();
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
        self.execute_transaction_billed(
            packed_transaction,
            pending_block_timestamp,
            block_status,
            None,
        )
    }

    /// As `execute_transaction`, but when `explicit_billed` is set (applying an
    /// already-accepted block) it bills the block-recorded cpu/net and skips the
    /// objective resource-limit checks — Antelope light/replay validation.
    // The node-local wall-clock ceiling for a single transaction (see
    // NodeConfig::max_transaction_time_ms). Falls back to a generous default when
    // no config is loaded (a bare test controller).
    fn max_transaction_time_ms(&self) -> u32 {
        self.node_config
            .as_ref()
            .map(|c| c.max_transaction_time_ms)
            .unwrap_or(30_000)
    }

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

        // Verify authority — but only when this node is the one admitting the
        // transaction (mempool/producing). When applying an already-accepted
        // block (explicit_billed), signatures were authenticated by the producer,
        // so this is Antelope light/replay validation: the authority check is
        // skipped, exactly like the objective resource-limit checks below. It has
        // no state effect (auth_sequence and permission-usage bumps happen during
        // execution and finalize), so skipping it leaves the resulting state and
        // receipts unchanged.
        if explicit_billed.is_none() {
            AuthorizationManager::check_authorization(
                &mut self.db,
                &signed_transaction.transaction().actions,
                &signed_transaction.recovered_keys(&self.chain_id)?,
                &BTreeSet::new(),
                seconds(signed_transaction.transaction().header.delay_sec.into()),
                &BTreeSet::new(),
            )?;
        }

        let mut trx_context = TransactionContext::new(
            self.db.clone(),
            self.wasm_runtime.clone(),
            self.last_accepted_block().block_num() + 1,
            pending_block_timestamp.clone(),
            packed_transaction.id(),
            *block_status,
            packed_transaction.clone(),
            self.max_transaction_time_ms(),
        );
        self.set_context_active_schedule(&trx_context)?;

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

    pub fn active_producer_schedule(&self) -> &ProducerSchedule {
        &self.active_schedule
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

    // ----- state sync (Avalanche StateSyncableVM) -------------------------
    //
    // chainbase has no object serializer and its SHiP delta stream is lossy for
    // reconstruction, so state moves as a physical copy of the arena file (see
    // `Database::snapshot_bytes`). The summary itself is a small commitment; the
    // snapshot payload is fetched separately, chunk by chunk, over the AppRequest
    // channel (see `crate::chain::state_sync` and the node's sync manager). The
    // producing side caches the snapshot it advertised so it can serve those
    // chunks without re-snapshotting per request.

    /// Produce a state summary for the last accepted block, caching the snapshot
    /// it commits to so `serve_snapshot_chunk` can answer download requests.
    ///
    /// Snapshots the live arena when the cache is stale, so the caller must hold
    /// the controller exclusively (no block being processed): `snapshot_bytes`
    /// briefly drops and remaps the database.
    pub fn produce_state_summary(&mut self) -> Result<StateSummary, ChainError> {
        let height = self.last_accepted_block.block_num();

        // Reuse the cached snapshot while it still commits to the tip; otherwise
        // take a fresh one. Re-snapshotting scans the whole arena, so caching
        // matters when a peer pulls many chunks for the same summary.
        if self.snapshot_cache.as_ref().map(|c| c.height) != Some(height) {
            let envelope = self.db.snapshot_bytes()?;
            let hash = *Digest::hash(&envelope).as_bytes();
            self.snapshot_cache = Some(CachedSnapshot {
                height,
                hash,
                envelope,
            });
        }
        let cache = self.snapshot_cache.as_ref().unwrap();

        let block_bytes = self
            .last_accepted_block
            .pack()
            .map_err(|e| ChainError::InternalError(format!("summary: pack block: {}", e)))?;
        let schedule_bytes = self
            .active_schedule
            .pack()
            .map_err(|e| ChainError::InternalError(format!("summary: pack schedule: {}", e)))?;
        let bytes = state_sync::encode_summary_bytes(
            &schedule_bytes,
            &block_bytes,
            cache.envelope.len() as u64,
            &cache.hash,
        );

        Ok(StateSummary {
            id: self.last_accepted_block_id.clone(),
            height: height as u64,
            bytes,
        })
    }

    /// Read a summary's id and height without applying it.
    pub fn parse_state_summary(bytes: &[u8]) -> Result<(Id, u64), ChainError> {
        let target = state_sync::decode_summary_bytes(bytes)?;
        Ok((target.block.id()?, target.height))
    }

    /// Parse a summary into a [`SyncTarget`] the sync manager can drive a
    /// download from.
    pub fn sync_target_from_summary(bytes: &[u8]) -> Result<state_sync::SyncTarget, ChainError> {
        state_sync::decode_summary_bytes(bytes)
    }

    /// Serve one slice of the snapshot a peer is downloading. Answered only when
    /// the cached snapshot matches the requested `height` and `hash`; a stale or
    /// absent cache is an error the caller turns into an AppRequest failure so the
    /// peer retries elsewhere or re-fetches the summary.
    pub fn serve_snapshot_chunk(
        &self,
        height: u64,
        hash: &[u8; 32],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, ChainError> {
        let cache = self
            .snapshot_cache
            .as_ref()
            .ok_or_else(|| ChainError::InternalError("serve chunk: no snapshot cached".into()))?;
        if cache.height as u64 != height || &cache.hash != hash {
            return Err(ChainError::InternalError(
                "serve chunk: request does not match the cached snapshot".into(),
            ));
        }
        let start = offset as usize;
        let end = start
            .checked_add(len as usize)
            .filter(|&e| e <= cache.envelope.len())
            .ok_or_else(|| ChainError::InternalError("serve chunk: out of range".into()))?;
        Ok(cache.envelope[start..end].to_vec())
    }

    /// Apply a downloaded snapshot: swap the arena to it, re-base the block log to
    /// the snapshot's block, and adopt it as the tip.
    ///
    /// State sync fast-forwards past blocks this node never downloaded, so the
    /// block log can't stay gapless from genesis — it is re-based to start at the
    /// snapshot block, and the trace/chain-state logs are cleared to resume at the
    /// next accepted block. The schedule in force at the snapshot is persisted so
    /// a later restart recovers it. `envelope` has already been verified against
    /// the summary hash by the download driver; `restore_from_bytes` re-checks its
    /// internal checksum.
    pub fn apply_state_snapshot(
        &mut self,
        block: SignedBlock,
        schedule: ProducerSchedule,
        envelope: &[u8],
    ) -> Result<(), ChainError> {
        let block_id = block.id()?;

        // Drop speculative and cached blocks: after a sync the tip is the
        // snapshot block, not anything we were building on.
        self.clear_pending()?;
        self.verified_blocks.clear();

        // The chainbase revision advances one per accepted block, so the
        // snapshot's revision must equal the summary block's height. Check it
        // from the header first: a mismatch means the summary paired a block with
        // a snapshot of different state, and we reject it before the swap rather
        // than half-adopt an inconsistent tip.
        let header = pulsevm_ffi::peek_snapshot_header(envelope)?;
        if header.revision as u64 != block.block_num() as u64 {
            return Err(ChainError::InternalError(format!(
                "snapshot revision {} does not match summary block height {}",
                header.revision,
                block.block_num()
            )));
        }

        // Swap chainbase to the snapshot's state; its revision becomes the
        // snapshot height.
        self.db.restore_from_bytes(envelope)?;

        // Re-base the logs. The block log starts again at the snapshot block so a
        // restart reconstructs the tip from here; the state-history logs have no
        // entries for a block this node never executed, so they are cleared.
        let packed_block = block
            .pack()
            .map_err(|e| ChainError::InternalError(format!("accept: pack block: {}", e)))?;
        self.block_log
            .as_ref()
            .ok_or_else(|| ChainError::InternalError("accept: no block log".into()))?
            .reset_to(block_id.clone(), &packed_block)
            .map_err(|e| ChainError::InternalError(format!("accept: rebase block log: {}", e)))?;
        if let Some(log) = self.trace_log.as_ref() {
            log.clear().map_err(|e| {
                ChainError::InternalError(format!("accept: clear trace log: {}", e))
            })?;
        }
        if let Some(log) = self.chain_state_log.as_ref() {
            log.clear().map_err(|e| {
                ChainError::InternalError(format!("accept: clear chain state log: {}", e))
            })?;
        }

        // Persist the schedule in force at the snapshot before adopting it, so a
        // restart-after-sync recovers it (the re-based log's tip may not carry a
        // schedule change).
        self.write_synced_schedule(&schedule)?;
        self.active_schedule = schedule;

        self.last_accepted_block = block;
        self.last_accepted_block_id = block_id.clone();
        self.preferred_id = block_id;
        // The cache commits to the pre-sync tip; drop it.
        self.snapshot_cache = None;
        Ok(())
    }

    fn write_synced_schedule(&self, schedule: &ProducerSchedule) -> Result<(), ChainError> {
        let dir = self
            .db_path
            .as_ref()
            .ok_or_else(|| ChainError::InternalError("accept: no db path".into()))?;
        let packed = schedule
            .pack()
            .map_err(|e| ChainError::InternalError(format!("accept: pack schedule: {}", e)))?;
        std::fs::write(std::path::Path::new(dir).join(SYNCED_SCHEDULE_FILE), packed)
            .map_err(|e| ChainError::InternalError(format!("accept: write schedule: {}", e)))
    }

    fn load_synced_schedule(db_path: &str) -> Option<ProducerSchedule> {
        let bytes = std::fs::read(std::path::Path::new(db_path).join(SYNCED_SCHEDULE_FILE)).ok()?;
        ProducerSchedule::read_bounded(&bytes).ok()
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
            self.db.arena_start_undo_session(); // mirror the replayed block's session
            let (traces, _transaction_mroot, _action_mroot, proposed_schedule) =
                match self.execute_block(block, block_status, mempool) {
                    Ok(v) => v,
                    Err(e) => {
                        self.db.arena_undo(); // session drops on the error; mirror the undo
                        return Err(e);
                    }
                };
            self.pending_chain.push(PendingBlock {
                id: block.id()?,
                parent: block.previous_id().clone(),
                session,
                traces,
                proposed_schedule,
            });
        }

        Ok(())
    }

    pub fn get_greylist_limit() -> Result<u32, ChainError> {
        Ok(1000) // TODO: Implement greylist limit
    }

    // Rewrite the pulse.prods producer permissions to require the given
    // producer set. Runs inside the block's undo session (from `build_block` /
    // `execute_block`, not at accept), so the writes are tracked with the block
    // — they unwind with it on a fork and land in the block's state-history
    // deltas, which are packed from the session's undo state at accept.
    fn update_producers_authority(
        &mut self,
        producers: &[ProducerKey],
        pending_block_time: &BlockTimestamp,
    ) -> Result<(), ChainError> {
        let num_producers = producers.len() as u32;

        let update_permission = |db: &mut Database,
                                 actor: Name,
                                 permission: Name,
                                 threshold: u32|
         -> Result<(), ChainError> {
            let mut auth = Authority::new(threshold, vec![], vec![], vec![]);

            for producer in producers {
                auth.accounts.push(PermissionLevelWeight::new(
                    PermissionLevel::new(producer.producer_name.into(), ACTIVE_NAME.into()),
                    1,
                ));
            }

            db.modify_permission(
                actor.into(),
                permission.into(),
                &auth,
                &pending_block_time.to_time_point(),
            )?;

            Ok(())
        };
        let calculate_threshold = |numerator: u32, denominator: u32| -> u32 {
            (num_producers * numerator) / denominator + 1
        };

        update_permission(
            &mut self.db,
            PRODS_NAME,
            ACTIVE_NAME,
            calculate_threshold(2, 3), // more than 2/3 of producers must sign
        )?;
        update_permission(
            &mut self.db,
            PRODS_NAME,
            MAJORITY_PRODUCERS_PERMISSION_NAME,
            calculate_threshold(1, 2), // more than 1/2 of producers must sign
        )?;
        update_permission(
            &mut self.db,
            PRODS_NAME,
            MINORITY_PRODUCERS_PERMISSION_NAME,
            calculate_threshold(1, 3), // more than 1/3 of producers must sign
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::Path,
        str::FromStr,
        sync::Arc,
        vec,
    };

    use pulsevm_ffi::{
        Authority,
        KeyWeight,
        TimePointSec,
    };
    use pulsevm_proc_macros::{
        NumBytes,
        Read,
        Write,
    };
    use pulsevm_serialization::Write;
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::{
        runtime,
        sync::RwLock,
    };

    use crate::{
        ACTIVE_NAME,
        chain::{
            abi::AbiDefinition,
            asset::{
                Asset,
                Symbol,
            },
            authority::PermissionLevel,
            pulse_contract::{
                DeleteAuth,
                LinkAuth,
                NewAccount,
                SetAbi,
                SetCode,
                UnlinkAuth,
                UpdateAuth,
            },
            transaction::{
                Action,
                Transaction,
                TransactionHeader,
            },
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

    // System-contract action args for the bootstrap test.
    // eosio.system::init(unsigned_int version, symbol core).
    #[derive(Debug, Clone, Read, Write, NumBytes)]
    struct SystemInit {
        version: pulsevm_serialization::VarUint32,
        core: Symbol,
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
                // Point-denominated budgets (see config::POINTS_PER_US): a row
                // write costs ~16k points now that the db intrinsics are metered,
                // and the multi-index reference contract does thousands of ops, so
                // the old microsecond-scale 150k is far too small. Match the real
                // chain's genesis.json so tests run under the deployed limits.
                "max_block_cpu_usage": 3000000000u64,
                "target_block_cpu_usage_pct": 2500,
                "max_transaction_cpu_usage": 1000000000,
                "min_transaction_cpu_usage": 100000,
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

    // A distinct, valid account name for index `i` (prefix keeps it from starting
    // with a digit; three base-26 letters give ~17k unique names).
    fn nth_account_name(i: usize) -> Name {
        let alphabet = b"abcdefghijklmnopqrstuvwxyz";
        let mut n = i;
        let mut bytes = vec![b'a'];
        for _ in 0..3 {
            bytes.push(alphabet[n % 26]);
            n /= 26;
        }
        Name::from_str(std::str::from_utf8(&bytes).unwrap()).unwrap()
    }

    // One transaction that creates `count` accounts, i.e. `count` newaccount
    // actions in a single transaction. Each action re-enters execute_action and so
    // hits the wall-clock checktime at its head.
    fn create_many_accounts(
        private_key: &PrivateKey,
        count: usize,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let actions = (0..count)
            .map(|i| {
                Action::new(
                    Name::from_str("pulse").unwrap(),
                    Name::from_str("newaccount").unwrap(),
                    NewAccount {
                        creator: Name::from_str("pulse").unwrap(),
                        name: nth_account_name(i),
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
                )
            })
            .collect();
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            actions,
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

    fn fmt_res(r: &Result<TransactionResult, ChainError>) -> String {
        match r {
            Ok(_) => "OK".to_string(),
            Err(e) => format!("ERR: {e}"),
        }
    }

    /// End-to-end bootstrap of the real system contract
    /// (reference_contracts/pulse_system.wasm) on this node: deploy the token,
    /// create and issue the core token, create the fee/stake accounts the system
    /// contract hardcodes (pulse.ram/ramfee/rex/stake — decoded from the wasm),
    /// deploy the 80KB privileged system contract onto `pulse`, run `init`, bring
    /// the RAM market to life with `setram`, and settle a real `buyrambsys`
    /// purchase — the full resource-market path runs on this node.
    ///
    /// Action signatures match the Proton eosio.system source (our wasm is a
    /// smaller build of it); args are packed directly here rather than via the ABI.
    #[tokio::test]
    async fn bootstrap_system_contract() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mut controller = Controller::new();
        // Realistic CPU/NET limits (the committed genesis.json values, tx 1e9 /
        // block 3e9), not the deliberately-tiny test genesis whose 150000 tx CPU
        // budget can't even afford to deploy an 80KB contract.
        let genesis_bytes = json!({
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
                "max_block_cpu_usage": 3000000000u32,
                "target_block_cpu_usage_pct": 2500,
                "max_transaction_cpu_usage": 1000000000u32,
                "min_transaction_cpu_usage": 100,
                "max_transaction_lifetime": 4294967295u32,
                "max_inline_action_size": 4096,
                "max_inline_action_depth": 6,
                "max_authority_depth": 6,
                "max_action_return_value_size": 256
            }
        })
        .to_string()
        .into_bytes();
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
        let status = BlockStatus::Building;

        // On main, genesis CPU/NET limits only take effect from end-of-block
        // (set_block_parameters runs in finalize, not initialize), so block 1 is
        // capped at the C++ default ~2M and can't afford an 80KB setcode. Advance
        // one block so the genesis limits are live before we deploy — the block
        // needs at least one transaction (empty blocks are gated), so create an
        // ordinary account to carry it.
        {
            let mempool = Arc::new(RwLock::new(Mempool::new()));
            let mut mempool = mempool.write().await;
            mempool.add_transaction(create_account(
                &private_key,
                Name::from_str("alice")?,
                chain_id,
            )?);
            let block = controller.build_block(&mut mempool).await?;
            controller.accept_block(&block.id()?, &mut mempool)?;
            eprintln!("SPIKE: advanced to block {}", block.block_num());
        }
        let ts = controller.last_accepted_block().timestamp().clone();

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let system_wasm =
            fs::read(root.join(Path::new("reference_contracts/pulse_system.wasm"))).unwrap();
        let token_wasm =
            fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();

        let pulse = Name::from_str("pulse")?;
        let token = Name::from_str("pulse.token")?;
        // The core symbol init() records must equal the one the token is created
        // with; derive both from the same Asset so they can't drift.
        let max_supply = Asset::from_str("1000000000.0000 PULSE").unwrap();
        let core = max_supply.symbol;

        // Run one boot action; each step is a precondition for the next, so any
        // failure fails the test with the offending step named.
        macro_rules! step {
            ($label:expr, $trx:expr) => {{
                let r = controller.execute_transaction(&$trx, &ts, &status);
                eprintln!("BOOT {}: {}", $label, fmt_res(&r));
                assert!(r.is_ok(), "boot step failed [{}]: {}", $label, fmt_res(&r));
            }};
        }

        // --- Bootstrap the token ---
        step!(
            "1 newaccount pulse.token",
            create_account(&private_key, token, chain_id)?
        );
        step!(
            "2 setcode pulse_token",
            set_code(&private_key, token, token_wasm, chain_id)?
        );
        // create() requires the token contract's own authority.
        step!(
            "3 token create",
            call_contract(
                &private_key,
                token,
                Name::from_str("create")?,
                &Create {
                    issuer: pulse,
                    max_supply,
                },
                chain_id,
            )?
        );
        // issue() requires the issuer's (pulse's) authority, not the contract's.
        step!(
            "4 token issue",
            call_contract_as(
                &private_key,
                token,
                Name::from_str("issue")?,
                &Issue {
                    to: pulse,
                    quantity: Asset::from_str("1000000.0000 PULSE").unwrap(),
                    memo: "spike".to_string(),
                },
                pulse,
                chain_id,
            )?
        );

        // The system contract hardcodes these fee/stake accounts (decoded straight
        // from the wasm's embedded name constants); init and the resource market
        // reference them, so they must exist before init runs.
        for acct in ["pulse.ram", "pulse.ramfee", "pulse.rex", "pulse.stake"] {
            step!(
                format!("4b newaccount {acct}"),
                create_account(&private_key, Name::from_str(acct)?, chain_id)?
            );
        }

        // --- Deploy + initialize the system contract ---
        eprintln!("SPIKE: pulse_system.wasm is {} bytes", system_wasm.len());
        step!(
            "5 setcode pulse_system onto pulse",
            set_code(&private_key, pulse, system_wasm, chain_id)?
        );
        step!(
            "6 system init",
            call_contract(
                &private_key,
                pulse,
                Name::from_str("init")?,
                &SystemInit {
                    version: pulsevm_serialization::VarUint32(0),
                    core,
                },
                chain_id,
            )?
        );

        // --- Drive the resource market / governance ---
        // init leaves the RAM market with no base liquidity in this build
        // (free_ram() is 0 until max_ram_size is set), so a purchase prices to 0
        // bytes. setram raises max_ram_size and adds the delta to the market base,
        // bringing it to life. Signature (Proton eosio.system): setram(uint64).
        #[derive(Debug, Clone, Read, Write, NumBytes)]
        struct SetRam {
            max_ram_size: u64,
        }
        step!(
            "6b setram",
            call_contract(
                &private_key,
                pulse,
                Name::from_str("setram")?,
                &SetRam {
                    max_ram_size: 16 * 1024 * 1024 * 1024,
                },
                chain_id,
            )?
        );

        // alice was created by the native newaccount handler, which (like EOSIO)
        // leaves her resource limits unlimited (-1). buyram grants the receiver
        // `current_ram_limit + gift`, so on an unlimited account that underflows to
        // a tiny value and the account can't cover the rows the purchase writes. On
        // a real chain the system contract's own newaccount meters accounts first;
        // this 80KB build doesn't expose setalimits, so provision alice directly
        // through the node (the same effect) before buying.
        let alice = Name::from_str("alice")?;
        {
            let mut db = controller.database();
            db.set_account_limits(alice.as_u64(), 8 * 1024, 1_000_000, 1_000_000)?;
        }

        // Drive the RAM market. Signatures confirmed against the Proton
        // eosio.system source (this wasm is a smaller build of that contract):
        // buyrambsys(name payer, name receiver, uint32 bytes) reserves a fixed
        // number of RAM bytes, priced through the bancor market.
        #[derive(Debug, Clone, Read, Write, NumBytes)]
        struct BuyRamB {
            payer: Name,
            receiver: Name,
            bytes: u32,
        }
        step!(
            "7 buyrambsys for alice",
            call_contract(
                &private_key,
                pulse,
                Name::from_str("buyrambsys")?,
                &BuyRamB {
                    payer: pulse,
                    receiver: alice,
                    bytes: 8192,
                },
                chain_id,
            )?
        );

        eprintln!("BOOT: system contract bootstrapped, initialized, and RAM purchased");
        Ok(())
    }

    // Like `call_contract`, but authorizes an arbitrary actor@active instead of the
    // contract account — needed for actions whose required authority is the caller
    // (e.g. token `issue`, authorized by the issuer) rather than the contract.
    fn call_contract_as<T: Write>(
        private_key: &PrivateKey,
        contract: Name,
        action: Name,
        action_data: &T,
        authorizer: Name,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                contract,
                action,
                action_data.pack().unwrap(),
                vec![PermissionLevel::new(
                    authorizer.as_u64(),
                    ACTIVE_NAME.as_u64(),
                )],
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

        // build_block produces a valid block and retains its speculative session
        // on the pending chain (committed on accept, undone if the chain unwinds
        // past it), so the account it created stays visible on BOTH backends. The
        // mirror invariant is that the arena agrees with chainbase, whatever the
        // session policy — so compare the two rather than assume undo/retain.
        mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("glenn")?,
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        let chain_has = !controller.database().find_account_metadata(name)?.is_null();
        let arena_has = controller
            .database()
            .arena_account_metadata_privileged(name)
            .is_some();
        assert_eq!(
            arena_has, chain_has,
            "arena diverged from chainbase on the speculative account after build_block"
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
        let wasm = fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();

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
        assert_eq!(
            threshold, 1,
            "mirrored authority threshold did not round-trip"
        );
        Ok(())
    }

    /// Serve-path permission oracle: with arena reads enabled, authorization
    /// resolves each permission's full authority from the arena
    /// (`DbRead::permission_authority`), not from chainbase. Both transactions
    /// here authorize before they execute, so build_block only succeeds if the
    /// arena-served authority satisfies the signature — the real end-to-end proof
    /// the served authority is correct. Afterwards the served value is read back
    /// directly and the read cross-check must show zero divergences.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_permission_authority_serves_from_arena() -> Result<(), ChainError> {
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
        // Serve authorization reads from the arena for the rest of this test.
        controller.database().enable_arena_reads();

        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;
        let perm = Name::from_str("claude")?;

        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        mempool.add_transaction(update_auth(
            &private_key,
            glenn,
            perm,
            ACTIVE_NAME,
            1,
            chain_id,
        )?);
        // Authorization for both transactions runs through the arena-served
        // authority; a wrong serve would fail the signature check here.
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let owner = glenn.as_u64();
        let perm_u = perm.as_u64();

        // Read the served authority back and confirm it is the arena's decoded
        // value (threshold and one key, matching what updateauth set).
        let served = db
            .read()?
            .permission_authority(owner, perm_u)?
            .expect("arena did not serve the new permission's authority");
        assert_eq!(served.threshold, 1, "served authority threshold is wrong");
        assert_eq!(served.keys.len(), 1, "served authority key count is wrong");

        // Every authorization read served during the two transactions matched
        // chainbase byte-for-byte.
        let (_ok, nc_fail) = db.arena_noncontract_crosscheck_counts();
        assert_eq!(
            nc_fail, 0,
            "arena served {nc_fail} authorization reads that diverged from chainbase"
        );
        Ok(())
    }

    /// Serve-path satisfies oracle: the `permission_object::satisfies` check that
    /// gates every updateauth walks the owner/id/parent tree. Build a chain
    /// active -> a -> b -> c -> d; creating each child requires the authorizing
    /// permission (active) to satisfy the new permission's parent, which for the
    /// deeper links means walking up several parents. With arena reads enabled the
    /// walk is served from the arena — a wrong walk (e.g. a permission-id space
    /// that didn't track chainbase) would reject the updateauth and fail
    /// build_block, and the read cross-check must stay clean. This is also the
    /// end-to-end proof that arena permission ids match chainbase's.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_permission_satisfies_serves_from_arena() -> Result<(), ChainError> {
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
        controller.database().enable_arena_reads();

        let chain_id = controller.chain_id().clone();
        let glenn = Name::from_str("glenn")?;
        let (pa, pb, pc, pd) = (
            Name::from_str("perma")?,
            Name::from_str("permb")?,
            Name::from_str("permc")?,
            Name::from_str("permd")?,
        );

        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        // active -> perma -> permb -> permc -> permd. Creating permc requires
        // active to satisfy permb (one parent hop); permd requires active to
        // satisfy permc (two hops) — the walk, not just the immediate-parent case.
        mempool.add_transaction(update_auth(
            &private_key,
            glenn,
            pa,
            ACTIVE_NAME,
            1,
            chain_id,
        )?);
        mempool.add_transaction(update_auth(&private_key, glenn, pb, pa, 1, chain_id)?);
        mempool.add_transaction(update_auth(&private_key, glenn, pc, pb, 1, chain_id)?);
        mempool.add_transaction(update_auth(&private_key, glenn, pd, pc, 1, chain_id)?);
        // Each updateauth authorizes through the arena-served satisfies walk; a
        // wrong walk would reject one of these and fail build_block.
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let db = controller.database();
        let (_ok, nc_fail) = db.arena_noncontract_crosscheck_counts();
        assert_eq!(
            nc_fail, 0,
            "arena served {nc_fail} authorization reads/satisfies checks that diverged from chainbase"
        );

        // Directly confirm the served walk: active satisfies the two-hop
        // descendant permc, and permb does not satisfy its ancestor active.
        let r = db.read()?;
        let active_perm =
            AuthorizationManager::get_permission(&r, glenn.as_u64(), ACTIVE_NAME.as_u64())?;
        let permc = AuthorizationManager::get_permission(&r, glenn.as_u64(), pc.as_u64())?;
        assert!(
            active_perm.satisfies(&permc, &r)?,
            "active must satisfy its descendant permc"
        );
        assert!(
            !permc.satisfies(&active_perm, &r)?,
            "a descendant must not satisfy its ancestor"
        );
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
        assert_eq!(
            required,
            perm.as_u64(),
            "link did not point at the new permission"
        );
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
        let wasm = fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
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
        let wasm = fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
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
        assert_eq!(
            arena_seq, chain_seq,
            "mirrored global_action_sequence diverged"
        );
        assert!(
            chain_seq > 0,
            "expected applied actions to advance the sequence"
        );
        Ok(())
    }

    /// Static global_property (chain_config) oracle. Genesis seeds the mirror from
    /// chainbase (below the per-write hooks), and a `setparams`-style write must
    /// then update both in lockstep. Assert the mirror equals chainbase at genesis
    /// and again after a config change, and that the change is actually observed.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_global_property_mirrors_setparams() -> Result<(), ChainError> {
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
        let db = controller.database();

        // Genesis: the mirror was seeded from chainbase, so both sides match and
        // the config is non-empty.
        let genesis_chain = db.global_property_state_bytes()?;
        let genesis_arena = db
            .arena_global_property_state_bytes()
            .expect("arena is missing the global_property row after genesis");
        assert!(
            !genesis_chain.is_empty(),
            "genesis chain_config serialized empty"
        );
        assert_eq!(
            genesis_chain, genesis_arena,
            "genesis-seeded global_property diverged from chainbase"
        );

        // Read the active config, change fields of both widths (u32 + u16), and
        // write it back through the same path a setparams intrinsic uses.
        let gpo = Controller::get_global_properties(&db)?;
        let c = gpo.get_chain_config();
        let cfg = pulsevm_ffi::ChainConfigV0 {
            max_block_net_usage: c.get_max_block_net_usage(),
            target_block_net_usage_pct: c.get_target_block_net_usage_pct(),
            max_transaction_net_usage: c.get_max_transaction_net_usage(),
            base_per_transaction_net_usage: c.get_base_per_transaction_net_usage(),
            net_usage_leeway: c.get_net_usage_leeway(),
            context_free_discount_net_usage_num: c.get_context_free_discount_net_usage_num(),
            context_free_discount_net_usage_den: c.get_context_free_discount_net_usage_den(),
            max_block_cpu_usage: c.get_max_block_cpu_usage(),
            target_block_cpu_usage_pct: c.get_target_block_cpu_usage_pct(),
            max_transaction_cpu_usage: c.get_max_transaction_cpu_usage(),
            min_transaction_cpu_usage: c.get_min_transaction_cpu_usage(),
            max_transaction_lifetime: c.get_max_transaction_lifetime(),
            deferred_trx_expiration_window: 0,
            max_transaction_delay: c.get_max_transaction_delay(),
            max_inline_action_size: c.get_max_inline_action_size() + 4096,
            max_inline_action_depth: c.get_max_inline_action_depth(),
            max_authority_depth: c.get_max_authority_depth() + 1,
        };
        // `cfg` copied the values out; the borrow of the chainbase object (`gpo`/`c`)
        // ends here under NLL, before the mutating write below.
        db.set_global_properties(&cfg)?;

        let after_chain = db.global_property_state_bytes()?;
        let after_arena = db
            .arena_global_property_state_bytes()
            .expect("arena is missing the global_property row after setparams");
        assert_eq!(
            after_chain, after_arena,
            "global_property diverged after a config change"
        );
        assert_ne!(
            genesis_chain, after_chain,
            "the config change was not observed on the chainbase side"
        );
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
        assert_eq!(
            arena, chain,
            "mirrored virtual limits diverged from chainbase"
        );
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
        let wasm = fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
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
        let name = glenn.as_u64();

        // account_object + account_metadata_object, field for field.
        assert!(
            !db.find_account(name)?.is_null(),
            "chainbase account missing"
        );
        assert!(db.arena_account_exists(name), "arena account missing");
        let ptr = db.find_account_metadata(name)?;
        assert!(!ptr.is_null());
        let meta = unsafe { &*ptr };
        let arena_meta = db
            .arena_account_metadata(name)
            .expect("arena metadata missing");
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
        let (parent, _threshold) = db
            .arena_permission(name, perm.as_u64())
            .expect("arena perm");
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
        use sha2::{
            Digest,
            Sha256,
        };

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
        let wasm = fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
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
        use sha2::{
            Digest,
            Sha256,
        };

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
        assert_eq!(
            chain_root, arena_root,
            "cross-impl account_object state root diverged"
        );
        assert!(
            chain_bytes.len() > 16,
            "expected multiple accounts with abi data"
        );
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
        use sha2::{
            Digest,
            Sha256,
        };

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
        assert_eq!(
            chain_root, arena_root,
            "cross-impl permission state root diverged"
        );
        assert!(
            !chain_bytes.is_empty(),
            "expected permissions in the enumeration"
        );
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
        use sha2::{
            Digest,
            Sha256,
        };

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
        let wasm = fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
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
        // (table name, chainbase bytes, arena bytes)
        let tables: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
            (
                "account_metadata",
                db.account_metadata_state_bytes()?,
                db.arena_account_metadata_state_bytes().unwrap(),
            ),
            (
                "account",
                db.account_state_bytes()?,
                db.arena_account_state_bytes().unwrap(),
            ),
            (
                "permission",
                db.permission_state_bytes()?,
                db.arena_permission_state_bytes().unwrap(),
            ),
            (
                "permission_link",
                db.permission_link_state_bytes()?,
                db.arena_permission_link_state_bytes().unwrap(),
            ),
            (
                "code",
                db.code_state_bytes()?,
                db.arena_code_state_bytes().unwrap(),
            ),
            (
                "transaction",
                db.transaction_state_bytes()?,
                db.arena_transaction_state_bytes().unwrap(),
            ),
            (
                "resource_usage",
                db.resource_usage_state_bytes()?,
                db.arena_resource_usage_state_bytes().unwrap(),
            ),
            (
                "resource_limits",
                db.account_limits_state_bytes()?,
                db.arena_account_limits_state_bytes().unwrap(),
            ),
            (
                "resource_state",
                db.resource_state_bytes()?,
                db.arena_resource_state_bytes().unwrap(),
            ),
            (
                "dynamic_global_property",
                db.get_global_action_sequence()?.to_le_bytes().to_vec(),
                db.arena_global_action_sequence()
                    .unwrap()
                    .to_le_bytes()
                    .to_vec(),
            ),
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
        assert_eq!(
            chain_root, arena_root,
            "full-state cross-impl root diverged"
        );

        // Sanity: the populated tables are non-empty on both sides.
        for name in [
            "account_metadata",
            "account",
            "permission",
            "code",
            "resource_usage",
        ] {
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
        use sha2::{
            Digest,
            Sha256,
        };

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
        let wasm = fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();

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
            (
                "table_id",
                db.contract_table_state_bytes()?,
                db.arena_contract_table_state_bytes().unwrap(),
            ),
            (
                "key_value",
                db.contract_kv_state_bytes()?,
                db.arena_contract_kv_state_bytes().unwrap(),
            ),
        ];
        let mut chain_root = Sha256::new();
        let mut arena_root = Sha256::new();
        for (name, chain_bytes, arena_bytes) in &tables {
            assert_eq!(
                chain_bytes, arena_bytes,
                "cross-impl contract state diverged for {name}"
            );
            chain_root.update(chain_bytes);
            arena_root.update(arena_bytes);
        }
        assert_eq!(
            <[u8; 32]>::from(chain_root.finalize()),
            <[u8; 32]>::from(arena_root.finalize()),
            "cross-impl contract root diverged"
        );
        assert!(
            !tables[0].1.is_empty(),
            "expected the create action to make a table"
        );
        assert!(
            !tables[1].1.is_empty(),
            "expected the create action to store a row"
        );
        Ok(())
    }

    /// Every cross-impl table as `(name, chainbase bytes, arena bytes)` for the
    /// full-state root — the 10 block-populated tables plus the two contract
    /// primary tables (empty unless a contract wrote rows).
    #[cfg(feature = "arena-shadow")]
    fn cross_impl_tables(
        db: &Database,
    ) -> Result<Vec<(&'static str, Vec<u8>, Vec<u8>)>, ChainError> {
        Ok(vec![
            (
                "account_metadata",
                db.account_metadata_state_bytes()?,
                db.arena_account_metadata_state_bytes().unwrap_or_default(),
            ),
            (
                "account",
                db.account_state_bytes()?,
                db.arena_account_state_bytes().unwrap_or_default(),
            ),
            (
                "permission",
                db.permission_state_bytes()?,
                db.arena_permission_state_bytes().unwrap_or_default(),
            ),
            (
                "permission_link",
                db.permission_link_state_bytes()?,
                db.arena_permission_link_state_bytes().unwrap_or_default(),
            ),
            (
                "code",
                db.code_state_bytes()?,
                db.arena_code_state_bytes().unwrap_or_default(),
            ),
            (
                "transaction",
                db.transaction_state_bytes()?,
                db.arena_transaction_state_bytes().unwrap_or_default(),
            ),
            (
                "resource_usage",
                db.resource_usage_state_bytes()?,
                db.arena_resource_usage_state_bytes().unwrap_or_default(),
            ),
            (
                "resource_limits",
                db.account_limits_state_bytes()?,
                db.arena_account_limits_state_bytes().unwrap_or_default(),
            ),
            (
                "resource_state",
                db.resource_state_bytes()?,
                db.arena_resource_state_bytes().unwrap_or_default(),
            ),
            (
                "dynamic_global_property",
                db.get_global_action_sequence()?.to_le_bytes().to_vec(),
                db.arena_global_action_sequence()
                    .unwrap_or(0)
                    .to_le_bytes()
                    .to_vec(),
            ),
            (
                "global_property",
                db.global_property_state_bytes()?,
                db.arena_global_property_state_bytes().unwrap_or_default(),
            ),
            (
                "resource_limits_config",
                db.resource_config_state_bytes()?,
                db.arena_resource_config_state_bytes().unwrap_or_default(),
            ),
            (
                "contract_table",
                db.contract_table_state_bytes()?,
                db.arena_contract_table_state_bytes().unwrap_or_default(),
            ),
            (
                "contract_key_value",
                db.contract_kv_state_bytes()?,
                db.arena_contract_kv_state_bytes().unwrap_or_default(),
            ),
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
            eprintln!(
                "replay_local_block_log: set PULSEVM_REPLAY_{{BLOCK_LOG_DIR,GENESIS,CHAIN_ID}} to run"
            );
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
        controller.initialize(
            &chain_id,
            &config_bytes,
            &genesis_bytes,
            temp_path.path().to_str().unwrap(),
        )?;

        // Open the source node's block_log (separate from our fresh one).
        let src =
            crate::chain::state_history::StateHistoryLog::open_with_magic(&src_dir, "block_log", 0)
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
        let wasm = fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
        let glenn = Name::from_str("glenn")?;

        // Node A builds a rich block and packs it — the "fixture".
        let packed = {
            let mempool = Arc::new(RwLock::new(Mempool::new()));
            let mut mempool = mempool.write().await;
            let mut a = Controller::new();
            let dir = get_temp_dir();
            a.initialize(
                &chain_id,
                &config_bytes,
                &genesis,
                dir.path().to_str().unwrap(),
            )?;
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
        b.initialize(
            &chain_id,
            &config_bytes,
            &genesis,
            dir.path().to_str().unwrap(),
        )?;
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
            a.initialize(
                &chain_id,
                &config_bytes,
                &genesis,
                dir.path().to_str().unwrap(),
            )?;
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
        assert_eq!(
            packed, built_packed,
            "block_log round-trip corrupted the block"
        );

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let mut mempool = mempool.write().await;
        let mut b = Controller::new();
        let dir = get_temp_dir();
        b.initialize(
            &chain_id,
            &config_bytes,
            &genesis,
            dir.path().to_str().unwrap(),
        )?;
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
        let expected =
            Id::from_str("000000020aacb295ab19375a5c59dbdd5678f8287cdf7395bc42f73fcdc820b4")
                .unwrap();
        assert_eq!(
            got, expected,
            "reconstructed block 2 id mismatch: got {got}"
        );
    }

    /// ISO block timestamp -> Antelope slot (500ms interval, 2000-01-01 epoch).
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
    fn reconstruct_block(r: &serde_json::Value) -> Result<SignedBlock, ChainError> {
        use crate::chain::{
            block::SignedBlockHeader,
            crypto::Signature,
            transaction::{
                PackedTransaction,
                TransactionCompression,
                TransactionReceipt,
                TransactionReceiptHeader,
                TransactionStatus,
            },
        };
        use pulsevm_crypto::Bytes;
        use pulsevm_serialization::VarUint32;
        use std::collections::{
            BTreeSet,
            VecDeque,
        };

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
                    return Err(ChainError::BlockError(format!(
                        "unhandled tx status {other}"
                    )));
                }
            };
            let cpu = t["cpu_usage_us"].as_u64().unwrap() as u32;
            let net = t["net_usage_words"].as_u64().unwrap() as u32;
            let trx = &t["trx"];
            if !trx.is_object() {
                return Err(ChainError::BlockError(
                    "pruned transaction (id only)".into(),
                ));
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
            let packed_trx: Bytes = hex::decode(trx["packed_trx"].as_str().unwrap())
                .unwrap()
                .into();
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
        let chain_id =
            Id::from_str("531a7002b4a4b67987f8706c01b965c76ffc3ad301608ac61a1f738cba6c3a9a")
                .unwrap();
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let config_bytes = json!({"producer_name":"pulse","producer_key":"PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez"})
            .to_string()
            .into_bytes();

        let mut files: Vec<_> = fs::read_dir(&dir)
            .expect("blocks dir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
            .collect();
        files.sort();

        // Fixtures may store the block under a JSON-RPC `result` wrapper (a raw
        // getBlock response) or at the top level (just the block). Accept either,
        // so a wrapper mismatch can't silently make every block parse as block 0
        // and get skipped — which passes the test while replaying nothing.
        fn block_body(v: &serde_json::Value) -> &serde_json::Value {
            match v.get("result") {
                Some(r) if !r.is_null() => r,
                _ => v,
            }
        }

        // The genesis initial_timestamp is block 1's timestamp; the committed
        // genesis.json may carry a placeholder, so patch it to the real one so
        // our genesis block (and the genesis accounts' creation dates) match.
        let b1: serde_json::Value =
            serde_json::from_slice(&fs::read(files.first().expect("no block fixtures")).unwrap())
                .unwrap();
        let b1r = block_body(&b1);
        assert_eq!(
            b1r["block_num"].as_u64(),
            Some(1),
            "first fixture must be block 1"
        );
        let ts = b1r["timestamp"].as_str().unwrap().trim_end_matches(".000");
        let mut g: serde_json::Value =
            serde_json::from_slice(&fs::read(repo_root.join("genesis.json")).unwrap()).unwrap();
        g["initial_timestamp"] = json!(ts);

        // The committed genesis.json also carries a placeholder initial_key, so
        // recover the real system-account key from the first signed transaction
        // (using the real chain_id) and patch it in — otherwise pulse@active
        // won't have the key its transactions are signed with.
        for f in &files {
            let v: serde_json::Value = serde_json::from_slice(&fs::read(f).unwrap()).unwrap();
            let r = block_body(&v);
            if r["transactions"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false)
            {
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
        controller.initialize(
            &chain_id,
            &config_bytes,
            &genesis_bytes,
            temp.path().to_str().unwrap(),
        )?;

        // The arena is the primary read backend (see ArenaShadow): the node
        // serves every contract read FROM the arena, chainbase still takes the
        // writes, and the inline cross-check still runs. If the arena served a
        // wrong byte, execution would diverge and the cross-impl root would break,
        // so a clean full-history replay is the node running on arena-served reads.
        // Reads are on by default; a falsey PULSEVM_ARENA_READS reverts to
        // chainbase, so read the effective state rather than the raw env.
        let arena_reads = controller.database().arena_reads_enabled();

        // Our genesis (block 1) must match the testnet's, or block 2 won't chain.
        let genesis_id = controller.last_accepted_block().id()?;
        let start = controller.last_accepted_block().block_num() + 1;
        assert_eq!(
            genesis_id.to_string(),
            b1r["id"].as_str().unwrap(),
            "our genesis block id != testnet block 1 id — genesis mismatch"
        );

        // getBlock omits the producer signature, so reconstruct_block leaves a
        // placeholder that can't be recovered — block signing/verification landed
        // after this fixture was captured. To still exercise the real
        // verify -> accept path (and the schedule logic that guards it), seed the
        // block-signing schedule with a key we hold (the block-signing key is
        // independent of the genesis account key) and re-sign each reconstructed
        // block with it below. Nothing in this fixture changes the schedule, so it
        // stays this single producer throughout.
        let block_signer =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        controller.active_schedule = ProducerSchedule {
            version: 0,
            producers: vec![ProducerKey {
                producer_name: Name::from_str("pulse")?,
                block_signing_key: block_signer.get_public_key(),
            }],
        };

        // Incremental durability: append the mirror's delta to a WAL after every
        // accepted block, exactly as a running node would, so the crash-recovery
        // reconstruction at the end runs over a real per-block flush cadence.
        let wal = temp.path().join("arena.wal");
        let ckpt = temp.path().join("arena_checkpoint.bin");

        // Restart the mirror once around the middle of the run to prove it
        // resumes from disk and keeps matching chainbase afterward.
        let restart_at = start + (files.len() as u32) / 2;
        let mut restarted = false;
        let mut restart_block = 0u32;

        // Golden per-block arena roots. `PULSEVM_GOLDEN_ROOTS` names a file: if it
        // exists, verify each block's arena root against it and SKIP the live
        // chainbase cross-checks (used by the standalone-write replay, where
        // chainbase is never written and can't be the oracle); if it is set but
        // absent, record the roots for a later verify run. A per-block root is a
        // stable fingerprint over every arena table's canonical state bytes.
        let golden_file = std::env::var("PULSEVM_GOLDEN_ROOTS").ok();
        // Per-(block, table) roots, so a mismatch names the exact diverging table.
        let golden_roots: Option<std::collections::HashMap<(u32, String), u64>> = golden_file
            .as_ref()
            .filter(|p| Path::new(p).exists())
            .map(|p| {
                fs::read_to_string(p)
                    .expect("read golden roots")
                    .lines()
                    .filter_map(|l| {
                        let mut it = l.split_whitespace();
                        let n: u32 = it.next()?.parse().ok()?;
                        let table = it.next()?.to_string();
                        let r = u64::from_str_radix(it.next()?, 16).ok()?;
                        Some(((n, table), r))
                    })
                    .collect()
            });
        let mut recorded: Option<Vec<(u32, String, u64)>> = match &golden_file {
            Some(_) if golden_roots.is_none() => Some(Vec::new()),
            _ => None,
        };

        let mut replayed = 0u32;
        for f in &files {
            let v: serde_json::Value = serde_json::from_slice(&fs::read(f).unwrap()).unwrap();
            let r = block_body(&v);
            let n = r["block_num"].as_u64().unwrap_or(0) as u32;
            if n < start {
                continue;
            }
            let mut block = reconstruct_block(r)?;
            // Sign with the scheduled key so verify_block authenticates it (see
            // the block_signer note above).
            let sig_digest: crate::utils::Digest =
                block.signed_block_header.header.sig_digest()?.0.into();
            block.signed_block_header.signature = block_signer.sign(&sig_digest)?;
            if let Err(e) = controller.verify_block(&block, &mut mempool).await {
                eprintln!("stalled applying block {n}: {e:?}");
                break;
            }
            controller.accept_block(&block.id()?, &mut mempool)?;
            controller.set_preferred_id(block.id()?);
            controller.database().arena_flush_delta(&wal)?;

            let tables = cross_impl_tables(&controller.database())?;

            // Per-table arena root: a fingerprint over one arena table's canonical
            // bytes, recorded/verified table by table so a mismatch names the table.
            let table_root = |arena: &[u8]| -> u64 {
                use std::hash::{
                    Hash,
                    Hasher,
                };
                let mut h = std::collections::hash_map::DefaultHasher::new();
                arena.hash(&mut h);
                h.finish()
            };

            // Golden-verify mode: chainbase is not the oracle (its writes may be
            // skipped), so check each arena table against the recorded set instead
            // of the live cross-impl diff.
            if let Some(golden) = &golden_roots {
                let mut mismatch = None;
                for (name, _chain, arena) in &tables {
                    let h = table_root(arena);
                    if let Some(&g) = golden.get(&(n, name.to_string()))
                        && g != h
                    {
                        mismatch = Some(format!("table {name}: arena {h:016x} != golden {g:016x}"));
                        break;
                    }
                }
                if let Some(m) = mismatch {
                    eprintln!("golden mismatch at block {n}, {m} (matched up to {replayed})");
                    break;
                }
                replayed = n;
                if !restarted && n >= restart_at {
                    assert!(
                        controller.database().arena_restart(&ckpt)?,
                        "arena restart should run with the shadow enabled"
                    );
                    restarted = true;
                    restart_block = n;
                }
                continue;
            }
            if let Some(rec) = &mut recorded {
                for (name, _chain, arena) in &tables {
                    rec.push((n, name.to_string(), table_root(arena)));
                }
            }

            let mut diverged = None;
            for (name, chain_bytes, arena_bytes) in cross_impl_tables(&controller.database())? {
                if chain_bytes != arena_bytes {
                    if name == "contract_key_value" && std::env::var("PULSEVM_KV_DEBUG").is_ok() {
                        let rows = |b: &[u8]| {
                            let mut m = std::collections::BTreeMap::new();
                            let mut p = 0;
                            while p + 44 <= b.len() {
                                let u =
                                    |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
                                let vlen = u32::from_le_bytes(b[p + 40..p + 44].try_into().unwrap())
                                    as usize;
                                let key = (u(p), u(p + 8), u(p + 16), u(p + 24)); // code,scope,table,pk
                                m.insert(
                                    key,
                                    (u(p + 32), b[p + 44..(p + 44 + vlen).min(b.len())].to_vec()),
                                );
                                p += 44 + vlen;
                            }
                            m
                        };
                        let (c, a) = (rows(&chain_bytes), rows(&arena_bytes));
                        for (k, cv) in &c {
                            match a.get(k) {
                                None => eprintln!(
                                    "  chain-only row {k:?} payer={} vlen={}",
                                    cv.0,
                                    cv.1.len()
                                ),
                                Some(av) if av != cv => eprintln!(
                                    "  DIFF row {k:?}: chain payer={} vlen={} | arena payer={} vlen={}",
                                    cv.0,
                                    cv.1.len(),
                                    av.0,
                                    av.1.len()
                                ),
                                _ => {}
                            }
                        }
                        for (k, av) in &a {
                            if !c.contains_key(k) {
                                eprintln!(
                                    "  arena-only row {k:?} payer={} vlen={}",
                                    av.0,
                                    av.1.len()
                                );
                            }
                        }
                    }
                    if name == "resource_state" && std::env::var("PULSEVM_KV_DEBUG").is_ok() {
                        let f = |b: &[u8]| {
                            let u64a =
                                |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
                            // avg_net(20) avg_cpu(20) then 7 u64 scalars
                            format!(
                                "pending_net={} pending_cpu={} tot_net={} tot_cpu={} tot_ram={} vnet={} vcpu={} avgnet_vex={} avgcpu_vex={}",
                                u64a(40),
                                u64a(48),
                                u64a(56),
                                u64a(64),
                                u64a(72),
                                u64a(80),
                                u64a(88),
                                u64a(0),
                                u64a(20)
                            )
                        };
                        eprintln!("  chain: {}", f(&chain_bytes));
                        eprintln!("  arena: {}", f(&arena_bytes));
                    }
                    diverged = Some(name);
                    break;
                }
            }
            if let Some(name) = diverged {
                eprintln!(
                    "cross-impl diverged at block {n}, table {name} (matched blocks up to {replayed})"
                );
                break;
            }
            replayed = n;

            // Restart the mirror once, mid-chain: checkpoint it, drop the live
            // state, reload from disk, and keep going. Every following block still
            // has to match chainbase, which only holds if the reloaded revision
            // and rows line up exactly — the node-reboot guarantee.
            if !restarted && n >= restart_at {
                assert!(
                    controller.database().arena_restart(&ckpt)?,
                    "arena restart should run with the shadow enabled"
                );
                restarted = true;
                restart_block = n;
            }
        }

        // Guard against a silent no-op: if the harness ever parses no real blocks
        // (a fixture-shape or numbering mismatch), `replayed` stays below the
        // first block and the whole cross-check ran on nothing. Fail loudly rather
        // than report a green run over zero blocks.
        assert!(
            replayed >= start,
            "replay covered no blocks (replayed up to {replayed}, expected >= {start}) — \
             fixture/harness mismatch"
        );

        // Record the golden roots (verified this run by the live cross-check) for a
        // later standalone-write verify run.
        if let (Some(path), Some(rec)) = (&golden_file, &recorded) {
            let body: String = rec
                .iter()
                .map(|(n, t, r)| format!("{n} {t} {r:016x}\n"))
                .collect();
            fs::write(path, body).expect("write golden roots");
            eprintln!("recorded {} golden arena roots to {}", rec.len(), path);
        }

        // Golden-verify mode ran with chainbase writes skipped, so the read-surface
        // and persistence cross-checks below — which all read chainbase — don't
        // apply. The per-block arena-root match against the golden set is the proof
        // that the arena reproduced the whole chain on its own.
        if golden_roots.is_some() {
            eprintln!(
                "replayed real testnet blocks up to {replayed} on the ARENA ALONE (chainbase writes skipped); every per-block arena state root matched the golden set recorded from the cross-checked run"
            );
            return Ok(());
        }

        // Read-surface check: the cross-impl root proves the arena *holds* the
        // same rows as chainbase, but running as primary means the arena must
        // *serve* reads. Drive the arena's raw contract read (arena_kv_get — the
        // primitive behind db_get_i64) from chainbase's own enumeration of every
        // contract row, and require the arena to return the same value bytes.
        // Chainbase enumerates, the arena point-reads independently, so a match
        // is a real read-path agreement, not a serialization tautology.
        let db = controller.database();
        let chain_kv = db.contract_kv_state_bytes()?;
        let mut checked = 0u64;
        // chainbase's wire format is already sorted by (code,scope,table,primary),
        // so rows for a table arrive contiguously and in ascending primary order —
        // exactly the sequence a forward scan must reproduce. Collect that expected
        // scan per table as we go, then diff it against the arena's own scan.
        let mut cur_table: Option<(u64, u64, u64)> = None;
        let mut expected_scan: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut tables_scanned = 0u64;
        let flush = |t: (u64, u64, u64), rows: &[(u64, Vec<u8>)]| {
            let got = db.arena_table_range(t.0, t.1, t.2);
            assert_eq!(
                got.as_slice(),
                rows,
                "arena_table_range({},{},{}) scan != chainbase forward scan",
                t.0,
                t.1,
                t.2
            );
        };
        let mut p = 0usize;
        while p + 44 <= chain_kv.len() {
            let u = |o: usize| u64::from_le_bytes(chain_kv[o..o + 8].try_into().unwrap());
            let (code, scope, table, primary) = (u(p), u(p + 8), u(p + 16), u(p + 24));
            let vlen = u32::from_le_bytes(chain_kv[p + 40..p + 44].try_into().unwrap()) as usize;
            let value = chain_kv[p + 44..(p + 44 + vlen).min(chain_kv.len())].to_vec();

            // Point read: the db_get_i64 primitive returns chainbase's value.
            let got = db.arena_kv_get(code, scope, table, primary);
            assert_eq!(
                got.as_deref(),
                Some(value.as_slice()),
                "arena_kv_get({code},{scope},{table},{primary}) != chainbase value"
            );
            checked += 1;

            // Accumulate this table's expected forward scan; flush at each boundary.
            let key = (code, scope, table);
            if cur_table != Some(key) {
                if let Some(prev) = cur_table.take() {
                    flush(prev, &expected_scan);
                    tables_scanned += 1;
                    expected_scan.clear();
                }
                cur_table = Some(key);
            }
            expected_scan.push((primary, value));
            p += 44 + vlen;
        }
        if let Some(prev) = cur_table.take() {
            flush(prev, &expected_scan);
            tables_scanned += 1;
        }

        // Inline read cross-check tally: accumulated by apply_context::db_get_i64
        // over every contract read the node actually served during execution
        // (including mid-transaction speculative reads). Must be all matches.
        let (read_ok, read_fail) = db.arena_read_crosscheck_counts();
        assert_eq!(
            read_fail, 0,
            "arena served {read_fail} contract reads that diverged from chainbase mid-execution"
        );

        // Iterator-positioning cross-check tally: accumulated by the
        // db_next/previous/lowerbound/upperbound wrappers over every cursor move
        // during execution. The arena computed the same landing key as chainbase.
        let (pos_ok, pos_fail) = db.arena_pos_crosscheck_counts();
        assert_eq!(
            pos_fail, 0,
            "arena positioned {pos_fail} iterator moves differently from chainbase"
        );

        // Non-contract read cross-check tally: accumulated by the account and
        // permission lookups the node ran during authorization and dispatch. The
        // arena answered each the same as chainbase (existence, parent, threshold,
        // privileged flag).
        let (nc_ok, nc_fail) = db.arena_noncontract_crosscheck_counts();
        assert_eq!(
            nc_fail, 0,
            "arena answered {nc_fail} account/permission reads differently from chainbase"
        );

        // Persistence at real state size: checkpoint the mirror built from the
        // full history, reload it into a fresh mirror, and require a byte-
        // identical state root. This is the durability the store needs to be
        // primary — the state survives a save/load intact.
        let persist = db.arena_persistence_roundtrip(&ckpt)?;
        let persist_msg = match persist {
            Some((matched, size)) => {
                assert!(
                    matched,
                    "arena state root changed across checkpoint save/load"
                );
                format!("checkpoint {size} bytes reloaded with identical state root")
            }
            None => "persistence check skipped (shadow off)".to_string(),
        };

        // Crash recovery over the incremental path: rebuild a fresh mirror purely
        // from the per-block WAL and require the same state root as the live one.
        let wal_msg = match db.arena_wal_reload_matches(&wal)? {
            Some(matched) => {
                assert!(
                    matched,
                    "arena state root changed when rebuilt from the WAL"
                );
                let size = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
                format!("{size}-byte per-block WAL replayed to identical state root")
            }
            None => "WAL check skipped (shadow off)".to_string(),
        };

        let restart_msg = if restarted {
            format!(
                "mirror restarted from disk at block {restart_block} and stayed in lockstep to {replayed}"
            )
        } else {
            "no mid-chain restart (run too short)".to_string()
        };

        let read_source = if arena_reads {
            "the ARENA"
        } else {
            "chainbase"
        };
        eprintln!(
            "replayed real testnet blocks up to {replayed} serving contract reads from {read_source}; C++ chainbase and the Rust arena matched the cross-impl full-state root at every block; arena served {checked} point reads and {tables_scanned} table scans identical to chainbase; {read_ok} inline reads + {pos_ok} iterator positions + {nc_ok} account/permission reads cross-checked live, 0 divergences; {persist_msg}; {wal_msg}; {restart_msg}"
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
                    // The retained pending-chain model keeps the just-built block at
                    // the tip, so chainbase's head shows its accounts whether or not
                    // it is accepted; a non-accepted block is unwound at the next
                    // build (which reconciles to the last accepted preferred). So the
                    // expected head is the committed set plus this block's accounts.
                    let head: HashSet<u64> =
                        expected.iter().copied().chain(names.iter().copied()).collect();
                    if accept {
                        controller.accept_block(&block.id()?, &mut mempool)?;
                        controller.set_preferred_id(block.id()?);
                        expected.extend(names.iter().copied());
                    }
                    // After each block, arena and chainbase must agree, and match
                    // the head (committed + the block now at the tip).
                    let db = controller.database();
                    for &u in &used {
                        let want = head.contains(&u);
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

    // A privileged contract that reads the action data as a packed
    // vector<producer_key>, calls set_proposed_producers, and returns the i64
    // result (the new schedule version, or -1) via set_action_return_value.
    const PROPOSE_PRODUCERS_WAT: &str = r#"
        (module
          (import "env" "action_data_size" (func $ads (result i32)))
          (import "env" "read_action_data" (func $read (param i32 i32) (result i32)))
          (import "env" "set_proposed_producers" (func $spp (param i32 i32) (result i64)))
          (import "env" "set_action_return_value" (func $sarv (param i32 i32)))
          (memory 1)
          (export "memory" (memory 0))
          (func (export "apply") (param i64 i64 i64)
            (local $len i32)
            (local $ret i64)
            (local.set $len (call $ads))
            (drop (call $read (i32.const 0) (local.get $len)))
            (local.set $ret (call $spp (i32.const 0) (local.get $len)))
            (i64.store (i32.const 1024) (local.get $ret))
            (call $sarv (i32.const 1024) (i32.const 8))))
    "#;

    // A contract that copies the active producer set into the return value.
    const READ_PRODUCERS_WAT: &str = r#"
        (module
          (import "env" "get_active_producers" (func $gap (param i32 i32) (result i32)))
          (import "env" "set_action_return_value" (func $sarv (param i32 i32)))
          (memory 1)
          (export "memory" (memory 0))
          (func (export "apply") (param i64 i64 i64)
            (local $n i32)
            (local.set $n (call $gap (i32.const 0) (i32.const 256)))
            (call $sarv (i32.const 0) (local.get $n))))
    "#;

    // Build a signed transaction carrying a single action to `account`, with the
    // account's own active permission (self-authorized contract call).
    fn push_action(
        key: &PrivateKey,
        account: Name,
        action: Name,
        data: Vec<u8>,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                account,
                action,
                data,
                vec![PermissionLevel::new(account.as_u64(), ACTIVE_NAME.as_u64())],
            )],
        )
        .sign(key, &chain_id)?;
        PackedTransaction::from_signed_transaction(trx)
    }

    // Pull the return value set by the first action that produced one.
    fn action_return_value(result: &TransactionResult) -> Vec<u8> {
        result
            .trace
            .action_traces
            .iter()
            .find(|t| !t.return_value.is_empty())
            .map(|t| t.return_value.clone())
            .unwrap_or_default()
    }

    fn decode_producer_names(bytes: &[u8]) -> Vec<Name> {
        assert_eq!(
            bytes.len() % 8,
            0,
            "producer name array must be 8-byte aligned"
        );
        bytes
            .chunks_exact(8)
            .map(|c| Name::new(u64::from_le_bytes(c.try_into().unwrap())))
            .collect()
    }

    // set_proposed_producers reports the new schedule version, and -1 when the
    // proposal matches the active set. Driven through a real privileged contract
    // and the wasm host boundary; push_transaction reverts, so only the return
    // value is under test here.
    #[tokio::test]
    async fn set_proposed_producers_reports_version_and_noop() -> Result<(), ChainError> {
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
        let mut mempool = Mempool::new();

        let admin = Name::from_str("prodadmin")?;
        let producera = Name::from_str("producera")?;
        mempool.add_transaction(create_account(&private_key, admin, chain_id)?);
        mempool.add_transaction(create_account(&private_key, producera, chain_id)?);
        mempool.add_transaction(set_code(
            &private_key,
            admin,
            crate::wat2wasm(PROPOSE_PRODUCERS_WAT).expect("valid WAT"),
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        // set_proposed_producers is privileged; make the contract account so.
        controller.database().set_privileged(admin.as_u64(), true)?;

        let genesis_key = private_key.get_public_key();
        let ts: BlockTimestamp = TimePoint::now().into();

        // Proposing exactly the active set (genesis: pulse alone) is a no-op → -1.
        let same = vec![ProducerKey {
            producer_name: PULSE_NAME,
            block_signing_key: genesis_key.clone(),
        }];
        let r = controller.push_transaction(
            &push_action(
                &private_key,
                admin,
                Name::from_str("run")?,
                same.pack().unwrap(),
                chain_id,
            )?,
            &ts,
            &BlockStatus::Verifying,
        )?;
        assert_eq!(
            i64::from_le_bytes(action_return_value(&r).try_into().unwrap()),
            -1,
            "proposing the active set must return -1"
        );

        // A genuinely new set returns the next version (active is version 0 → 1).
        let changed = vec![
            ProducerKey {
                producer_name: PULSE_NAME,
                block_signing_key: genesis_key.clone(),
            },
            ProducerKey {
                producer_name: producera,
                block_signing_key: genesis_key.clone(),
            },
        ];
        let r = controller.push_transaction(
            &push_action(
                &private_key,
                admin,
                Name::from_str("run")?,
                changed.pack().unwrap(),
                chain_id,
            )?,
            &ts,
            &BlockStatus::Verifying,
        )?;
        assert_eq!(
            i64::from_le_bytes(action_return_value(&r).try_into().unwrap()),
            1,
            "proposing a changed set must return the next version"
        );

        Ok(())
    }

    // get_active_producers copies the active producer names (raw 8-byte name
    // array) into the guest buffer, and tracks the active schedule.
    #[tokio::test]
    async fn get_active_producers_reflects_active_schedule() -> Result<(), ChainError> {
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
        let mut mempool = Mempool::new();

        let glenn = Name::from_str("glenn")?;
        mempool.add_transaction(create_account(&private_key, glenn, chain_id)?);
        mempool.add_transaction(set_code(
            &private_key,
            glenn,
            crate::wat2wasm(READ_PRODUCERS_WAT).expect("valid WAT"),
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let ts: BlockTimestamp = TimePoint::now().into();
        let read = |c: &mut Controller| -> Result<Vec<Name>, ChainError> {
            let r = c.push_transaction(
                &push_action(
                    &private_key,
                    glenn,
                    Name::from_str("run")?,
                    vec![],
                    chain_id,
                )?,
                &ts,
                &BlockStatus::Verifying,
            )?;
            Ok(decode_producer_names(&action_return_value(&r)))
        };

        // Genesis: the sole producer is pulse.
        assert_eq!(read(&mut controller)?, vec![PULSE_NAME]);

        // After a schedule change, the read tracks the new active set.
        let producera = Name::from_str("producera")?;
        controller.activate_producer_schedule(vec![
            ProducerKey {
                producer_name: PULSE_NAME,
                block_signing_key: private_key.get_public_key(),
            },
            ProducerKey {
                producer_name: producera,
                block_signing_key: private_key.get_public_key(),
            },
        ])?;
        assert_eq!(read(&mut controller)?, vec![PULSE_NAME, producera]);

        Ok(())
    }

    // Bit-for-bit block-id parity across serialization and re-execution. A
    // producer builds a real chain — onblock runs at the head of every block,
    // plus an account-creating transaction — and each block is round-tripped
    // through the wire format. A fresh node (new database from the same genesis)
    // then replays every block through the production verify path, which enforces
    // the action and transaction merkle roots. Every replayed block id must equal
    // the producer's, and the reconstructed state must agree. This is the
    // property that lets any node re-execute the chain and arrive at identical
    // block ids, with no escape hatch.
    #[tokio::test]
    async fn block_ids_replay_bit_for_bit_from_serialized_bytes() -> Result<(), ChainError> {
        let (mut producer, private_key, chain_id, _p_temp) = init_test_controller()?;
        let mut p_mempool = Mempool::new();

        let names = ["aaa", "bbb", "ccc", "ddd", "eee"];
        let mut wire_blocks: Vec<Vec<u8>> = Vec::new();
        let mut expected_ids: Vec<Id> = Vec::new();

        for name in names {
            p_mempool.add_transaction(create_account(
                &private_key,
                Name::from_str(name)?,
                chain_id,
            )?);
            let block = producer.build_block(&mut p_mempool).await?;
            producer.accept_block(&block.id()?, &mut p_mempool)?;
            producer.set_preferred_id(block.id()?);

            expected_ids.push(block.id()?);
            wire_blocks.push(block.pack()?);
        }

        // Fresh node, new database, same genesis and chain id.
        let (mut validator, _pk, _cid, _v_temp) = init_test_controller()?;
        let mut v_mempool = Mempool::new();

        for (i, bytes) in wire_blocks.iter().enumerate() {
            let block = SignedBlock::read(bytes.as_slice(), &mut 0)?;
            // Serialization must preserve the id (which commits to both roots).
            assert_eq!(
                block.id()?,
                expected_ids[i],
                "serialized block {i} did not round-trip to the same id"
            );
            // verify_block re-derives and enforces the merkle roots; a divergent
            // re-execution (onblock receipt, sequences, trx receipts) fails here.
            validator.verify_block(&block, &mut v_mempool).await?;
            validator.accept_block(&block.id()?, &mut v_mempool)?;
            validator.set_preferred_id(block.id()?);
        }

        assert_eq!(
            validator.last_accepted_block_id,
            *expected_ids.last().unwrap(),
            "validator tip does not match the producer tip"
        );
        // The chain re-executed into the same state: every account is present.
        let db = validator.database();
        for name in names {
            assert!(
                !db.find_account(Name::from_str(name)?.as_u64())?.is_null(),
                "account {name} missing after replay"
            );
        }

        Ok(())
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
        assert_eq!(
            controller.last_accepted_block().block_num(),
            base_block_num + 1
        );

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
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("aaa")?,
            chain_id,
        )?);
        let b2 = producer.build_block(&mut p_mempool).await?;
        producer.set_preferred_id(b2.id()?);
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("bbb")?,
            chain_id,
        )?);
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
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("aaa")?,
            chain_id,
        )?);
        let a = producer.build_block(&mut p_mempool).await?;

        producer.set_preferred_id(a.id()?);
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("bbb")?,
            chain_id,
        )?);
        let b = producer.build_block(&mut p_mempool).await?;

        // Re-prefer A so the next build reconciles back to A (unwinding B) and
        // builds C as B's sibling.
        producer.set_preferred_id(a.id()?);
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("ccc")?,
            chain_id,
        )?);
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
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("aaa")?,
            chain_id,
        )?);
        let a = producer.build_block(&mut p_mempool).await?;
        producer.set_preferred_id(a.id()?);
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("bbb")?,
            chain_id,
        )?);
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

    // Same action, same start state, byte-identical result. `pg` is a test_api
    // routine that stores, iterates and reads a table with its own asserts, so a
    // divergence in the db host fns traps outright; we also compare receipts. The
    // two runs use separate databases but share the thread-local warm-store pool
    // and module cache, so this also checks a stale pooled store doesn't leak into
    // the next run.
    #[tokio::test]
    async fn contract_execution_is_reproducible() -> Result<(), ChainError> {
        async fn run_pg() -> Result<VecDeque<Digest>, ChainError> {
            let (mut controller, private_key, _cid, _temp) = init_test_controller()?;
            let ts = controller.last_accepted_block().timestamp().clone();
            let chain_id = controller.chain_id().clone();
            let st = BlockStatus::Building;
            controller.execute_transaction(
                &create_account(&private_key, Name::from_str("testapi")?, chain_id)?,
                &ts,
                &st,
            )?;
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap();
            let contract =
                fs::read(root.join(Path::new("reference_contracts/test_api_db.wasm"))).unwrap();
            controller.execute_transaction(
                &set_code(&private_key, Name::from_str("testapi")?, contract, chain_id)?,
                &ts,
                &st,
            )?;
            let res = controller.execute_transaction(
                &call_contract(
                    &private_key,
                    Name::from_str("testapi")?,
                    Name::from_str("pg")?,
                    &Vec::<u8>::new(),
                    chain_id,
                )?,
                &ts,
                &st,
            )?;
            Ok(res.action_receipt_digests)
        }

        let first = run_pg().await?;
        let second = run_pg().await?;
        assert_eq!(
            first, second,
            "identical execution must produce identical action receipts"
        );

        // first == second only proves same-machine reproducibility. CI runs this
        // on amd64 and arm64 (test.yml), and both check the constant below, so
        // matching it on each arch is the cross-arch gate for a full contract run.
        // A deliberate change to pg or the receipt moves it — recompute and commit.
        const PG_RECEIPT_GOLDEN: &str =
            "74087ef5d3c7a33f952046415b2cefa57a84ddafc406b9f5f3e06984bbf9fd27";
        let got: String = first
            .iter()
            .flat_map(|d| d.as_bytes().iter().map(|b| format!("{b:02x}")))
            .collect();
        assert_eq!(
            got, PG_RECEIPT_GOLDEN,
            "pg action-receipt digest drifted from the committed golden"
        );

        Ok(())
    }

    // The reject_nan_* tests pin the classifier; this pins the wiring — that
    // every idx_double / idx_long_double intrinsic taking a key from a contract
    // actually calls it. Each case is a tiny contract whose apply writes a NaN and
    // calls one intrinsic; the guard runs before any table work, so it traps on an
    // empty table and the transaction fails with the secondary-key message. Drop
    // the guard from one site and that case stops trapping.
    #[tokio::test]
    async fn nan_secondary_key_rejected_through_host_boundary() -> Result<(), ChainError> {
        // Minimal contract: import one host fn, export memory + apply, write a NaN
        // and call the fn. apply's three params are ignored — any action reaches it.
        fn contract(nan_writer: &str, import: &str, sig: &str, call: &str) -> Vec<u8> {
            let wat = format!(
                r#"
                (module
                  (import "env" "{import}" (func $f {sig}))
                  (memory (export "memory") 1)
                  (func (export "apply") (param i64 i64 i64)
                    {nan_writer}
                    {call}))
                "#
            );
            wat::parse_str(wat).unwrap()
        }

        // f64: one word. binary128: lo=0, hi = exponent-all-ones + mantissa MSB,
        // little-endian (lo at 0, hi at 8 — matches read_float128).
        let nan_f64 = "(i64.store (i32.const 0) (i64.const 0x7ff8000000000000))";
        let nan_f128 = "(i64.store (i32.const 0) (i64.const 0))\n\
                        (i64.store (i32.const 8) (i64.const 0x7fff800000000000))";

        // (label, import, signature, call). The secondary key is always at ptr 0
        // (where the NaN was written); other pointers/ids/iterators are dummies
        // the guard never reaches. `update` returns nothing; the rest return i32.
        let store_sig = "(param i64 i64 i64 i64 i32) (result i32)";
        let store_call = "(drop (call $f (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i32.const 0)))";
        let update_sig = "(param i32 i64 i32)";
        let update_call = "(call $f (i32.const 0) (i64.const 0) (i32.const 0))";
        let bound_sig = "(param i64 i64 i64 i32 i32) (result i32)";
        let bound_call = "(drop (call $f (i64.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 16)))";

        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "db_idx_double_store",
                contract(nan_f64, "db_idx_double_store", store_sig, store_call),
            ),
            (
                "db_idx_double_update",
                contract(nan_f64, "db_idx_double_update", update_sig, update_call),
            ),
            (
                "db_idx_double_find_secondary",
                contract(
                    nan_f64,
                    "db_idx_double_find_secondary",
                    bound_sig,
                    bound_call,
                ),
            ),
            (
                "db_idx_double_lowerbound",
                contract(nan_f64, "db_idx_double_lowerbound", bound_sig, bound_call),
            ),
            (
                "db_idx_double_upperbound",
                contract(nan_f64, "db_idx_double_upperbound", bound_sig, bound_call),
            ),
            (
                "db_idx_long_double_store",
                contract(nan_f128, "db_idx_long_double_store", store_sig, store_call),
            ),
            (
                "db_idx_long_double_update",
                contract(
                    nan_f128,
                    "db_idx_long_double_update",
                    update_sig,
                    update_call,
                ),
            ),
            (
                "db_idx_long_double_find_secondary",
                contract(
                    nan_f128,
                    "db_idx_long_double_find_secondary",
                    bound_sig,
                    bound_call,
                ),
            ),
            (
                "db_idx_long_double_lowerbound",
                contract(
                    nan_f128,
                    "db_idx_long_double_lowerbound",
                    bound_sig,
                    bound_call,
                ),
            ),
            (
                "db_idx_long_double_upperbound",
                contract(
                    nan_f128,
                    "db_idx_long_double_upperbound",
                    bound_sig,
                    bound_call,
                ),
            ),
        ];

        for (label, wasm) in cases {
            let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
            let ts = controller.last_accepted_block().timestamp().clone();
            let chain_id = controller.chain_id().clone();
            let st = BlockStatus::Building;
            controller.execute_transaction(
                &create_account(&private_key, Name::from_str("testapi")?, chain_id)?,
                &ts,
                &st,
            )?;
            controller.execute_transaction(
                &set_code(&private_key, Name::from_str("testapi")?, wasm, chain_id)?,
                &ts,
                &st,
            )?;
            let res = controller.execute_transaction(
                &call_contract(
                    &private_key,
                    Name::from_str("testapi")?,
                    Name::from_str("run")?,
                    &Vec::<u8>::new(),
                    chain_id,
                )?,
                &ts,
                &st,
            );
            let err = match res {
                Ok(_) => panic!("{label} must reject a NaN secondary key"),
                Err(e) => e,
            };
            assert!(
                err.to_string()
                    .contains("not an allowed value for a secondary key"),
                "{label} failed for the wrong reason: {err}"
            );
        }

        Ok(())
    }

    /// Serve-path code oracle: with arena reads enabled, the VM fetches and
    /// compiles the contract image from the arena (`get_code_bytes_by_hash`),
    /// not from chainbase. Deploy a trivial contract and call it; the action
    /// only succeeds if the arena served a byte-identical image the VM can
    /// instantiate, and the system-object read cross-check must stay clean.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_contract_code_serves_from_arena() -> Result<(), ChainError> {
        let wasm = wat::parse_str(
            r#"(module (memory (export "memory") 1) (func (export "apply") (param i64 i64 i64)))"#,
        )
        .unwrap();

        let (mut controller, private_key, _cid, _temp) = init_test_controller()?;
        // Serve every system-object read from the arena for the rest of the test.
        controller.database().enable_arena_reads();
        let chain_id = controller.chain_id().clone();
        let ts = controller.last_accepted_block().timestamp().clone();
        let st = BlockStatus::Building;
        let testapi = Name::from_str("testapi")?;

        controller.execute_transaction(
            &create_account(&private_key, testapi, chain_id)?,
            &ts,
            &st,
        )?;
        controller.execute_transaction(
            &set_code(&private_key, testapi, wasm, chain_id)?,
            &ts,
            &st,
        )?;
        // Runs the contract: exec_one sees a non-empty code hash and asks the VM
        // to run it, so the image is fetched from the arena and compiled here.
        controller.execute_transaction(
            &call_contract(
                &private_key,
                testapi,
                Name::from_str("run")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &ts,
            &st,
        )?;

        let (_ok, nc_fail) = controller.database().arena_noncontract_crosscheck_counts();
        assert_eq!(
            nc_fail, 0,
            "arena served {nc_fail} system-object reads that diverged from chainbase"
        );
        Ok(())
    }

    /// Secondary-index iterator-handle oracle: a contract that drives the full
    /// idx64 surface (store, end, lowerbound/upperbound, find_secondary/primary,
    /// next/previous off both ends, remove) must see the arena mint the identical
    /// iterator handle chainbase does at every call, and land on the identical
    /// row. The testnet replay never touches secondary indices, so this WAT
    /// contract is the only thing that exercises the path — assert the arena
    /// positioning tally is non-empty (the path really ran) and clean (no
    /// divergence), with arena reads serving every secondary value.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_idx64_iterator_handles_mint_and_serve() -> Result<(), ChainError> {
        // scope=100, table=200; rows (primary, secondary): (10,100) (20,200)
        // (30,200) (40,300). The duplicate secondary 200 forces the (secondary,
        // primary) tie-break, and walking next/previous falls off both ends.
        let wasm = wat::parse_str(
            r#"(module
  (import "env" "db_idx64_store" (func $store (param i64 i64 i64 i64 i32) (result i32)))
  (import "env" "db_idx64_end" (func $end (param i64 i64 i64) (result i32)))
  (import "env" "db_idx64_lowerbound" (func $lb (param i64 i64 i64 i32 i32) (result i32)))
  (import "env" "db_idx64_upperbound" (func $ub (param i64 i64 i64 i32 i32) (result i32)))
  (import "env" "db_idx64_find_secondary" (func $fs (param i64 i64 i64 i32 i32) (result i32)))
  (import "env" "db_idx64_find_primary" (func $fp (param i64 i64 i64 i32 i64) (result i32)))
  (import "env" "db_idx64_next" (func $next (param i32 i32) (result i32)))
  (import "env" "db_idx64_previous" (func $prev (param i32 i32) (result i32)))
  (import "env" "db_idx64_remove" (func $rm (param i32)))
  (memory (export "memory") 1)
  (func (export "apply") (param $receiver i64) (param $code i64) (param $action i64)
    (local $scope i64) (local $table i64) (local $it i32) (local $e i32)
    (local.set $scope (i64.const 100))
    (local.set $table (i64.const 200))

    ;; store the four rows, payer = receiver
    (i64.store (i32.const 0) (i64.const 100))
    (drop (call $store (local.get $scope) (local.get $table) (local.get $receiver) (i64.const 10) (i32.const 0)))
    (i64.store (i32.const 0) (i64.const 200))
    (drop (call $store (local.get $scope) (local.get $table) (local.get $receiver) (i64.const 20) (i32.const 0)))
    (i64.store (i32.const 0) (i64.const 200))
    (drop (call $store (local.get $scope) (local.get $table) (local.get $receiver) (i64.const 30) (i32.const 0)))
    (i64.store (i32.const 0) (i64.const 300))
    (drop (call $store (local.get $scope) (local.get $table) (local.get $receiver) (i64.const 40) (i32.const 0)))

    ;; end iterator for the table
    (local.set $e (call $end (local.get $receiver) (local.get $scope) (local.get $table)))

    ;; lowerbound(0) lands on the first row, then next walks off the end
    (i64.store (i32.const 0) (i64.const 0))
    (local.set $it (call $lb (local.get $receiver) (local.get $scope) (local.get $table) (i32.const 0) (i32.const 8)))
    (local.set $it (call $next (local.get $it) (i32.const 8)))
    (local.set $it (call $next (local.get $it) (i32.const 8)))
    (local.set $it (call $next (local.get $it) (i32.const 8)))
    (local.set $it (call $next (local.get $it) (i32.const 8)))

    ;; point lookups
    (i64.store (i32.const 0) (i64.const 200))
    (drop (call $fs (local.get $receiver) (local.get $scope) (local.get $table) (i32.const 0) (i32.const 8)))
    (drop (call $fp (local.get $receiver) (local.get $scope) (local.get $table) (i32.const 0) (i64.const 30)))
    (i64.store (i32.const 0) (i64.const 200))
    (drop (call $ub (local.get $receiver) (local.get $scope) (local.get $table) (i32.const 0) (i32.const 8)))

    ;; previous from the end iterator lands on the last row, then walks off the front
    (local.set $it (call $prev (local.get $e) (i32.const 8)))
    (local.set $it (call $prev (local.get $it) (i32.const 8)))
    (local.set $it (call $prev (local.get $it) (i32.const 8)))
    (local.set $it (call $prev (local.get $it) (i32.const 8)))
    (local.set $it (call $prev (local.get $it) (i32.const 8)))

    ;; remove the first row through a fresh handle
    (i64.store (i32.const 0) (i64.const 0))
    (local.set $it (call $lb (local.get $receiver) (local.get $scope) (local.get $table) (i32.const 0) (i32.const 8)))
    (call $rm (local.get $it))
  )
)"#,
        )
        .unwrap();

        let (mut controller, private_key, _cid, _temp) = init_test_controller()?;
        controller.database().enable_arena_reads();
        let chain_id = controller.chain_id().clone();
        let ts = controller.last_accepted_block().timestamp().clone();
        let st = BlockStatus::Building;
        let testapi = Name::from_str("testapi")?;

        controller.execute_transaction(
            &create_account(&private_key, testapi, chain_id)?,
            &ts,
            &st,
        )?;
        controller.execute_transaction(
            &set_code(&private_key, testapi, wasm, chain_id)?,
            &ts,
            &st,
        )?;

        let (ok_before, fail_before) = controller.database().arena_pos_crosscheck_counts();
        controller.execute_transaction(
            &call_contract(
                &private_key,
                testapi,
                Name::from_str("run")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &ts,
            &st,
        )?;
        let (ok_after, fail_after) = controller.database().arena_pos_crosscheck_counts();

        assert_eq!(
            fail_after, fail_before,
            "arena secondary-index handles/positions diverged from chainbase during idx64 iteration"
        );
        assert!(
            ok_after - ok_before >= 20,
            "expected the idx64 walk to cross-check many handles, saw {}",
            ok_after - ok_before
        );
        Ok(())
    }

    /// Secondary-index iterator-handle oracle for the wider-key families: the
    /// idx64 walk covers the u64 machinery; this covers the two structural
    /// variants — a u128 secondary (idx128) and an IEEE-754 float secondary
    /// (idx_double, whose `last`/order use the software-float key). One contract
    /// drives both surfaces off both ends; the arena must mint chainbase's handle
    /// and land on chainbase's row at every step, served under arena reads.
    #[cfg(feature = "arena-shadow")]
    #[tokio::test]
    async fn oracle_secondary_wide_key_handles_mint_and_serve() -> Result<(), ChainError> {
        // idx128 table 300, idx_double table 301, scope 100. Rows (primary,
        // secondary): (10,100/1.0) (20,200/2.0) (30,200/2.0) (40,300/3.0). The
        // idx128 secondary is a u128 at [0..16] (hi word kept 0); the double
        // secondary is the f64 bit pattern at [24..32]. Primary out cells are
        // [16..24] and [32..40].
        let wasm = wat::parse_str(
            r#"(module
  (import "env" "db_idx128_store" (func $s128 (param i64 i64 i64 i64 i32) (result i32)))
  (import "env" "db_idx128_end" (func $e128 (param i64 i64 i64) (result i32)))
  (import "env" "db_idx128_lowerbound" (func $lb128 (param i64 i64 i64 i32 i32) (result i32)))
  (import "env" "db_idx128_upperbound" (func $ub128 (param i64 i64 i64 i32 i32) (result i32)))
  (import "env" "db_idx128_find_secondary" (func $fs128 (param i64 i64 i64 i32 i32) (result i32)))
  (import "env" "db_idx128_find_primary" (func $fp128 (param i64 i64 i64 i32 i64) (result i32)))
  (import "env" "db_idx128_next" (func $n128 (param i32 i32) (result i32)))
  (import "env" "db_idx128_previous" (func $p128 (param i32 i32) (result i32)))
  (import "env" "db_idx128_update" (func $u128 (param i32 i64 i32)))
  (import "env" "db_idx_double_store" (func $sd (param i64 i64 i64 i64 i32) (result i32)))
  (import "env" "db_idx_double_end" (func $ed (param i64 i64 i64) (result i32)))
  (import "env" "db_idx_double_lowerbound" (func $lbd (param i64 i64 i64 i32 i32) (result i32)))
  (import "env" "db_idx_double_upperbound" (func $ubd (param i64 i64 i64 i32 i32) (result i32)))
  (import "env" "db_idx_double_find_secondary" (func $fsd (param i64 i64 i64 i32 i32) (result i32)))
  (import "env" "db_idx_double_find_primary" (func $fpd (param i64 i64 i64 i32 i64) (result i32)))
  (import "env" "db_idx_double_next" (func $nd (param i32 i32) (result i32)))
  (import "env" "db_idx_double_previous" (func $pd (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "apply") (param $receiver i64) (param $code i64) (param $action i64)
    (local $scope i64) (local $it i32) (local $e i32)
    (local.set $scope (i64.const 100))

    ;; ---- idx128 (table 300), u128 secondary at [0..16], hi word stays 0 ----
    (i64.store (i32.const 8) (i64.const 0))
    (i64.store (i32.const 0) (i64.const 100))
    (drop (call $s128 (local.get $scope) (i64.const 300) (local.get $receiver) (i64.const 10) (i32.const 0)))
    (i64.store (i32.const 0) (i64.const 200))
    (drop (call $s128 (local.get $scope) (i64.const 300) (local.get $receiver) (i64.const 20) (i32.const 0)))
    (i64.store (i32.const 0) (i64.const 200))
    (drop (call $s128 (local.get $scope) (i64.const 300) (local.get $receiver) (i64.const 30) (i32.const 0)))
    (i64.store (i32.const 0) (i64.const 300))
    (drop (call $s128 (local.get $scope) (i64.const 300) (local.get $receiver) (i64.const 40) (i32.const 0)))

    (local.set $e (call $e128 (local.get $receiver) (local.get $scope) (i64.const 300)))
    (i64.store (i32.const 0) (i64.const 0))
    (local.set $it (call $lb128 (local.get $receiver) (local.get $scope) (i64.const 300) (i32.const 0) (i32.const 16)))
    (local.set $it (call $n128 (local.get $it) (i32.const 16)))
    (local.set $it (call $n128 (local.get $it) (i32.const 16)))
    (local.set $it (call $n128 (local.get $it) (i32.const 16)))
    (local.set $it (call $n128 (local.get $it) (i32.const 16)))
    (i64.store (i32.const 0) (i64.const 200))
    (drop (call $fs128 (local.get $receiver) (local.get $scope) (i64.const 300) (i32.const 0) (i32.const 16)))
    (drop (call $fp128 (local.get $receiver) (local.get $scope) (i64.const 300) (i32.const 0) (i64.const 30)))
    (i64.store (i32.const 0) (i64.const 200))
    (drop (call $ub128 (local.get $receiver) (local.get $scope) (i64.const 300) (i32.const 0) (i32.const 16)))
    (local.set $it (call $p128 (local.get $e) (i32.const 16)))
    (local.set $it (call $p128 (local.get $it) (i32.const 16)))
    (local.set $it (call $p128 (local.get $it) (i32.const 16)))
    (local.set $it (call $p128 (local.get $it) (i32.const 16)))
    (local.set $it (call $p128 (local.get $it) (i32.const 16)))

    ;; update: re-point primary 10 from secondary 100 to 500, then the served
    ;; finds must reflect the new key and lose the old (proves the update mirror
    ;; reaches the arena — a stale arena would diverge here under reads).
    (i64.store (i32.const 0) (i64.const 100))
    (local.set $it (call $fs128 (local.get $receiver) (local.get $scope) (i64.const 300) (i32.const 0) (i32.const 16)))
    (i64.store (i32.const 0) (i64.const 500))
    (call $u128 (local.get $it) (local.get $receiver) (i32.const 0))
    (i64.store (i32.const 0) (i64.const 500))
    (drop (call $fs128 (local.get $receiver) (local.get $scope) (i64.const 300) (i32.const 0) (i32.const 16)))
    (i64.store (i32.const 0) (i64.const 100))
    (drop (call $fs128 (local.get $receiver) (local.get $scope) (i64.const 300) (i32.const 0) (i32.const 16)))

    ;; ---- idx_double (table 301), f64 bits at [24..32] ----
    (i64.store (i32.const 24) (i64.reinterpret_f64 (f64.const 1)))
    (drop (call $sd (local.get $scope) (i64.const 301) (local.get $receiver) (i64.const 10) (i32.const 24)))
    (i64.store (i32.const 24) (i64.reinterpret_f64 (f64.const 2)))
    (drop (call $sd (local.get $scope) (i64.const 301) (local.get $receiver) (i64.const 20) (i32.const 24)))
    (i64.store (i32.const 24) (i64.reinterpret_f64 (f64.const 2)))
    (drop (call $sd (local.get $scope) (i64.const 301) (local.get $receiver) (i64.const 30) (i32.const 24)))
    (i64.store (i32.const 24) (i64.reinterpret_f64 (f64.const 3)))
    (drop (call $sd (local.get $scope) (i64.const 301) (local.get $receiver) (i64.const 40) (i32.const 24)))

    (local.set $e (call $ed (local.get $receiver) (local.get $scope) (i64.const 301)))
    (i64.store (i32.const 24) (i64.reinterpret_f64 (f64.const -1)))
    (local.set $it (call $lbd (local.get $receiver) (local.get $scope) (i64.const 301) (i32.const 24) (i32.const 32)))
    (local.set $it (call $nd (local.get $it) (i32.const 32)))
    (local.set $it (call $nd (local.get $it) (i32.const 32)))
    (local.set $it (call $nd (local.get $it) (i32.const 32)))
    (local.set $it (call $nd (local.get $it) (i32.const 32)))
    (i64.store (i32.const 24) (i64.reinterpret_f64 (f64.const 2)))
    (drop (call $fsd (local.get $receiver) (local.get $scope) (i64.const 301) (i32.const 24) (i32.const 32)))
    (drop (call $fpd (local.get $receiver) (local.get $scope) (i64.const 301) (i32.const 24) (i64.const 30)))
    (i64.store (i32.const 24) (i64.reinterpret_f64 (f64.const 2)))
    (drop (call $ubd (local.get $receiver) (local.get $scope) (i64.const 301) (i32.const 24) (i32.const 32)))
    (local.set $it (call $pd (local.get $e) (i32.const 32)))
    (local.set $it (call $pd (local.get $it) (i32.const 32)))
    (local.set $it (call $pd (local.get $it) (i32.const 32)))
    (local.set $it (call $pd (local.get $it) (i32.const 32)))
    (local.set $it (call $pd (local.get $it) (i32.const 32)))
  )
)"#,
        )
        .unwrap();

        let (mut controller, private_key, _cid, _temp) = init_test_controller()?;
        controller.database().enable_arena_reads();
        let chain_id = controller.chain_id().clone();
        let ts = controller.last_accepted_block().timestamp().clone();
        let st = BlockStatus::Building;
        let testapi = Name::from_str("testapi")?;

        controller.execute_transaction(
            &create_account(&private_key, testapi, chain_id)?,
            &ts,
            &st,
        )?;
        controller.execute_transaction(
            &set_code(&private_key, testapi, wasm, chain_id)?,
            &ts,
            &st,
        )?;

        let (ok_before, fail_before) = controller.database().arena_pos_crosscheck_counts();
        controller.execute_transaction(
            &call_contract(
                &private_key,
                testapi,
                Name::from_str("run")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &ts,
            &st,
        )?;
        let (ok_after, fail_after) = controller.database().arena_pos_crosscheck_counts();

        assert_eq!(
            fail_after, fail_before,
            "arena idx128/idx_double handles or positions diverged from chainbase"
        );
        assert!(
            ok_after - ok_before >= 40,
            "expected the idx128 + idx_double walks to cross-check many handles, saw {}",
            ok_after - ok_before
        );
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
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("testapi")?,
            chain_id,
        )?);
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
    async fn rejects_block_with_wrong_signature() -> Result<(), ChainError> {
        // Build a valid block, then replace its signature with one made over a
        // different digest. It is still a well-formed signature, but recovers to
        // a key that isn't the producer's scheduled key, so verification must
        // reject it. This proves the signature check is enforced, not a no-op.
        let (mut producer, private_key, chain_id, _p_temp) = init_test_controller()?;
        let mut p_mempool = Mempool::new();
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("testapi")?,
            chain_id,
        )?);
        let mut block = producer.build_block(&mut p_mempool).await?;

        let wrong_digest: crate::utils::Digest = [0u8; 32].into();
        block.signed_block_header.signature = private_key.sign(&wrong_digest)?;

        let (mut validator, _pk, _cid, _v_temp) = init_test_controller()?;
        let mut v_mempool = Mempool::new();
        assert!(
            validator
                .verify_block(&block, &mut v_mempool)
                .await
                .is_err(),
            "block with a signature over the wrong digest must be rejected"
        );

        Ok(())
    }

    #[tokio::test]
    async fn active_schedule_gates_block_verification() -> Result<(), ChainError> {
        // A block signed by the genesis key must be rejected once the schedule is
        // rotated to a different key, and accepted again when re-signed with the
        // new key — proving verification follows the active schedule, not a fixed
        // genesis key.
        let (mut producer, private_key, chain_id, _p_temp) = init_test_controller()?;
        let mut p_mempool = Mempool::new();
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("testapi")?,
            chain_id,
        )?);
        let mut block = producer.build_block(&mut p_mempool).await?;

        let (mut validator, _pk, _cid, _v_temp) = init_test_controller()?;
        let new_key = PrivateKey::random();
        validator.activate_producer_schedule(vec![ProducerKey {
            producer_name: Name::from_str("pulse")?,
            block_signing_key: new_key.get_public_key(),
        }])?;
        assert_eq!(validator.active_schedule.version, 1);

        let mut v_mempool = Mempool::new();
        assert!(
            validator
                .verify_block(&block, &mut v_mempool)
                .await
                .is_err(),
            "genesis-key signature must be rejected under the rotated schedule"
        );

        let sig_digest: crate::utils::Digest =
            block.signed_block_header.header.sig_digest()?.0.into();
        block.signed_block_header.signature = new_key.sign(&sig_digest)?;
        validator.verify_block(&block, &mut v_mempool).await?;

        Ok(())
    }

    #[tokio::test]
    async fn state_sync_transfers_state_tip_and_schedule() -> Result<(), ChainError> {
        // End-to-end file-copy state sync, in process: a producer builds real
        // state and a rotated schedule, a fresh node adopts it from the summary,
        // and a restart of that node reconstructs the synced tip and schedule
        // from the re-based block log plus the persisted schedule — never the
        // stale genesis state it started from.
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let genesis_bytes = generate_genesis(&private_key);
        // A small arena keeps the snapshot copy cheap; the default is tens of GB.
        let config_bytes = json!({
            "producer_name": "pulse",
            "producer_key": private_key.to_string(),
            "db_size": 128u64 * 1024 * 1024,
        })
        .to_string()
        .into_bytes();
        let init = |dir: &str| -> Result<Controller, ChainError> {
            let mut c = Controller::new();
            c.initialize(&chain_id, &config_bytes, &genesis_bytes.to_vec(), dir)?;
            Ok(c)
        };

        let producer_temp = get_temp_dir();
        let mut producer = init(producer_temp.path().to_str().unwrap())?;
        let name = Name::from_str("glenn")?.as_u64();
        let mut p_mempool = Mempool::new();
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("glenn")?,
            chain_id,
        )?);
        let block = producer.build_block(&mut p_mempool).await?;
        producer.accept_block(&block.id()?, &mut p_mempool)?;

        // Rotate the schedule so it differs from the genesis seed — this is what
        // the persisted-schedule path has to recover across a restart.
        let rotated_key = PrivateKey::random();
        producer.activate_producer_schedule(vec![ProducerKey {
            producer_name: Name::from_str("pulse")?,
            block_signing_key: rotated_key.get_public_key(),
        }])?;
        let producer_height = producer.last_accepted_block().block_num();
        let producer_schedule = producer.active_schedule.clone();
        assert_eq!(producer_schedule.version, 1);
        assert!(!producer.database().find_account_metadata(name)?.is_null());

        let summary = producer.produce_state_summary()?;
        assert_eq!(summary.height, producer_height as u64);

        // Syncing node: fresh genesis, so it has neither glenn nor the schedule.
        let syncer_temp = get_temp_dir();
        let syncer_path = syncer_temp.path().to_str().unwrap().to_string();
        let mut syncer = init(&syncer_path)?;
        assert!(syncer.database().find_account_metadata(name)?.is_null());

        // Parse agrees with produce on the commitment.
        let (parsed_id, parsed_height) = Controller::parse_state_summary(&summary.bytes)?;
        assert_eq!(parsed_id, summary.id);
        assert_eq!(parsed_height, producer_height as u64);

        // Download the snapshot chunk by chunk from the producer, exactly as the
        // P2P driver does — here the fetch is a direct call, not an AppRequest.
        let target = Controller::sync_target_from_summary(&summary.bytes)?;
        let (hash, height) = (target.hash, target.height);
        let envelope = crate::chain::state_sync::download_snapshot(&target, |off, len| {
            let chunk = producer.serve_snapshot_chunk(height, &hash, off, len);
            async move { chunk }
        })
        .await?;

        // Apply transfers state, tip, and schedule.
        syncer.apply_state_snapshot(target.block.clone(), target.schedule.clone(), &envelope)?;
        assert!(
            !syncer.database().find_account_metadata(name)?.is_null(),
            "state not transferred"
        );
        assert_eq!(syncer.last_accepted_block().block_num(), producer_height);
        assert_eq!(syncer.last_accepted_block().id()?, summary.id);
        assert_eq!(syncer.database().revision(), producer_height as i64);
        assert_eq!(syncer.active_schedule, producer_schedule);

        // Restart the synced node from its data directory.
        syncer.shutdown()?;
        let restarted = init(&syncer_path)?;
        assert!(
            !restarted.database().find_account_metadata(name)?.is_null(),
            "synced state lost across restart"
        );
        assert_eq!(restarted.last_accepted_block().block_num(), producer_height);
        assert_eq!(restarted.last_accepted_block().id()?, summary.id);
        assert_eq!(
            restarted.active_schedule, producer_schedule,
            "synced schedule lost across restart"
        );

        Ok(())
    }

    /// End-to-end state sync over REAL testnet blocks. Replays blocks fetched by
    /// scripts/fetch-blocks.sh into a producer, then has a fresh node sync the
    /// resulting state by downloading the snapshot chunk by chunk (the exact
    /// driver the P2P AppRequest path uses) and applying it — then restarts the
    /// synced node to prove the re-based log persists. Ignored by default; run:
    ///   PULSEVM_RPC_BLOCKS_DIR=/tmp/rpcblocks cargo test -p pulsevm_core \
    ///     state_sync_real_testnet_blocks -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn state_sync_real_testnet_blocks() -> Result<(), ChainError> {
        let Ok(dir) = std::env::var("PULSEVM_RPC_BLOCKS_DIR") else {
            eprintln!("set PULSEVM_RPC_BLOCKS_DIR (see scripts/fetch-blocks.sh) to run");
            return Ok(());
        };
        let chain_id =
            Id::from_str("531a7002b4a4b67987f8706c01b965c76ffc3ad301608ac61a1f738cba6c3a9a")
                .unwrap();
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();

        // Collect the block fixtures in order.
        let mut files: Vec<_> = fs::read_dir(&dir)
            .expect("blocks dir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
            .collect();
        files.sort();

        // Patch genesis so our block 1 matches the testnet's: the real initial
        // timestamp (block 1's) and the real system-account key (recovered from
        // the first signed transaction). Same procedure as replay_testnet_blocks.
        let b1: serde_json::Value =
            serde_json::from_slice(&fs::read(files.first().expect("no block fixtures")).unwrap())
                .unwrap();
        assert_eq!(b1["result"]["block_num"].as_u64(), Some(1));
        let ts = b1["result"]["timestamp"]
            .as_str()
            .unwrap()
            .trim_end_matches(".000");
        let mut g: serde_json::Value =
            serde_json::from_slice(&fs::read(repo_root.join("genesis.json")).unwrap()).unwrap();
        g["initial_timestamp"] = json!(ts);
        for f in &files {
            let v: serde_json::Value = serde_json::from_slice(&fs::read(f).unwrap()).unwrap();
            let r = &v["result"];
            if r["transactions"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false)
            {
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
        // Some early system transactions are billed far above the default 150ms
        // per-transaction cap (privileged eosio actions bypass CPU limits on the
        // real chain; our VM still enforces them), so raise the limits for replay
        // — we only need these blocks to execute and build state.
        if let Some(cfg) = g.get_mut("initial_configuration") {
            cfg["max_transaction_cpu_usage"] = json!(4_000_000_000u64);
            cfg["max_block_cpu_usage"] = json!(4_000_000_000u64);
        }
        let genesis_bytes = serde_json::to_vec(&g).unwrap();
        // A small arena keeps the snapshot copy cheap; the default is tens of GB.
        let config_bytes = json!({
            "producer_name": "pulse",
            "producer_key": "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez",
            "db_size": 512u64 * 1024 * 1024,
        })
        .to_string()
        .into_bytes();
        let init = |dir: &str| -> Result<Controller, ChainError> {
            let mut c = Controller::new();
            c.initialize(&chain_id, &config_bytes, &genesis_bytes, dir)?;
            Ok(c)
        };

        // ---- Producer: replay the real blocks to build authentic state. ----
        let producer_temp = get_temp_dir();
        let mut producer = init(producer_temp.path().to_str().unwrap())?;
        assert_eq!(
            producer.last_accepted_block().id()?.to_string(),
            b1["result"]["id"].as_str().unwrap(),
            "our genesis block id != testnet block 1 — genesis mismatch"
        );

        // getBlock omits the producer signature, so re-sign each block with a key
        // we hold and seed the schedule with it (as replay_testnet_blocks does).
        let block_signer =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        producer.active_schedule = ProducerSchedule {
            version: 0,
            producers: vec![ProducerKey {
                producer_name: Name::from_str("pulse")?,
                block_signing_key: block_signer.get_public_key(),
            }],
        };

        let start = producer.last_accepted_block().block_num() + 1;
        let mut mempool = Mempool::new();
        let mut replayed = 0u32;
        for f in &files {
            // Skip any fixture that didn't fetch cleanly (a transient RPC error
            // can leave a non-JSON file).
            let Ok(bytes) = fs::read(f) else { continue };
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                continue;
            };
            if v.get("result").and_then(|r| r.get("block_num")).is_none() {
                continue;
            }
            let r = &v["result"];
            let n = r["block_num"].as_u64().unwrap_or(0) as u32;
            if n < start {
                continue;
            }
            let mut block = reconstruct_block(r)?;
            let sig_digest: crate::utils::Digest =
                block.signed_block_header.header.sig_digest()?.0.into();
            block.signed_block_header.signature = block_signer.sign(&sig_digest)?;
            // This foreign fixture predates onblock, so its canonical merkle roots
            // won't match a chain that runs onblock every block — replay stops at
            // the first block whose roots we (correctly) re-derive differently.
            // The self-contained state-sync coverage lives in
            // state_sync_transfers_state_tip_and_schedule, which builds its state
            // from our own onblock-running blocks.
            if let Err(e) = producer.verify_block(&block, &mut mempool).await {
                eprintln!("replay stalled at block {n}: {e:?}");
                break;
            }
            producer.accept_block(&block.id()?, &mut mempool)?;
            producer.set_preferred_id(block.id()?);
            replayed += 1;
        }
        let height = producer.last_accepted_block().block_num();
        assert!(
            replayed >= 50,
            "replayed only {replayed} blocks — too few for a meaningful sync test"
        );
        eprintln!("replayed {replayed} real blocks, tip at height {height}");
        // The system account exists in the real chain's state.
        let pulse = Name::from_str("pulse")?.as_u64();
        assert!(!producer.database().find_account(pulse)?.is_null());

        // ---- Sync: a fresh node downloads and applies the snapshot. ----
        let summary = producer.produce_state_summary()?;
        let producer_tip_id = producer.last_accepted_block().id()?;

        let syncer_temp = get_temp_dir();
        let syncer_path = syncer_temp.path().to_str().unwrap().to_string();
        let mut syncer = init(&syncer_path)?;
        assert!(
            syncer.database().find_account(pulse)?.is_null()
                || syncer.last_accepted_block().block_num() == 1,
            "syncer should start from genesis, not the producer's height"
        );

        let target = Controller::sync_target_from_summary(&summary.bytes)?;
        assert_eq!(target.height, height as u64);
        let (hash, th) = (target.hash, target.height);
        let envelope = crate::chain::state_sync::download_snapshot(&target, |off, len| {
            let chunk = producer.serve_snapshot_chunk(th, &hash, off, len);
            async move { chunk }
        })
        .await?;
        eprintln!(
            "downloaded {} snapshot bytes in {}-byte chunks",
            envelope.len(),
            crate::chain::state_sync::SNAPSHOT_CHUNK_LEN
        );

        syncer.apply_state_snapshot(target.block.clone(), target.schedule.clone(), &envelope)?;

        // The synced node now holds the producer's tip, revision and state.
        assert_eq!(syncer.last_accepted_block().block_num(), height);
        assert_eq!(syncer.last_accepted_block().id()?, producer_tip_id);
        assert_eq!(syncer.database().revision(), height as i64);
        assert!(
            !syncer.database().find_account(pulse)?.is_null(),
            "system account missing after sync"
        );
        // Faithfulness: re-snapshotting the synced arena reproduces the exact
        // payload hash the producer advertised — the transfer was lossless.
        let re = syncer.produce_state_summary()?;
        let re_target = Controller::sync_target_from_summary(&re.bytes)?;
        assert_eq!(
            re_target.hash, target.hash,
            "re-snapshot of synced state does not match the producer's snapshot"
        );

        // A restart reconstructs the synced tip from the re-based block log.
        syncer.shutdown()?;
        let restarted = init(&syncer_path)?;
        assert_eq!(restarted.last_accepted_block().block_num(), height);
        assert_eq!(restarted.last_accepted_block().id()?, producer_tip_id);
        assert!(!restarted.database().find_account(pulse)?.is_null());
        eprintln!("synced node restarted cleanly at height {height}");

        Ok(())
    }

    #[tokio::test]
    async fn producer_schedule_reconstructed_from_block_log() -> Result<(), ChainError> {
        // A schedule change rides in the signed block header, so it is recovered
        // from the block log on restart — there is no out-of-band file to lose,
        // and a chain that changed producers never silently reverts to genesis.
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let genesis_bytes = generate_genesis(&private_key);
        let config_bytes = json!({
            "producer_name": "pulse",
            "producer_key": private_key.to_string(),
        })
        .to_string()
        .into_bytes();
        let temp = get_temp_dir();
        let path = temp.path().to_str().unwrap().to_string();
        let new_key = PrivateKey::random();
        let new_schedule = ProducerSchedule {
            version: 1,
            producers: vec![ProducerKey {
                producer_name: Name::from_str("pulse")?,
                block_signing_key: new_key.get_public_key(),
            }],
        };

        {
            let mut controller = Controller::new();
            controller.initialize(&chain_id, &config_bytes, &genesis_bytes.to_vec(), &path)?;

            // Build a real block on genesis, carry the schedule change in its
            // (re-signed) header, and append it to the log. This stands in for an
            // accepted schedule-changing block without needing a privileged
            // contract to run set_proposed_producers.
            let mut mempool = Mempool::new();
            mempool.add_transaction(create_account(
                &private_key,
                Name::from_str("testapi")?,
                chain_id,
            )?);
            let mut block = controller.build_block(&mut mempool).await?;
            block.signed_block_header.header.new_producers = Some(
                new_schedule
                    .pack()
                    .map_err(|e| ChainError::SerializationError(e.to_string()))?,
            );
            block.signed_block_header.header.schedule_version = new_schedule.version;
            let sig_digest: crate::utils::Digest =
                block.signed_block_header.header.sig_digest()?.0.into();
            block.signed_block_header.signature = private_key.sign(&sig_digest)?;

            let packed = block
                .pack()
                .map_err(|e| ChainError::SerializationError(e.to_string()))?;
            controller
                .block_log
                .as_ref()
                .unwrap()
                .append(block.id()?, &packed)
                .map_err(|e| ChainError::InternalError(e.to_string()))?;
            controller.shutdown()?;
        }

        let mut reopened = Controller::new();
        reopened.initialize(&chain_id, &config_bytes, &genesis_bytes.to_vec(), &path)?;
        assert_eq!(
            reopened.active_schedule, new_schedule,
            "schedule must be reconstructed from the block log header, not a side file"
        );

        Ok(())
    }

    #[tokio::test]
    async fn schedule_change_updates_producers_authority() -> Result<(), ChainError> {
        // When a new producer schedule takes effect, the pulse.prods permissions
        // must be rewritten to require >2/3 (active), >1/2 (prod.major) and >1/3
        // (prod.minor) of the scheduled producers, each counted through their
        // active permission — so producer-gated authority follows the schedule
        // instead of staying delegated to the genesis producer.
        let (mut controller, _private_key, _chain_id, _temp) = init_test_controller()?;

        let producers: Vec<ProducerKey> = ["alice", "bob", "carol", "dave", "erin"]
            .iter()
            .map(|producer| {
                Ok(ProducerKey {
                    producer_name: Name::from_str(producer)?,
                    block_signing_key: PrivateKey::random().get_public_key(),
                })
            })
            .collect::<Result<_, ChainError>>()?;
        let expected_accounts: Vec<PermissionLevelWeight> = producers
            .iter()
            .map(|producer| {
                PermissionLevelWeight::new(
                    PermissionLevel::new(producer.producer_name.into(), ACTIVE_NAME.into()),
                    1,
                )
            })
            .collect();

        controller.activate_producer_schedule(producers.clone())?;
        let timestamp = *controller.last_accepted_block.timestamp();
        controller.update_producers_authority(&producers, &timestamp)?;

        // With 5 producers the thresholds are all distinct: more than 2/3 → 4,
        // more than 1/2 → 3, more than 1/3 → 2.
        let expectations = [
            (ACTIVE_NAME, 4u32),
            (MAJORITY_PRODUCERS_PERMISSION_NAME, 3u32),
            (MINORITY_PRODUCERS_PERMISSION_NAME, 2u32),
        ];
        let db = controller.db.read()?;
        for (permission_name, threshold) in expectations {
            // Confirm the permission exists, then read its authority by name
            // (owned, arena-served) rather than off a chainbase object.
            AuthorizationManager::get_permission(&db, PRODS_NAME.into(), permission_name.into())?;
            let authority = db
                .permission_authority(PRODS_NAME.into(), permission_name.into())?
                .expect("pulse.prods permission must have an authority");
            assert_eq!(
                authority,
                Authority::new(threshold, vec![], expected_accounts.clone(), vec![]),
                "pulse.prods@{} must require {} of the 5 scheduled producers",
                permission_name,
                threshold
            );
        }

        Ok(())
    }

    // The election loop end to end: a privileged contract calls
    // set_proposed_producers, the built block carries the new schedule in its
    // signed header, and accepting that block both activates the schedule and
    // rewrites the pulse.prods producer permissions to match it. Activation is
    // an accept-time effect — after build but before accept, the schedule and
    // the permissions must still be exactly what they were.
    #[tokio::test]
    async fn set_proposed_producers_activates_schedule_and_updates_authority()
    -> Result<(), ChainError> {
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
        let mut mempool = Mempool::new();

        // Proposed producers must be real accounts. Five of them make the three
        // thresholds distinct: more than 2/3 → 4, more than 1/2 → 3, more than
        // 1/3 → 2.
        let admin = Name::from_str("prodadmin")?;
        let electees = ["alice", "bob", "carol", "dave"]
            .iter()
            .map(|name| Name::from_str(name))
            .collect::<Result<Vec<_>, ChainError>>()?;
        mempool.add_transaction(create_account(&private_key, admin, chain_id)?);
        for name in &electees {
            mempool.add_transaction(create_account(&private_key, *name, chain_id)?);
        }
        mempool.add_transaction(set_code(
            &private_key,
            admin,
            crate::wat2wasm(PROPOSE_PRODUCERS_WAT).expect("valid WAT"),
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;
        // Mirror consensus: move the preference to the accepted tip so the next
        // block builds on it.
        controller.set_preferred_id(block.id()?);

        // set_proposed_producers is privileged; make the contract account so.
        controller.database().set_privileged(admin.as_u64(), true)?;

        let read_authority =
            |controller: &Controller, permission_name: Name| -> Result<Authority, ChainError> {
                let db = controller.db.read()?;
                Ok(AuthorizationManager::get_permission(
                    &db,
                    PRODS_NAME.into(),
                    permission_name.into(),
                )?
                .get_authority()
                .to_authority())
            };
        let genesis_authorities = [
            read_authority(&controller, ACTIVE_NAME)?,
            read_authority(&controller, MAJORITY_PRODUCERS_PERMISSION_NAME)?,
            read_authority(&controller, MINORITY_PRODUCERS_PERMISSION_NAME)?,
        ];

        // Elect the four new accounts alongside pulse, through the contract.
        let proposed: Vec<ProducerKey> = electees
            .iter()
            .map(|name| ProducerKey {
                producer_name: *name,
                block_signing_key: PrivateKey::random().get_public_key(),
            })
            .chain(std::iter::once(ProducerKey {
                producer_name: PULSE_NAME,
                block_signing_key: private_key.get_public_key(),
            }))
            .collect();
        mempool.add_transaction(push_action(
            &private_key,
            admin,
            Name::from_str("run")?,
            proposed.pack().unwrap(),
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;

        // The built block advertises the change in its signed header, versioned
        // as the successor of the parent schedule.
        let header_schedule = block
            .signed_block_header
            .header
            .new_schedule()?
            .expect("built block must carry the proposed schedule in its header");
        assert_eq!(header_schedule.version, 1);
        assert_eq!(header_schedule.producers, proposed);

        // The signer set has not flipped yet — activation is an accept-time
        // effect — but the permission rewrite is part of the block's own state,
        // so the live database (which includes the pending block's session)
        // already shows it. It unwinds with the block if the chain forks.
        assert_eq!(controller.active_schedule.version, 0);
        assert_ne!(
            read_authority(&controller, ACTIVE_NAME)?,
            genesis_authorities[0],
            "the pulse.prods rewrite must ride inside the block's session"
        );

        controller.accept_block(&block.id()?, &mut mempool)?;

        // Accepting the block activates the schedule...
        assert_eq!(
            controller.active_schedule,
            ProducerSchedule {
                version: 1,
                producers: proposed.clone(),
            },
            "accepting the schedule-carrying block must activate the schedule"
        );

        // ...and rewrites the producer-gated permissions to require the new set.
        let expected_accounts: Vec<PermissionLevelWeight> = proposed
            .iter()
            .map(|producer| {
                PermissionLevelWeight::new(
                    PermissionLevel::new(producer.producer_name.into(), ACTIVE_NAME.into()),
                    1,
                )
            })
            .collect();
        let expectations = [
            (ACTIVE_NAME, 4u32),
            (MAJORITY_PRODUCERS_PERMISSION_NAME, 3u32),
            (MINORITY_PRODUCERS_PERMISSION_NAME, 2u32),
        ];
        for (i, (permission_name, threshold)) in expectations.into_iter().enumerate() {
            let authority = read_authority(&controller, permission_name)?;
            assert_ne!(
                authority, genesis_authorities[i],
                "pulse.prods@{} must have been rewritten by the schedule change",
                permission_name
            );
            assert_eq!(
                authority,
                Authority::new(threshold, vec![], expected_accounts.clone(), vec![]),
                "pulse.prods@{} must require {} of the 5 elected producers",
                permission_name,
                threshold
            );
        }

        Ok(())
    }

    // A contract for the `pulse` account that proposes a fixed producer schedule
    // from inside the implicit onblock action — the shape of eosio.system's
    // update_elected_producers, the only place the real system contract calls
    // set_proposed_producers. The packed schedule is baked into the data
    // segment; the action-name guard keeps native actions dispatched to pulse
    // from proposing.
    fn onblock_proposer_wat(packed_schedule: &[u8]) -> String {
        let data: String = packed_schedule
            .iter()
            .map(|b| format!("\\{:02x}", b))
            .collect();
        format!(
            r#"
            (module
              (import "env" "set_proposed_producers" (func $spp (param i32 i32) (result i64)))
              (memory 1)
              (export "memory" (memory 0))
              (data (i32.const 0) "{data}")
              (func (export "apply") (param $receiver i64) (param $code i64) (param $action i64)
                (if (i64.eq (local.get $action) (i64.const {onblock}))
                  (then (drop (call $spp (i32.const 0) (i32.const {len})))))))
            "#,
            onblock = ONBLOCK_NAME.as_u64() as i64,
            len = packed_schedule.len(),
        )
    }

    // The voting-driven election path: eosio.system calls set_proposed_producers
    // from inside the implicit onblock action, not from a signed transaction. A
    // schedule proposed there must reach the block header, activate on accept,
    // and rewrite the pulse.prods producer permissions — the node must not drop
    // onblock's proposal on the floor.
    #[tokio::test]
    async fn onblock_schedule_proposal_reaches_header_and_activates() -> Result<(), ChainError> {
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
        let mut mempool = Mempool::new();

        // Proposed producers must be real accounts; five (four new plus pulse)
        // make the pulse.prods thresholds distinct (4/3/2).
        let electees = ["alice", "bob", "carol", "dave"]
            .iter()
            .map(|name| Name::from_str(name))
            .collect::<Result<Vec<_>, ChainError>>()?;
        let proposed: Vec<ProducerKey> = electees
            .iter()
            .map(|name| ProducerKey {
                producer_name: *name,
                block_signing_key: PrivateKey::random().get_public_key(),
            })
            .chain(std::iter::once(ProducerKey {
                producer_name: PULSE_NAME,
                block_signing_key: private_key.get_public_key(),
            }))
            .collect();

        // Block 1: create the producer accounts and deploy the proposing
        // contract onto pulse (privileged at genesis). onblock heads the block,
        // so it runs before this setcode and must not have proposed anything.
        for name in &electees {
            mempool.add_transaction(create_account(&private_key, *name, chain_id)?);
        }
        mempool.add_transaction(set_code(
            &private_key,
            PULSE_NAME,
            crate::wat2wasm(&onblock_proposer_wat(&proposed.pack().unwrap())).expect("valid WAT"),
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        assert!(
            block.signed_block_header.header.new_schedule()?.is_none(),
            "the deploy block's onblock ran before the contract existed"
        );
        controller.accept_block(&block.id()?, &mut mempool)?;
        controller.set_preferred_id(block.id()?);

        // Block 2 carries only an ordinary transaction; the schedule proposal
        // can come from nowhere but the implicit onblock heading the block.
        mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("erin")?,
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        let header_schedule = block
            .signed_block_header
            .header
            .new_schedule()?
            .expect("onblock's proposal must reach the block header");
        assert_eq!(header_schedule.version, 1);
        assert_eq!(header_schedule.producers, proposed);

        controller.accept_block(&block.id()?, &mut mempool)?;
        assert_eq!(
            controller.active_schedule,
            ProducerSchedule {
                version: 1,
                producers: proposed.clone(),
            },
            "accepting the block must activate onblock's proposed schedule"
        );

        // Activation must also rewrite the producer-gated permissions.
        let expected_accounts: Vec<PermissionLevelWeight> = proposed
            .iter()
            .map(|producer| {
                PermissionLevelWeight::new(
                    PermissionLevel::new(producer.producer_name.into(), ACTIVE_NAME.into()),
                    1,
                )
            })
            .collect();
        let db = controller.db.read()?;
        for (permission_name, threshold) in [
            (ACTIVE_NAME, 4u32),
            (MAJORITY_PRODUCERS_PERMISSION_NAME, 3u32),
            (MINORITY_PRODUCERS_PERMISSION_NAME, 2u32),
        ] {
            let permission = AuthorizationManager::get_permission(
                &db,
                PRODS_NAME.into(),
                permission_name.into(),
            )?;
            assert_eq!(
                permission.get_authority().to_authority(),
                Authority::new(threshold, vec![], expected_accounts.clone(), vec![]),
                "pulse.prods@{} must require {} of the 5 producers elected via onblock",
                permission_name,
                threshold
            );
        }
        drop(db);

        // The rewrite must be visible to state history: the accepted block's
        // packed deltas (what SHIP serves) must carry the updated pulse.prods
        // rows. A rewrite applied after pack_deltas/commit would leave every
        // SHIP consumer permanently showing the genesis authority.
        let deltas = controller
            .chain_state_log
            .as_ref()
            .expect("chain state log initialized")
            .read_block(block.block_num())
            .expect("deltas stored for the schedule block");
        let contains = |needle: &[u8]| deltas.windows(needle.len()).any(|w| w == needle);
        assert!(
            contains(&PRODS_NAME.as_u64().to_le_bytes()),
            "the schedule block's deltas must include the pulse.prods permission rows"
        );
        assert!(
            contains(&electees[2].as_u64().to_le_bytes()),
            "the rewritten authority (listing the elected producers) must be in the deltas"
        );

        Ok(())
    }

    #[tokio::test]
    async fn rejects_header_schedule_change_that_execution_did_not_make() -> Result<(), ChainError>
    {
        // A header may only claim a schedule change its transactions actually
        // made. A block whose header advertises a schedule version with no
        // new_producers is self-inconsistent and must be rejected outright — even
        // with a valid signature — so a producer can't smuggle in a schedule the
        // chain never voted for.
        let (mut producer, private_key, chain_id, _p_temp) = init_test_controller()?;
        let mut p_mempool = Mempool::new();
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("testapi")?,
            chain_id,
        )?);
        let mut block = producer.build_block(&mut p_mempool).await?;

        // Forge a non-zero schedule version with no matching new_producers, then
        // re-sign so this is a validity failure, not a signature failure.
        block.signed_block_header.header.schedule_version = 5;
        let sig_digest: crate::utils::Digest =
            block.signed_block_header.header.sig_digest()?.0.into();
        block.signed_block_header.signature = private_key.sign(&sig_digest)?;

        let (mut validator, _pk, _cid, _v_temp) = init_test_controller()?;
        let mut v_mempool = Mempool::new();
        assert!(
            validator
                .verify_block(&block, &mut v_mempool)
                .await
                .is_err(),
            "a header schedule version with no new_producers must be rejected"
        );

        Ok(())
    }

    #[tokio::test]
    async fn refuses_to_produce_with_unscheduled_key() -> Result<(), ChainError> {
        // After the schedule rotates to a key this node does not hold, building a
        // block would produce something no one (including this node) could verify,
        // so build_block must fail closed rather than emit it.
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
        let other = PrivateKey::random();
        controller.activate_producer_schedule(vec![ProducerKey {
            producer_name: Name::from_str("pulse")?,
            block_signing_key: other.get_public_key(),
        }])?;

        let mut mempool = Mempool::new();
        mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("testapi")?,
            chain_id,
        )?);
        assert!(
            controller.build_block(&mut mempool).await.is_err(),
            "node must refuse to produce a block it cannot validly sign"
        );

        Ok(())
    }

    #[tokio::test]
    async fn onblock_runs_at_head_of_every_block() -> Result<(), ChainError> {
        // onblock is an implicit action received by the system account. A block
        // carrying a single newaccount transaction (also received by pulse) must
        // advance pulse's received-action sequence by two — once for onblock,
        // once for newaccount. Drop onblock from the block and the delta is one,
        // so this pins the invocation, not just the build/verify merkle agreement.
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
        let mut mempool = Mempool::new();

        let before = controller
            .database()
            .get_account_metadata(PULSE_NAME.as_u64())?
            .get_recv_sequence();

        mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("testapi")?,
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let after = controller
            .database()
            .get_account_metadata(PULSE_NAME.as_u64())?
            .get_recv_sequence();

        assert_eq!(
            after - before,
            2,
            "expected onblock + newaccount to each advance pulse's recv sequence"
        );

        Ok(())
    }

    // onblock executes in microseconds but is billed the configured CPU floor:
    // init_for_implicit_trx pins its explicit bill to min_transaction_cpu_usage,
    // and finalize charges that against the block's pending CPU usage. The block
    // CPU budget must drop by exactly that amount, and the net budget not at all.
    #[tokio::test]
    async fn onblock_consumes_min_transaction_cpu_usage() -> Result<(), ChainError> {
        let (mut controller, _private_key, _chain_id, _temp) = init_test_controller()?;

        let db = controller.database();
        // Scoped: the guard must not still be held when `run_onblock` below asks
        // the same lock for a write, which is a self-deadlock on one thread.
        let min_cpu_us = {
            let r = db.read()?;
            r.get_global_properties()?
                .get_chain_config()
                .get_min_transaction_cpu_usage() as u64
        };
        assert!(min_cpu_us > 0, "genesis must set a non-zero CPU floor");

        let cpu_before = db.get_block_cpu_limit()?;
        let net_before = db.get_block_net_limit()?;

        let timestamp: BlockTimestamp = TimePoint::now().into();
        let previous = controller.preferred_id;
        let (digests, _) =
            controller.run_onblock(&timestamp, PULSE_NAME, previous, &BlockStatus::Building)?;
        assert!(
            !digests.is_empty(),
            "onblock must have executed rather than been skipped"
        );

        assert_eq!(
            db.get_block_cpu_limit()?,
            cpu_before - min_cpu_us,
            "onblock must consume exactly min_transaction_cpu_usage from the block CPU budget"
        );
        assert_eq!(
            db.get_block_net_limit()?,
            net_before,
            "onblock must not consume any block net"
        );

        Ok(())
    }

    // The implicit onblock transaction runs on behalf of the privileged pulse
    // account with no CPU ceiling: init_for_implicit_trx pins cpu_limit to -1,
    // which wasm_runtime::run treats as an unlimited metering budget. Pin that
    // end to end by deploying a contract on pulse whose apply burns far more
    // metering points than max_transaction_cpu_usage allows: a regular input
    // transaction invoking it must exhaust its finite CPU limit, while onblock
    // must run the very same code to completion — which can only happen if the
    // wasm runtime received -1.
    #[tokio::test]
    async fn onblock_passes_unlimited_cpu_limit_to_wasm() -> Result<(), ChainError> {
        let (mut controller, private_key, _chain_id, _temp) = init_test_controller()?;
        let ts = controller.last_accepted_block().timestamp().clone();
        let chain_id = controller.chain_id().clone();
        let status = BlockStatus::Building;

        // Burns well over the per-transaction CPU limit of the test genesis
        // (~1e9 points), far below the unlimited budget. The loop body is packed
        // with f64.sqrt (a metered ~110 points each) so it overshoots the limit in
        // a few hundred thousand iterations rather than a billion cheap spins, which
        // keeps the onblock path (which runs it to completion) fast. Only the
        // onblock and burn actions loop — the setcode action deploying this very
        // contract also reaches apply (the receiver's code hash is read through a
        // live reference after the native handler ran) and must not burn.
        let onblock = ONBLOCK_NAME.as_u64() as i64;
        let burn = Name::from_str("burn")?.as_u64() as i64;
        let sqrts =
            "(local.set $acc (f64.sqrt (f64.add (local.get $acc) (f64.const 1))))\n".repeat(32);
        let wasm = wat::parse_str(&format!(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "apply") (param i64 i64 i64)
                (local $i i32) (local $acc f64)
                (block $skip
                  (br_if $skip
                    (i32.and
                      (i64.ne (local.get 2) (i64.const {onblock}))
                      (i64.ne (local.get 2) (i64.const {burn}))))
                  (local.set $acc (f64.const 3.14159265358979))
                  (local.set $i (i32.const 400000))
                  (block $exit
                    (loop $spin
                      (br_if $exit (i32.eqz (local.get $i)))
                      {sqrts}
                      (local.set $i (i32.sub (local.get $i) (i32.const 1)))
                      (br $spin))))))
            "#,
        ))
        .unwrap();
        controller.execute_transaction(
            &set_code(&private_key, PULSE_NAME, wasm, chain_id)?,
            &ts,
            &status,
        )?;

        // Sanity: under an input transaction the same code must blow through
        // the finite limit, proving the burn is heavy enough that onblock
        // below can only succeed on the unlimited budget.
        let res = controller.execute_transaction(
            &call_contract(
                &private_key,
                PULSE_NAME,
                Name::from_str("burn")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &ts,
            &status,
        );
        let err = match res {
            Ok(_) => panic!("an input transaction must not get an unlimited CPU budget"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("exhausted"),
            "input transaction failed for the wrong reason: {err}"
        );

        // onblock is received by pulse, so it now runs the same contract —
        // with the implicit transaction's unlimited CPU budget. A finite
        // budget would trap, onblock would be skipped, and no digests would
        // come back.
        let timestamp: BlockTimestamp = TimePoint::now().into();
        let previous = controller.preferred_id;
        let (digests, _) =
            controller.run_onblock(&timestamp, PULSE_NAME, previous, &BlockStatus::Building)?;
        assert!(
            !digests.is_empty(),
            "onblock must run the pulse contract to completion under a CPU limit of -1"
        );

        Ok(())
    }

    // A system contract that does not implement onblock must not break block
    // production. The failed implicit action is undone and contributes neither
    // a receipt nor CPU usage.
    #[tokio::test]
    async fn onblock_skipped_cleanly_when_contract_rejects_it() -> Result<(), ChainError> {
        let (mut controller, private_key, _chain_id, _temp) = init_test_controller()?;
        let ts = controller.last_accepted_block().timestamp().clone();
        let chain_id = controller.chain_id().clone();
        let status = BlockStatus::Building;

        let onblock = ONBLOCK_NAME.as_u64() as i64;
        let wasm = wat::parse_str(&format!(
            r#"
            (module
              (import "env" "eosio_assert" (func $assert (param i32 i32)))
              (memory (export "memory") 1)
              (data (i32.const 8) "unknown action\00")
              (func (export "apply") (param i64 i64 i64)
                (block $skip
                  (br_if $skip (i64.ne (local.get 2) (i64.const {onblock})))
                  (call $assert (i32.const 0) (i32.const 8)))))
            "#,
        ))
        .unwrap();
        controller.execute_transaction(
            &set_code(&private_key, PULSE_NAME, wasm, chain_id)?,
            &ts,
            &status,
        )?;

        let db = controller.database();
        let recv_before = db
            .get_account_metadata(PULSE_NAME.as_u64())?
            .get_recv_sequence();
        let cpu_before = db.get_block_cpu_limit()?;

        let timestamp: BlockTimestamp = TimePoint::now().into();
        let previous = controller.preferred_id;
        let (digests, proposed_schedule) =
            controller.run_onblock(&timestamp, PULSE_NAME, previous, &BlockStatus::Building)?;
        assert!(digests.is_empty());
        assert!(proposed_schedule.is_none());
        assert_eq!(
            db.get_account_metadata(PULSE_NAME.as_u64())?
                .get_recv_sequence(),
            recv_before,
            "a skipped onblock must not advance pulse's receive sequence"
        );
        assert_eq!(
            db.get_block_cpu_limit()?,
            cpu_before,
            "a skipped onblock must not consume block CPU"
        );

        Ok(())
    }

    // eosio_exit/pulse_exit ends the current action *successfully* — the reference
    // chain keeps the state the action produced up to the exit. A contract on pulse
    // writes a table row and then calls eosio_exit: the transaction must succeed and
    // the row must persist (a later read finds it). A sibling action calling
    // eosio_assert(false) still fails, proving a real trap is unaffected.
    #[tokio::test]
    async fn eosio_exit_ends_action_successfully_and_keeps_state() -> Result<(), ChainError> {
        let (mut controller, private_key, _chain_id, _temp) = init_test_controller()?;
        let ts = controller.last_accepted_block().timestamp().clone();
        let chain_id = controller.chain_id().clone();
        let status = BlockStatus::Building;

        let pulse = PULSE_NAME.as_u64() as i64;
        let tbl = Name::from_str("t")?.as_u64() as i64;
        let storexit = Name::from_str("storexit")?.as_u64() as i64;
        let check = Name::from_str("check")?.as_u64() as i64;
        let boom = Name::from_str("boom")?.as_u64() as i64;
        let wasm = wat::parse_str(&format!(
            r#"
            (module
              (import "env" "db_store_i64"
                (func $store (param i64 i64 i64 i64 i32 i32) (result i32)))
              (import "env" "db_find_i64"
                (func $find (param i64 i64 i64 i64) (result i32)))
              (import "env" "eosio_exit" (func $exit (param i32)))
              (import "env" "eosio_assert" (func $assert (param i32 i32)))
              (memory (export "memory") 1)
              (func (export "apply") (param i64 i64 i64)
                (block $notstore
                  (br_if $notstore (i64.ne (local.get 2) (i64.const {storexit})))
                  (i32.store (i32.const 0) (i32.const 305419896))
                  (drop (call $store (i64.const {pulse}) (i64.const {tbl})
                                     (i64.const {pulse}) (i64.const 1)
                                     (i32.const 0) (i32.const 4)))
                  (call $exit (i32.const 0))
                  (return))
                (block $notcheck
                  (br_if $notcheck (i64.ne (local.get 2) (i64.const {check})))
                  (call $assert
                    (i32.ge_s
                      (call $find (i64.const {pulse}) (i64.const {pulse})
                                  (i64.const {tbl}) (i64.const 1))
                      (i32.const 0))
                    (i32.const 0))
                  (return))
                (block $notboom
                  (br_if $notboom (i64.ne (local.get 2) (i64.const {boom})))
                  (call $assert (i32.const 0) (i32.const 0)))))
            "#,
        ))
        .unwrap();
        controller.execute_transaction(
            &set_code(&private_key, PULSE_NAME, wasm, chain_id)?,
            &ts,
            &status,
        )?;

        // The action stores a row and then calls eosio_exit. Before the fix this
        // surfaced as a trap and failed the transaction; now it must succeed.
        controller.execute_transaction(
            &call_contract(
                &private_key,
                PULSE_NAME,
                Name::from_str("storexit")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &ts,
            &status,
        )?;

        // The row written before the exit must have committed: this action asserts
        // the row is found, so it only succeeds if the state survived the exit.
        controller.execute_transaction(
            &call_contract(
                &private_key,
                PULSE_NAME,
                Name::from_str("check")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &ts,
            &status,
        )?;

        // Control: a genuine eosio_assert(false) still fails the transaction, so the
        // exit handling didn't turn every trap into a success.
        let boom_res = controller.execute_transaction(
            &call_contract(
                &private_key,
                PULSE_NAME,
                Name::from_str("boom")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &ts,
            &status,
        );
        assert!(
            boom_res.is_err(),
            "eosio_assert(false) must still fail the transaction"
        );

        Ok(())
    }

    // Wiring check for the wall-clock deadline: a node configured with a zero
    // max_transaction_time gives every transaction no time to run, so the checktime
    // call at the head of execute_action trips on the first action. Proves the
    // guard is actually invoked on the execution path and surfaces as the subjective
    // DeadlineError (not an objective CPU/apply failure).
    #[tokio::test]
    async fn zero_max_transaction_time_trips_checktime() -> Result<(), ChainError> {
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
            "max_transaction_time_ms": 0,
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

        let result = controller.execute_transaction(
            &create_account(&private_key, Name::from_str("glenn")?, chain_id)?,
            &ts,
            &status,
        );
        match result {
            Err(ChainError::DeadlineError(_)) => Ok(()),
            Err(e) => panic!("expected a DeadlineError, got a different error: {e}"),
            Ok(_) => panic!("expected a DeadlineError, but the transaction succeeded"),
        }
    }

    // The subjectivity guarantee: with the SAME zero max_transaction_time that trips
    // a normal transaction above, the explicit-billing path — the one block
    // validation/replay uses (execute_transaction_billed with recorded cpu/net) —
    // must run to completion, never tripping the wall-clock deadline. Otherwise a
    // slow validator would reject a block a faster producer made.
    #[tokio::test]
    async fn explicit_billing_is_exempt_from_checktime() -> Result<(), ChainError> {
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
            "max_transaction_time_ms": 0,
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

        // Some(..) marks the transaction as explicitly billed, exactly as
        // execute_block supplies the block-recorded cpu/net during validation.
        //
        // The cpu figure has to clear `min_transaction_cpu_usage`, which genesis
        // now sets to 100,000 — `validate_cpu_usage_to_bill` rejects a bill below
        // the floor whether or not it is explicit. The amount is incidental to
        // what this test asserts; billing the floor keeps it realistic, since a
        // producer's recorded cpu is never below it either.
        let result = controller.execute_transaction_billed(
            &create_account(&private_key, Name::from_str("glenn")?, chain_id)?,
            &ts,
            &status,
            Some((100_000, 12)),
        );
        if let Err(ChainError::DeadlineError(_)) = result {
            panic!("explicit-billed transaction must be exempt from the wall-clock deadline");
        }
        result.map(|_| ())
    }

    // The real accumulation case (as opposed to the degenerate zero-deadline trip
    // above): one transaction whose many newaccount actions genuinely take longer
    // than a 1 ms wall-clock ceiling to run. Each action re-enters execute_action
    // and re-checks the deadline, so once the running total crosses 1 ms the
    // transaction is abandoned mid-way with a DeadlineError — not a CPU/RAM trap
    // (metering is per-action and no single newaccount is close to its limit).
    //
    // Two things make this stable rather than flaky. The ceiling is the smallest
    // non-zero value the config allows (1 ms), and the action count is far larger
    // than needed: execution stops after ~1 ms of work regardless of how many
    // actions remain, so a big count is nearly free and only guarantees there is
    // always more work queued than a fast machine can finish inside 1 ms.
    #[tokio::test]
    async fn slow_multi_action_transaction_trips_checktime() -> Result<(), ChainError> {
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
            "max_transaction_time_ms": 1,
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

        let trx = create_many_accounts(&private_key, 1000, chain_id)?;
        let result = controller.execute_transaction(&trx, &ts, &status);
        match result {
            Err(ChainError::DeadlineError(_)) => Ok(()),
            Err(e) => panic!("expected a DeadlineError, got a different error: {e}"),
            Ok(_) => panic!("expected a DeadlineError, but the transaction succeeded"),
        }
    }

    // set_resource_limits lowering an account's RAM allowance below what it is
    // already using must fail the transaction: the host has to schedule a RAM
    // re-check when the limit shrank, exactly as add_ram_usage does on a growth.
    // A privileged contract on pulse drives set_resource_limits against a victim
    // account with a real, non-trivial RAM footprint (created via newaccount).
    // Dropping its limit to 1 byte must be rejected with "insufficient ram";
    // raising it well above usage — which is still a decrease from the genesis
    // unlimited (-1) default, so it runs the same check — must be accepted.
    #[tokio::test]
    async fn set_resource_limits_below_usage_is_rejected() -> Result<(), ChainError> {
        let (mut controller, private_key, _chain_id, _temp) = init_test_controller()?;
        let ts = controller.last_accepted_block().timestamp().clone();
        let chain_id = controller.chain_id().clone();
        let status = BlockStatus::Building;

        let victim = Name::from_str("victim")?;
        controller.execute_transaction(
            &create_account(&private_key, victim, chain_id)?,
            &ts,
            &status,
        )?;

        // A freshly created account already carries hundreds of bytes of account
        // and permission state, so a 1-byte limit is unambiguously below usage.
        let usage = controller
            .database()
            .get_account_ram_usage(victim.as_u64())?;
        assert!(usage > 1, "expected the new account to be using RAM");

        let shrink = Name::from_str("shrink")?.as_u64() as i64;
        let grow = Name::from_str("grow")?.as_u64() as i64;
        let victim_id = victim.as_u64() as i64;
        let wasm = wat::parse_str(&format!(
            r#"
            (module
              (import "env" "set_resource_limits"
                (func $set (param i64 i64 i64 i64)))
              (memory (export "memory") 1)
              (func (export "apply") (param i64 i64 i64)
                (block $done
                  (block $grow
                    (br_if $grow (i64.eq (local.get 2) (i64.const {grow})))
                    (br_if $done (i64.ne (local.get 2) (i64.const {shrink})))
                    (call $set (i64.const {victim_id}) (i64.const 1)
                              (i64.const -1) (i64.const -1))
                    (br $done))
                  (call $set (i64.const {victim_id}) (i64.const 100000000)
                            (i64.const -1) (i64.const -1)))))
            "#,
        ))
        .unwrap();
        controller.execute_transaction(
            &set_code(&private_key, PULSE_NAME, wasm, chain_id)?,
            &ts,
            &status,
        )?;

        let res = controller.execute_transaction(
            &call_contract(
                &private_key,
                PULSE_NAME,
                Name::from_str("shrink")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &ts,
            &status,
        );
        let err = match res {
            Ok(_) => panic!("lowering the RAM limit below usage must be rejected"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("insufficient ram"),
            "rejected for the wrong reason: {err}"
        );

        // The rejected transaction rolled back, so the limit is still unlimited.
        controller.execute_transaction(
            &call_contract(
                &private_key,
                PULSE_NAME,
                Name::from_str("grow")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &ts,
            &status,
        )?;
        let (mut ram, mut net, mut cpu) = (0i64, 0i64, 0i64);
        controller
            .database()
            .get_account_limits(victim.as_u64(), &mut ram, &mut net, &mut cpu)?;
        assert_eq!(
            ram, 100_000_000,
            "the accepted limit change did not persist"
        );

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
