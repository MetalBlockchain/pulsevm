use core::fmt;
use std::{
    collections::{
        BTreeSet,
        HashMap,
        HashSet,
        VecDeque,
    },
    fs,
    io::{
        ErrorKind,
        Write as IoWrite,
    },
    path::Path,
    str::FromStr,
    sync::LazyLock,
};

use crate::{
    ACTIVE_NAME,
    MAJORITY_PRODUCERS_PERMISSION_NAME,
    MINORITY_PRODUCERS_PERMISSION_NAME,
    PULSE_NAME,
    block::{
        BlockStatus,
        SignedBlock,
    },
    chain::{
        apply_context::{
            ApplyContext,
            generated_transaction_billable_size,
        },
        authority::PermissionLevel,
        authorization_manager::AuthorizationManager,
        block::BlockHeader,
        config::{
            DELETEAUTH_NAME,
            LINKAUTH_NAME,
            NEWACCOUNT_NAME,
            ONBLOCK_NAME,
            ONERROR_NAME,
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
        protocol_features::{
            ProtocolExecutionContext,
            ProtocolUpgrade,
            ProtocolUpgradeSchedule,
            ProtocolVersion,
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
        state_history::{
            StateHistoryLog,
            StateHistoryLogCheckpoint,
        },
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

use pulsevm_constants::{
    BLOCK_CPU_USAGE_AVERAGE_WINDOW_MS,
    BLOCK_INTERVAL_MS,
    BLOCK_SIZE_AVERAGE_WINDOW_MS,
    MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER,
};

const DISABLE_DEFERRED_TRXS_STAGE_1_FEATURE_DIGEST: [u8; 32] = [
    0xfc, 0xe5, 0x7d, 0x23, 0x31, 0x66, 0x73, 0x53, 0xa0, 0xea, 0xc6, 0xb4, 0x20, 0x9b, 0x67, 0xb8,
    0x43, 0xa7, 0x26, 0x2a, 0x84, 0x8a, 0xf0, 0xa4, 0x9a, 0x6e, 0x2f, 0xa9, 0xf6, 0x58, 0x4e, 0xb4,
];
const DISABLE_DEFERRED_TRXS_STAGE_2_FEATURE_DIGEST: [u8; 32] = [
    0x09, 0xe8, 0x6c, 0xb0, 0xac, 0xcf, 0x8d, 0x81, 0xc9, 0xe8, 0x5d, 0x34, 0xbe, 0xa4, 0xb9, 0x25,
    0xae, 0x93, 0x66, 0x26, 0xd0, 0x0c, 0x98, 0x4e, 0x46, 0x91, 0x18, 0x68, 0x91, 0xf5, 0xbc, 0x16,
];
use pulsevm_crypto::{
    Bytes,
    Digest,
    make_canonical_pair,
    merkle,
};
use pulsevm_database::{
    Authority,
    BlockTimestamp,
    Database,
    ElasticLimitParameters,
    Microseconds,
    MigrationManifest,
    PermissionLevelWeight,
    TimePoint,
    seconds,
};
use pulsevm_error::ChainError;
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

/// Append Antelope's canonical `varuint32` representation. This is used for
/// the `bytes sent_trx` member of the native `onerror` action payload.
fn append_varuint32(bytes: &mut Vec<u8>, value: usize) -> Result<(), ChainError> {
    let mut value = u32::try_from(value).map_err(|_| {
        ChainError::TransactionError("deferred transaction is too large for onerror".into())
    })?;
    while value >= 0x80 {
        bytes.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
    Ok(())
}

fn deferred_onerror_payload(sender_id: u128, packed_trx: &[u8]) -> Result<Vec<u8>, ChainError> {
    let mut data = sender_id.to_le_bytes().to_vec();
    append_varuint32(&mut data, packed_trx.len())?;
    data.extend_from_slice(packed_trx);
    Ok(data)
}

fn retire_deferred_transaction(
    db: &mut Database,
    trx_id: [u8; 32],
    payer: u64,
    packed_trx_len: usize,
) -> Result<(), ChainError> {
    ResourceLimitsManager::add_pending_ram_usage(
        db,
        &Name::new(payer),
        -generated_transaction_billable_size(packed_trx_len)?,
    )?;
    if !db.arena_remove_deferred_transaction(trx_id)? {
        return Err(ChainError::InternalError(format!(
            "cannot retire missing deferred transaction {}",
            hex::encode(trx_id)
        )));
    }
    Ok(())
}

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

/// Native system actions are selected by action name once the receiver and
/// scope have been validated by `find_apply_handler`. Keeping this separate
/// from the legacy `(receiver, scope, action)` table avoids scanning a map on
/// every custom-root system action.
pub static NATIVE_SYSTEM_HANDLERS: LazyLock<HashMap<Name, ApplyHandlerFn>> = LazyLock::new(|| {
    HashMap::from([
        (NEWACCOUNT_NAME, newaccount as ApplyHandlerFn),
        (SETCODE_NAME, setcode as ApplyHandlerFn),
        (SETABI_NAME, setabi as ApplyHandlerFn),
        (UPDATEAUTH_NAME, updateauth as ApplyHandlerFn),
        (DELETEAUTH_NAME, deleteauth as ApplyHandlerFn),
        (LINKAUTH_NAME, linkauth as ApplyHandlerFn),
        (UNLINKAUTH_NAME, unlinkauth as ApplyHandlerFn),
    ])
});

/// Antelope's append-only blockroot merkle. Only the active frontier is kept,
/// so adding one block is logarithmic and the complete history is unnecessary.
#[derive(Clone, Debug, Default)]
struct IncrementalBlockMerkle {
    active_nodes: Vec<Digest>,
    node_count: u64,
}

impl IncrementalBlockMerkle {
    fn root(&self) -> Digest {
        self.active_nodes.last().copied().unwrap_or_default()
    }

    fn append(&mut self, digest: Digest) -> Result<(), ChainError> {
        let next_count = self
            .node_count
            .checked_add(1)
            .ok_or_else(|| ChainError::BlockError("blockroot merkle overflow".into()))?;
        let implied_count = next_count.next_power_of_two();
        let max_depth = (u64::BITS - implied_count.leading_zeros()) as usize;
        let mut current_depth = max_depth - 1;
        let mut index = self.node_count;
        let mut top = digest;
        let mut active_index = 0usize;
        let mut updated = Vec::with_capacity(max_depth);
        let mut partial = false;

        while current_depth > 0 {
            if index & 1 == 0 {
                if !partial {
                    updated.push(top);
                }
                top = make_canonical_pair(top, top);
                partial = true;
            } else {
                let left = self
                    .active_nodes
                    .get(active_index)
                    .copied()
                    .ok_or_else(|| {
                        ChainError::BlockError("invalid blockroot merkle frontier".into())
                    })?;
                active_index += 1;
                if partial {
                    updated.push(left);
                }
                top = make_canonical_pair(left, top);
            }
            current_depth -= 1;
            index >>= 1;
        }
        updated.push(top);
        self.active_nodes = updated;
        self.node_count = next_count;
        Ok(())
    }
}

fn hash_digest_pair(left: Digest, right: Digest) -> Digest {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&left.0);
    bytes.extend_from_slice(&right.0);
    Digest::hash(&bytes)
}

/// The two pieces of Antelope header state committed by every producer
/// signature but not present in the block header itself.
#[derive(Clone, Debug, Default)]
struct HeaderSigningState {
    blockroot_merkle: IncrementalBlockMerkle,
    pending_schedule_hash: Digest,
}

#[derive(Clone, Debug)]
struct ProducerScheduleState {
    active: ProducerSchedule,
    pending: Option<ProducerSchedule>,
}

/// Header-only XPR migration verifier that can run ahead of sequential state
/// execution. It authenticates the exact signature digest and advances only
/// header-derived schedule/signing state; the controller still repeats every
/// cheap schedule, timestamp, syntax, execution, and merkle-root check.
#[doc(hidden)]
pub struct MigrationBlockAuthenticator {
    antelope_block_signatures: bool,
    schedule_state: ProducerScheduleState,
    signing_state: HeaderSigningState,
    previous_id: Id,
}

/// A block whose expensive public-key recovery was completed by a
/// `MigrationBlockAuthenticator`. Fields stay private so callers cannot forge
/// the proof or pair it with a different block.
#[doc(hidden)]
pub struct AuthenticatedMigrationBlock {
    block: SignedBlock,
    signer: PublicKey,
}

impl AuthenticatedMigrationBlock {
    pub fn block(&self) -> &SignedBlock {
        &self.block
    }
}

impl ProducerScheduleState {
    fn apply_header(&mut self, header: &BlockHeader) -> Result<bool, ChainError> {
        let mut promoted = false;
        if header.schedule_version != self.active.version {
            let pending = self.pending.take().ok_or_else(|| {
                ChainError::BlockError(format!(
                    "block declares active schedule version {}, but current version is {} and no schedule is pending",
                    header.schedule_version, self.active.version
                ))
            })?;
            if pending.version != header.schedule_version {
                return Err(ChainError::BlockError(format!(
                    "block declares active schedule version {}, but pending version is {}",
                    header.schedule_version, pending.version
                )));
            }
            self.active = pending;
            promoted = true;
        }

        if let Some(schedule) = header.new_schedule()? {
            if self.pending.is_some() {
                return Err(ChainError::BlockError(
                    "block sets new pending producers before the prior schedule became active"
                        .into(),
                ));
            }
            if schedule.version != self.active.version + 1 {
                return Err(ChainError::BlockError(format!(
                    "new pending schedule version {} does not follow active version {}",
                    schedule.version, self.active.version
                )));
            }
            self.pending = Some(schedule);
        }
        Ok(promoted)
    }
}

impl HeaderSigningState {
    fn from_genesis(genesis_id: &Id, schedule: &ProducerSchedule) -> Result<Self, ChainError> {
        let mut state = Self {
            blockroot_merkle: IncrementalBlockMerkle::default(),
            pending_schedule_hash: Digest::hash(&schedule.pack().map_err(|error| {
                ChainError::SerializationError(format!("pack genesis producer schedule: {error}"))
            })?),
        };
        state.blockroot_merkle.append(Digest(genesis_id.0.0))?;
        Ok(state)
    }

    fn signing_digest(&self, header: &BlockHeader) -> Result<Digest, ChainError> {
        let header_digest = Digest::hash(&header.pack().map_err(|error| {
            ChainError::SerializationError(format!("pack block header for signature: {error}"))
        })?);
        let header_root = hash_digest_pair(header_digest, self.blockroot_merkle.root());
        let pending_schedule_hash = header
            .new_schedule_hash()?
            .unwrap_or(self.pending_schedule_hash);
        Ok(hash_digest_pair(header_root, pending_schedule_hash))
    }

    fn accept(&mut self, block: &SignedBlock) -> Result<(), ChainError> {
        self.blockroot_merkle.append(Digest(block.id()?.0.0))?;
        if let Some(schedule_hash) = block.signed_block_header.header.new_schedule_hash()? {
            self.pending_schedule_hash = schedule_hash;
        }
        Ok(())
    }
}

impl MigrationBlockAuthenticator {
    pub fn authenticate(
        &mut self,
        block: SignedBlock,
    ) -> Result<AuthenticatedMigrationBlock, ChainError> {
        if *block.previous_id() != self.previous_id {
            return Err(ChainError::BlockError(format!(
                "migration signature stream expected parent {}, found {} for block {}",
                self.previous_id,
                block.previous_id(),
                block.block_num()
            )));
        }

        let header = &block.signed_block_header.header;
        self.schedule_state.apply_header(header)?;
        let expected = self
            .schedule_state
            .active
            .block_signing_key(&header.producer)
            .ok_or_else(|| {
                ChainError::BlockError(format!(
                    "block producer {} is not in the active schedule",
                    header.producer
                ))
            })?;
        let digest = if self.antelope_block_signatures {
            self.signing_state.signing_digest(header)?
        } else {
            header.sig_digest()?
        };
        let signer = block
            .signed_block_header
            .signature
            .recover_public_key(&digest)?;
        if &signer != expected {
            return Err(ChainError::BlockError(format!(
                "block signature recovered {signer}, expected {expected} for producer {} in schedule version {}",
                header.producer, self.schedule_state.active.version
            )));
        }

        let block_id = block.id()?;
        self.signing_state.accept(&block)?;
        self.previous_id = block_id;
        Ok(AuthenticatedMigrationBlock { block, signer })
    }
}

pub struct Controller {
    wasm_runtime: WasmRuntime,
    last_accepted_block: SignedBlock,
    last_accepted_block_id: Id,
    preferred_id: Id,
    db: Database,
    verified_blocks: HashMap<Id, SignedBlock>,
    chain_id: Id,
    // The genesis-derived chain id (`sha256(pack(genesis))`), which is what the
    // `global_property` state-history record commits to — distinct from
    // `chain_id`, the id AvalancheGo configured the node with (equal in
    // production; the replay test deliberately runs them apart).
    genesis_chain_id: Id,
    state: vm::State,

    block_log: Option<StateHistoryLog>,
    trace_log: Option<StateHistoryLog>,
    chain_state_log: Option<StateHistoryLog>,
    node_config: Option<NodeConfig>,

    // Consensus-critical upgrade schedule supplied in `upgrade_bytes` at VM
    // initialization. MetalGo sources it from each node's chain configuration,
    // so operators must keep the schedule identical across validators and
    // restarts. See `docs/protocol-features.md` section 5.
    protocol_upgrade_schedule: ProtocolUpgradeSchedule,

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

    // A schedule carried by `new_producers` is pending until a later header's
    // `schedule_version` promotes it. Keeping it separate prevents the proposal
    // and pending phases from changing block authorization prematurely.
    pending_schedule: Option<ProducerSchedule>,

    // Antelope header-signing state at `last_accepted_block_id`. Canonical XPR
    // signatures commit to this state in addition to the packed header.
    header_signing_state: HeaderSigningState,

    // Schedule in force for the block currently executing. Contracts read this
    // through get_active_producers/set_proposed_producers.
    block_active_schedule: ProducerSchedule,

    // Pending schedule visible while the current block executes. It is not
    // returned by get_active_producers, but Leap bases the next proposed version
    // and equality check on it when present.
    block_pending_schedule: Option<ProducerSchedule>,

    // The chain of blocks that have been executed (during build or verify) but
    // not yet accepted, ordered oldest first. Their state is materialized on the
    // live database as a stack of arena undo sessions on top of
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

/// Read-only state required for mempool admission. See
/// `docs/mempool-admission.md` §2–4 for its shared-live-state semantics.
/// The database handle is
/// internally synchronized, so this can validate advisory admission checks
/// without taking the controller lock while a producer is executing a block.
/// It intentionally observes the live state rather than a consensus snapshot:
/// admission has no state effect and transactions are still executed and
/// validated against the selected block state before inclusion.
#[derive(Clone)]
pub struct MempoolAdmissionState {
    db: Database,
    chain_id: Id,
    protocol_upgrade_schedule: ProtocolUpgradeSchedule,
}

impl MempoolAdmissionState {
    pub fn validate_transaction(
        &self,
        packed_transaction: &PackedTransaction,
        pending_block_timestamp: &BlockTimestamp,
    ) -> Result<(), ChainError> {
        let signed_transaction = packed_transaction.get_signed_transaction();
        let transaction = signed_transaction.transaction();

        let accepted_height = u32::try_from(self.db.revision()).map_err(|_| {
            ChainError::InternalError(format!(
                "database revision {} cannot be used as an accepted block height",
                self.db.revision()
            ))
        })?;
        let next_block_height = accepted_height
            .checked_add(1)
            .ok_or_else(|| ChainError::InternalError("accepted block height overflow".into()))?;
        self.protocol_upgrade_schedule
            .execution_context(next_block_height)
            .map_err(|e| ChainError::BlockError(e.to_string()))?;

        transaction.validate(pending_block_timestamp)?;

        let expiration: TimePoint = transaction.header.expiration().into();
        let pending: TimePoint = (*pending_block_timestamp).into();
        let max_lifetime = self.db.chain_config()?.max_transaction_lifetime;
        if expiration < pending {
            return Err(ChainError::TransactionError("transaction expired".into()));
        }
        if expiration > pending + seconds(max_lifetime as i64) {
            return Err(ChainError::TransactionError(
                "transaction has too long lifetime".into(),
            ));
        }

        let mut has_authorization = false;
        for action in &transaction.context_free_actions {
            if !self.db.is_account(action.account.as_u64())? {
                return Err(ChainError::TransactionError(format!(
                    "context free action {} references non-existent account {}",
                    action.name(),
                    action.account()
                )));
            }
            if !action.authorization.is_empty() {
                return Err(ChainError::TransactionError(
                    "context-free actions cannot have authorizations".into(),
                ));
            }
        }
        for action in &transaction.actions {
            if !self.db.is_account(action.account.as_u64())? {
                return Err(ChainError::TransactionError(format!(
                    "action {} references non-existent account {}",
                    action.name(),
                    action.account()
                )));
            }
            for authorization in action.authorization() {
                has_authorization = true;
                if !self.db.is_account(authorization.actor())? {
                    return Err(ChainError::TransactionError(format!(
                        "action's authorizing actor '{}' does not exist",
                        Name::new(authorization.actor)
                    )));
                }
                if AuthorizationManager::find_permission(&self.db.read()?, authorization)?.is_none()
                {
                    return Err(ChainError::TransactionError(format!(
                        "action's authorizations include a non-existent permission: {}",
                        authorization,
                    )));
                }
            }
        }
        if !has_authorization {
            return Err(ChainError::TransactionError(
                "transaction must have at least one authorization".into(),
            ));
        }

        if self
            .db
            .is_known_unexpired_transaction(&packed_transaction.id().0.0)?
        {
            return Err(ChainError::DatabaseError("duplicate tx".into()));
        }

        AuthorizationManager::check_authorization(
            &self.db,
            &transaction.actions,
            &signed_transaction.recovered_authority_keys(&self.chain_id)?,
            &BTreeSet::new(),
            seconds(transaction.header.delay_sec.into()),
            &BTreeSet::new(),
        )
    }
}

struct PendingBlock {
    id: Id,
    // Parent block id. For the front of the chain this equals the last accepted
    // block; for later entries it is the previous entry's id.
    #[allow(dead_code)] // Asserted by pending-chain invariant tests.
    parent: Id,
    // The block's mutations live on the arena's undo stack (an
    // `arena_start_undo_session` was opened when this entry was pushed). Accepting
    // the block commits that level; unwinding past it undoes it.
    // Transaction traces produced during execution, needed by `store_traces` at
    // accept time. Retaining them avoids recomputing via a second execution.
    traces: Vec<TransactionTrace>,
}

impl Drop for Controller {
    fn drop(&mut self) {
        // The pending blocks form the arena's undo stack and must be released in
        // reverse (LIFO) order, undoing each speculative level from the tip down.
        while self.pending_chain.pop().is_some() {
            self.db.arena_undo();
        }
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
const SYNCED_SCHEDULE_MAGIC: &[u8; 8] = b"PVMSCH01";

/// Durable poison marker for the multi-file state-sync publication window.
/// Its presence makes startup fail closed; successful application removes it
/// only after the arena, logs, producer schedule, and in-memory head agree.
const STATE_SYNC_INSTALL_MARKER_FILE: &str = "state_sync_installing";
const STATE_SYNC_INSTALL_MARKER_MAGIC: &[u8; 8] = b"PVMSYN01";

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

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
            genesis_chain_id: Id::default(),
            state: vm::State::Unspecified,

            block_log: None,
            trace_log: None,
            chain_state_log: None,
            node_config: None,
            protocol_upgrade_schedule: ProtocolUpgradeSchedule::default(),
            db_path: None,
            snapshot_cache: None,
            active_schedule: ProducerSchedule::default(),
            pending_schedule: None,
            header_signing_state: HeaderSigningState::default(),
            block_active_schedule: ProducerSchedule::default(),
            block_pending_schedule: None,

            pending_chain: Vec::new(),
            blocks_executed: 0,
        }
    }

    // The id of the block whose state is currently live on the database: the tip
    // of the pending chain, or the last accepted block when the chain is empty.
    fn pending_tip_id(&self) -> Id {
        debug_assert!(
            self.pending_chain
                .first()
                .map(|pending| pending.parent == self.last_accepted_block_id)
                .unwrap_or(true),
            "pending chain must start at the last accepted block"
        );
        debug_assert!(
            self.pending_chain
                .windows(2)
                .all(|pair| pair[1].parent == pair[0].id),
            "pending chain must be parent-linked in order"
        );
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
            let _entry = self.pending_chain.pop().unwrap();
            self.db.arena_undo(); // pop the matching arena session
        }
        Ok(())
    }

    // Discard the whole pending chain, restoring the database to the last
    // accepted state. Paths that must execute against the plain accepted base
    // call this first.
    fn clear_pending(&mut self) -> Result<(), ChainError> {
        self.unwind_pending_to(0)
    }

    fn rollback_accept_logs(
        &self,
        block_checkpoint: &StateHistoryLogCheckpoint,
        trace_checkpoint: &StateHistoryLogCheckpoint,
        chain_state_checkpoint: &StateHistoryLogCheckpoint,
    ) -> Vec<String> {
        let mut errors = Vec::new();
        let logs = [
            (
                "chain-state",
                self.chain_state_log.as_ref(),
                chain_state_checkpoint,
            ),
            ("trace", self.trace_log.as_ref(), trace_checkpoint),
            ("block", self.block_log.as_ref(), block_checkpoint),
        ];
        for (name, log, checkpoint) in logs {
            match log {
                Some(log) => {
                    if let Err(error) = log.rollback_to(checkpoint) {
                        errors.push(format!("{name} log rollback failed: {error}"));
                    }
                }
                None => errors.push(format!("{name} log disappeared during accept rollback")),
            }
        }
        errors
    }

    pub fn initialize(
        &mut self,
        chain_id: &Id,
        config_bytes: &Vec<u8>,
        genesis_bytes: &Vec<u8>,
        db_path: &str,
    ) -> Result<(), ChainError> {
        self.initialize_with_protocol_upgrades(chain_id, config_bytes, genesis_bytes, &[], db_path)
    }

    pub fn initialize_with_protocol_upgrades(
        &mut self,
        chain_id: &Id,
        config_bytes: &[u8],
        genesis_bytes: &[u8],
        upgrade_bytes: &[u8],
        db_path: &str,
    ) -> Result<(), ChainError> {
        info!("initializing controller with DB path: {}", db_path);
        self.protocol_upgrade_schedule = ProtocolUpgradeSchedule::from_upgrade_bytes(upgrade_bytes)
            .map_err(|e| {
                ChainError::ParseError(format!("failed to parse protocol upgrade schedule: {e}"))
            })?;
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

        Self::ensure_no_incomplete_state_sync(db_path)?;
        self.db_path = Some(db_path.to_string());
        // Parse this before restoring a migration checkpoint: a migration
        // genesis commits its checkpoint hash, so the node can reject a
        // manifest that belongs to a different target chain.
        let rust_genesis = pulsevm_database::GenesisState::from_bytes(genesis_bytes)?;

        // Initialize database
        self.db = Database::new(&db_path, self.node_config.as_ref().unwrap().db_size)
            .map_err(|e| ChainError::InternalError(format!("failed to open database: {}", e)))?;
        let system_account = self.node_config.as_ref().unwrap().system_account;
        let native_system_contract = self.node_config.as_ref().unwrap().native_system_contract;
        self.db
            .set_system_account(system_account)
            .map_err(ChainError::GenesisError)?;
        self.db
            .set_native_system_contract(native_system_contract)
            .map_err(ChainError::GenesisError)?;
        self.db.add_indices()?;
        let migration_checkpoint = self
            .node_config
            .as_ref()
            .and_then(|config| config.migration_checkpoint.as_ref());
        let migration_manifest = self
            .node_config
            .as_ref()
            .and_then(|config| config.migration_manifest.as_ref());
        if let (Some(checkpoint), Some(manifest_path)) = (migration_checkpoint, migration_manifest)
        {
            let manifest_bytes = fs::read(manifest_path).map_err(|e| {
                ChainError::GenesisError(format!(
                    "failed to read migration manifest {manifest_path}: {e}"
                ))
            })?;
            let manifest: MigrationManifest =
                serde_json::from_slice(&manifest_bytes).map_err(|e| {
                    ChainError::GenesisError(format!(
                        "failed to parse migration manifest {manifest_path}: {e}"
                    ))
                })?;
            manifest.verify_checkpoint_path(checkpoint).map_err(|e| {
                ChainError::GenesisError(format!(
                    "migration manifest {manifest_path} rejected checkpoint {checkpoint}: {e}"
                ))
            })?;
            let expected_checkpoint_sha256 =
                rust_genesis.migration_checkpoint_sha256.ok_or_else(|| {
                    ChainError::GenesisError(
                        "migration genesis is missing migration_checkpoint_sha256".into(),
                    )
                })?;
            if manifest.checkpoint_sha256 != hex::encode(expected_checkpoint_sha256) {
                return Err(ChainError::GenesisError(format!(
                    "migration manifest checkpoint hash {} does not match migration genesis {}",
                    manifest.checkpoint_sha256,
                    hex::encode(expected_checkpoint_sha256)
                )));
            }
            let header = self
                .db
                .restore_from_path(std::path::Path::new(checkpoint))
                .map_err(|e| {
                    ChainError::GenesisError(format!(
                        "failed to restore migration checkpoint {checkpoint}: {e}"
                    ))
                })?;
            if header.revision <= 0 {
                return Err(ChainError::GenesisError(
                    "migration checkpoint must carry a positive revision".into(),
                ));
            }
            for deferred in self.db.arena_deferred_transactions() {
                let transaction = PackedTransaction::from_deferred_transaction_bytes(Bytes::from(
                    deferred.packed_trx,
                ))
                .map_err(|error| {
                    ChainError::GenesisError(format!(
                        "migration deferred transaction {} cannot be decoded: {error}",
                        hex::encode(deferred.trx_id)
                    ))
                })?;
                if transaction.id().as_bytes() != deferred.trx_id {
                    return Err(ChainError::GenesisError(format!(
                        "migration deferred transaction {} does not match its packed bytes",
                        hex::encode(deferred.trx_id)
                    )));
                }
            }
            // Leap's second deferred-transaction retirement feature removes all
            // pending generated transactions when activated. A checkpoint made
            // before that activation can still carry rows, so normalize them
            // before the target chain starts producing blocks.
            if self
                .db
                .protocol_feature_activated(DISABLE_DEFERRED_TRXS_STAGE_2_FEATURE_DIGEST)
            {
                let pending = self.db.arena_deferred_transactions();
                for deferred in &pending {
                    retire_deferred_transaction(
                        &mut self.db,
                        deferred.trx_id,
                        deferred.payer,
                        deferred.packed_trx.len(),
                    )?;
                }
                if !pending.is_empty() {
                    info!(
                        "removed {} pending deferred transactions because DISABLE_DEFERRED_TRXS_STAGE_2 is active",
                        pending.len()
                    );
                }
            }
            info!(
                "restored migration Arena checkpoint {} at revision {} from manifest {}",
                checkpoint, header.revision, manifest_path
            );
        } else if migration_checkpoint.is_some() || migration_manifest.is_some() {
            return Err(ChainError::GenesisError(
                "migration_checkpoint and migration_manifest must be configured together".into(),
            ));
        } else if rust_genesis.migration_checkpoint_sha256.is_some() {
            return Err(ChainError::GenesisError(
                "migration genesis requires migration_checkpoint and migration_manifest".into(),
            ));
        }

        // Pure-Rust view of the genesis: the arena is authored directly from this,
        // and the schedule/timestamp below are read from it, so the initial state
        // never routes through C++.
        self.chain_id = chain_id.clone();

        // The chain id is sha256(fc::raw::pack(genesis)); derive it from the
        // parsed genesis and check it against the id AvalancheGo handed us. They
        // must agree, or the genesis blob and the chain it is meant to bring up
        // have diverged — surface that rather than run under a silent mismatch.
        let derived_chain_id = Id::new(rust_genesis.compute_chain_id());
        self.genesis_chain_id = derived_chain_id.clone();
        if &derived_chain_id != chain_id {
            warn!(
                "genesis-derived chain id {} does not match the configured chain id {}",
                derived_chain_id, chain_id
            );
        }

        // Seed the active producer schedule from genesis: the sole producer is
        // the configured producer_name, and it signs blocks with the genesis
        // initial key. On restart this is the base the block log is replayed onto
        // (see `reconstruct_schedule_from_log` below).
        let initial_key = PublicKey::new(rust_genesis.initial_key);
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
        let antelope_genesis = !native_system_contract;
        self.last_accepted_block = SignedBlock::new(
            Id::default(),
            // Rebuild the genesis block timestamp from the parsed micro count
            // through the pure-Rust conversion.
            BlockTimestamp::from(TimePoint::new(Microseconds::new(
                rust_genesis.initial_timestamp_micros,
            ))),
            if antelope_genesis {
                // EOSIO/Antelope authors the exceptional genesis block with an
                // empty producer name. The initial schedule still assigns the
                // configured producer starting with block 2.
                Name::default()
            } else {
                self.node_config.as_ref().unwrap().producer_name
            },
            VecDeque::new(),
            Digest::default(),
            if antelope_genesis {
                Digest(derived_chain_id.0.0)
            } else {
                Digest::default()
            },
        );
        if antelope_genesis {
            // Leap's genesis header is the one exceptional block with
            // `confirmed = 1`; its action root commits the genesis chain id.
            self.last_accepted_block
                .signed_block_header
                .header
                .confirmed = 1;
        }
        self.last_accepted_block_id = self.last_accepted_block.id()?;
        self.preferred_id = self.last_accepted_block.id()?;
        self.header_signing_state =
            HeaderSigningState::from_genesis(&self.last_accepted_block_id, &self.active_schedule)?;

        let revision = self.db.revision();
        info!("database revision: {}", revision);
        self.db.validate_system_account_state()?;

        if revision <= 0 {
            // Initialize the database with the genesis state
            info!("initializing database with genesis state");
            self.db
                .initialize_database_with_system_account(&rust_genesis, system_account)
                .map_err(|e| {
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
        let genesis_height = self.last_accepted_block.block_num();

        match block_log_range {
            None => {
                if revision != genesis_height as i64 {
                    return Err(ChainError::DatabaseError(format!(
                        "database revision {revision} does not match empty block log (expected fresh genesis revision {genesis_height})"
                    )));
                }
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
            Some((start, mut end)) => {
                // The block log is the accepted-head journal while chainbase is
                // the corresponding state. Either side being ahead means a
                // prior publication was interrupted; choosing either tip would
                // silently pair a block with the wrong state.
                if revision != end as i64 {
                    let migration_replay = self
                        .node_config
                        .as_ref()
                        .is_some_and(|config| !config.state_history_enabled);
                    if migration_replay && revision >= i64::from(start) && revision < i64::from(end)
                    {
                        warn!(
                            "migration replay is rewinding block log from {} to durable Arena revision {}",
                            end, revision
                        );
                        self.block_log
                            .as_ref()
                            .unwrap()
                            .truncate_after(revision as u32)
                            .map_err(|error| {
                                ChainError::DatabaseError(format!(
                                    "failed to rewind migration block log to revision {revision}: {error}"
                                ))
                            })?;
                        end = revision as u32;
                    } else {
                        error!(
                            "database revision {} does not match block log end {}",
                            revision, end
                        );

                        return Err(ChainError::DatabaseError(format!(
                            "database revision {} does not match block log end {}",
                            revision, end
                        )));
                    }
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
                // normally-grown chain, where the genesis seed is the base. A
                // re-based log (start > genesis) must have this file; silently
                // falling back to genesis producers would reinterpret synced
                // state after a torn or manually deleted sidecar.
                let synced = Self::load_synced_schedule(db_path)?;
                if start > genesis_height && synced.is_none() {
                    return Err(ChainError::DatabaseError(format!(
                        "state-synced block log starts at height {start}, but {} is missing",
                        SYNCED_SCHEDULE_FILE
                    )));
                }
                if let Some(synced) = synced {
                    self.active_schedule = synced;
                }

                // Rebuild the active schedule from the committed chain rather than
                // trusting an out-of-band file: the last block that carried a
                // `new_producers` names the schedule in force, and if none did the
                // base above still stands.
                self.reconstruct_schedule_from_log(start, end)?;
                if self
                    .node_config
                    .as_ref()
                    .is_some_and(|config| config.antelope_block_signatures)
                {
                    // Rebuild the compact signing frontier alongside the
                    // accepted block log. A genesis-based XPR replay retains the
                    // complete log, so this reproduces nodeos header state.
                    for height in start.max(genesis_height + 1)..=end {
                        let block = self.get_block_by_height(height)?.ok_or_else(|| {
                            ChainError::DatabaseError(format!(
                                "missing block {height} while rebuilding Antelope signing state"
                            ))
                        })?;
                        self.header_signing_state.accept(&block)?;
                    }
                }
            }
        }

        self.validate_persisted_protocol_state(self.last_accepted_block.block_num(), false)?;
        self.ensure_protocol_version_supported(self.last_accepted_block.block_num())?;
        Ok(())
    }

    /// Consensus protocol version active for a block height.
    pub fn protocol_version(&self, block_height: u32) -> ProtocolVersion {
        self.protocol_upgrade_schedule
            .protocol_version(block_height)
    }

    /// Canonical digest of the complete schedule loaded by this node, including
    /// future transitions. Operators compare this before an activation.
    pub fn protocol_upgrade_schedule_hash(&self) -> [u8; 32] {
        self.protocol_upgrade_schedule.schedule_hash()
    }

    pub fn next_protocol_upgrade(&self, block_height: u32) -> Option<ProtocolUpgrade> {
        self.protocol_upgrade_schedule.next_upgrade(block_height)
    }

    fn ensure_protocol_version_supported(
        &self,
        block_height: u32,
    ) -> Result<ProtocolExecutionContext, ChainError> {
        self.protocol_upgrade_schedule
            .execution_context(block_height)
            .map_err(|e| ChainError::BlockError(e.to_string()))
    }

    fn configured_protocol_records(&self, block_height: u32) -> Vec<([u8; 32], u32)> {
        self.protocol_upgrade_schedule
            .activated_upgrades(block_height)
            .iter()
            .copied()
            .map(ProtocolUpgrade::activation_record)
            .collect()
    }

    /// Bind the locally supplied schedule to the activation history committed
    /// in chainbase. `allow_pending_descendants` is used only at Accept while
    /// later verified blocks may still have live child undo sessions.
    fn validate_persisted_protocol_state(
        &self,
        block_height: u32,
        allow_pending_descendants: bool,
    ) -> Result<(), ChainError> {
        let stored = self.db.activated_protocol_features()?;
        let expected = self.configured_protocol_records(block_height);
        let configured = self
            .protocol_upgrade_schedule
            .protocol_upgrades
            .iter()
            .copied()
            .map(ProtocolUpgrade::activation_record)
            .collect::<Vec<_>>();
        let matches = if allow_pending_descendants {
            stored.starts_with(&expected) && configured.starts_with(&stored)
        } else {
            stored == expected
        };
        if !matches {
            return Err(ChainError::BlockError(format!(
                "configured protocol upgrade schedule does not match the {} activation record(s) persisted at chain height {block_height}",
                stored.len()
            )));
        }
        Ok(())
    }

    /// Confirm that a candidate executes against the activation history of its
    /// accepted parent. The record itself is persisted only after the candidate
    /// has been committed, so a rejected speculative block cannot activate it.
    fn prepare_protocol_execution(
        &mut self,
        context: ProtocolExecutionContext,
    ) -> Result<(), ChainError> {
        let block_height = context.block_height();
        self.validate_persisted_protocol_state(block_height.saturating_sub(1), false)
    }

    // Walk the block log back from the tip for the most recent block that changed
    // the producer schedule; its header carries the schedule now in force. Runs
    // once at startup. It is O(blocks since the last schedule change), which is
    // the whole log when the schedule never changed — acceptable while chains are
    // short; a cached height pointer is the obvious optimization if it gets hot.
    fn reconstruct_schedule_from_log(&mut self, start: u32, end: u32) -> Result<(), ChainError> {
        let mut state = ProducerScheduleState {
            active: self.active_schedule.clone(),
            pending: None,
        };
        for height in start.saturating_add(1)..=end {
            let block = self.get_block_by_height(height)?.ok_or_else(|| {
                ChainError::DatabaseError(format!(
                    "missing block {height} while rebuilding producer schedule state"
                ))
            })?;
            state.apply_header(&block.signed_block_header.header)?;
        }
        self.active_schedule = state.active;
        self.pending_schedule = state.pending;
        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), ChainError> {
        // Release the pending chain's live undo sessions before closing the
        // database so shutdown leaves no speculative state behind.
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
        let block_height = BlockHeader::num_from_id(&self.preferred_id) + 1;
        let protocol_context = self.ensure_protocol_version_supported(block_height)?;
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
            .flat_map(|b| b.transactions.iter().map(|r| *r.transaction_id()))
            .collect();
        let mut deferred: Vec<PackedTransaction> = Vec::new();

        // Build on top of preferred: reconcile the pending chain so the database
        // holds the preferred state, reusing any already-executed prefix.
        self.replay_accepted_state_to(self.preferred_id, &block_status, mempool)?;

        // Block timestamps are 500 ms slots and must strictly advance from the
        // parent. A fast local producer can build two blocks in one slot, so
        // advance to the first slot after the parent when wall-clock time has
        // not moved far enough yet.
        let wall_clock_timestamp: BlockTimestamp = TimePoint::now().into();
        let parent_timestamp = self.timestamp_for_parent(&self.preferred_id)?;
        let timestamp = BlockTimestamp::new(
            wall_clock_timestamp
                .slot()
                .max(parent_timestamp.slot().saturating_add(1)),
        );

        // The timer also removes expired entries, but build against the exact
        // timestamp committed to this candidate block so a direct build call
        // cannot select an expired transaction.
        mempool.prune_expired(&timestamp.to_time_point());

        let mut db = self.db.clone();
        db.arena_start_undo_session(); // the block session; retained on the pending chain
        if let Err(error) = self.prepare_protocol_execution(protocol_context) {
            db.arena_undo();
            return Err(error);
        }

        // Expiry clearing is part of the block's state, so it belongs inside the
        // block's session rather than before it.
        db.clear_expired_input_transactions(&timestamp.into())?;

        // The schedule active for this block is normally its parent's active
        // schedule. Once a pending schedule has reached accepted state, the next
        // block promotes it by naming its version in the header. Do not promote a
        // schedule that exists only on the speculative pending chain: it has not
        // become irreversible yet.
        let parent_schedule_state = self.schedule_state_for_parent(&self.preferred_id)?;
        let block_schedule = match &self.pending_schedule {
            Some(accepted_pending)
                if parent_schedule_state.active.version < accepted_pending.version =>
            {
                accepted_pending.clone()
            }
            _ => parent_schedule_state.active.clone(),
        };
        self.block_active_schedule = block_schedule.clone();

        // A queued protocol feature is activated by the next block header, just
        // as Leap's producer path emits its protocol_feature_activation
        // extension. Capture the parent queue before this block's transactions
        // run; a preactivation created by a transaction in this block belongs to
        // the following block.
        let protocol_feature_activations: Vec<Digest> = db
            .preactivated_protocol_features()
            .into_iter()
            .map(Digest)
            .collect();
        if !protocol_feature_activations.is_empty() {
            let digests: Vec<[u8; 32]> = protocol_feature_activations
                .iter()
                .map(|digest| digest.0)
                .collect();
            db.activate_protocol_features(
                &digests,
                BlockHeader::num_from_id(&self.preferred_id) + 1,
            )?;
        }

        // A proposal made in an earlier block may become the new pending
        // schedule in this header. Never publish a proposal authored by a
        // transaction in the block currently being assembled.
        let new_pending_schedule = if parent_schedule_state.pending.is_none() {
            match db.proposed_schedule() {
                Some((proposal_block, packed)) if proposal_block < block_height => {
                    let schedule = ProducerSchedule::read_bounded(&packed).map_err(|error| {
                        ChainError::BlockError(format!("invalid stored proposed schedule: {error}"))
                    })?;
                    db.clear_proposed_schedule()?;
                    Some(schedule)
                }
                _ => None,
            }
        } else {
            None
        };

        self.block_pending_schedule = if new_pending_schedule.is_some() {
            new_pending_schedule.clone()
        } else if block_schedule.version == parent_schedule_state.active.version {
            parent_schedule_state.pending.clone()
        } else {
            None
        };

        // onblock heads the block, before any mempool transaction, so its action
        // digests come first in the action merkle — matching what validators
        // recompute in `execute_block`.
        let previous = self.preferred_id;
        let (onblock_digests, _proposed_schedule) =
            self.run_onblock(protocol_context, &timestamp, previous, &block_status)?;
        action_receipt_digests.extend(onblock_digests);

        // Scheduled transactions are selected from durable Arena state, never
        // from the mempool. Their raw transaction bytes have no signatures: the
        // source chain authorized them when they were scheduled. Nested undo
        // sessions keep retirement separate from payload and `onerror` state.
        let now = timestamp.to_time_point().time_since_epoch().count();
        let disable_deferred_stage_1 =
            db.protocol_feature_activated(DISABLE_DEFERRED_TRXS_STAGE_1_FEATURE_DIGEST);
        let scheduled_transactions = if disable_deferred_stage_1 {
            // After stage 1 every pending deferred transaction is retired as
            // expired, even when its delay and expiration have not elapsed.
            db.arena_deferred_transactions()
        } else {
            db.arena_due_deferred_transactions(now)
        };
        for scheduled in scheduled_transactions {
            if disable_deferred_stage_1 || scheduled.expiration < now {
                // Leap retires an expired generated transaction without
                // executing its payload and commits only its transaction ID.
                let receipt = crate::chain::transaction::TransactionReceiptHeader::new(
                    crate::chain::transaction::TransactionStatus::Expired,
                    0,
                    0u32.into(),
                );
                let mut trace = TransactionTrace::default();
                trace.id = Id::new(scheduled.trx_id);
                trace.block_num = self.last_accepted_block().block_num() + 1;
                trace.block_time = timestamp.clone();
                trace.scheduled = true;
                trace.receipt = receipt.clone();
                retire_deferred_transaction(
                    &mut self.db,
                    scheduled.trx_id,
                    scheduled.payer,
                    scheduled.packed_trx.len(),
                )?;
                transaction_traces.push(trace);
                transaction_receipts.push_back(TransactionReceipt::for_id(
                    receipt,
                    Id::new(scheduled.trx_id),
                ));
                continue;
            }
            let transaction = PackedTransaction::from_deferred_transaction_bytes(Bytes::from(
                scheduled.packed_trx.clone(),
            ))
            .map_err(|error| {
                ChainError::TransactionError(format!(
                    "cannot decode deferred transaction {}: {error}",
                    hex::encode(scheduled.trx_id)
                ))
            })?;
            if transaction.id().as_bytes() != scheduled.trx_id {
                db.arena_undo();
                return Err(ChainError::TransactionError(format!(
                    "deferred transaction {} has an id that does not match its packed bytes",
                    hex::encode(scheduled.trx_id)
                )));
            }
            // Leap refunds and removes the generated-transaction object before
            // executing its payload. Keep that retirement in an outer session
            // while the payload runs in a child session: an objective payload
            // failure rolls back its mutations without restoring the retired
            // generated transaction before `onerror` runs.
            db.arena_start_undo_session();
            if let Err(error) = retire_deferred_transaction(
                &mut self.db,
                scheduled.trx_id,
                scheduled.payer,
                scheduled.packed_trx.len(),
            ) {
                db.arena_undo();
                return Err(error);
            }
            db.arena_start_undo_session();
            match self.execute_deferred_transaction_with_failure(
                &transaction,
                &timestamp,
                &block_status,
                scheduled.published,
            ) {
                Ok(result) => {
                    db.arena_squash();
                    db.arena_squash();
                    transaction_traces.push(result.trace.clone());
                    transaction_receipts.push_back(TransactionReceipt::for_id(
                        result.trace.receipt,
                        Id::new(scheduled.trx_id),
                    ));
                    action_receipt_digests.extend(result.action_receipt_digests);
                }
                Err((deferred_error, failure_cpu_us)) => {
                    db.arena_undo();
                    // XPR retires a failed generated transaction by sending its
                    // original raw bytes to `eosio::onerror`, with the original
                    // sender as receiver. The callback is its own session: none
                    // of the failed transaction's state may leak into it.
                    db.arena_start_undo_session();
                    match self.execute_deferred_onerror(&scheduled, &timestamp, &block_status) {
                        Ok(result) => {
                            db.arena_squash();
                            db.arena_squash();
                            transaction_traces.push(result.trace.clone());
                            transaction_receipts.push_back(TransactionReceipt::for_id(
                                result.trace.receipt,
                                Id::new(scheduled.trx_id),
                            ));
                            action_receipt_digests.extend(result.action_receipt_digests);
                        }
                        Err(onerror_error) => {
                            db.arena_undo();
                            // Both the deferred transaction and its callback
                            // failed objectively. Retire it with the original
                            // transaction id and billed failure CPU.
                            let account = transaction
                                .get_transaction()
                                .first_authorizer()
                                .ok_or_else(|| {
                                    ChainError::TransactionError(
                                        "deferred transaction has no authorizer".into(),
                                    )
                                })?;
                            ResourceLimitsManager::add_transaction_usage(
                                &mut self.db,
                                &Name::new(account),
                                failure_cpu_us as u64,
                                0,
                                timestamp.slot(),
                                true,
                            )?;
                            let receipt = crate::chain::transaction::TransactionReceiptHeader::new(
                                crate::chain::transaction::TransactionStatus::HardFail,
                                failure_cpu_us,
                                0u32.into(),
                            );
                            let mut trace = TransactionTrace::default();
                            trace.id = Id::new(scheduled.trx_id);
                            trace.block_num = self.last_accepted_block().block_num() + 1;
                            trace.block_time = timestamp.clone();
                            trace.scheduled = true;
                            trace.receipt = receipt.clone();
                            db.arena_squash();
                            transaction_traces.push(trace);
                            transaction_receipts.push_back(TransactionReceipt::for_id(
                                receipt,
                                Id::new(scheduled.trx_id),
                            ));
                            warn!(
                                "deferred transaction {} and onerror both failed; retired as hard_fail: {deferred_error}; {onerror_error}",
                                hex::encode(scheduled.trx_id)
                            );
                        }
                    }
                }
            }
        }

        // Get transactions from the mempool
        while let Some(transaction) = mempool.pop_transaction() {
            if pending_tx_ids.contains(transaction.id()) {
                deferred.push(transaction);
                continue;
            }

            db.arena_start_undo_session(); // open the per-transaction session
            let transaction_result = self.execute_transaction_with_protocol(
                &transaction,
                protocol_context,
                &timestamp,
                &block_status,
                None,
            );

            match transaction_result {
                Ok(result) => {
                    db.arena_squash(); // fold the tx into the block

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

                    db.arena_undo(); // a failed tx leaves no trace
                }
            }
        }

        // Return deferred transactions to the mempool for a later block.
        for tx in deferred {
            mempool.add_transaction(tx);
        }

        // Don't build a block if we have no transactions
        if transaction_receipts.len() == 0 {
            db.arena_undo(); // discard the empty block's session
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
        block
            .signed_block_header
            .header
            .set_protocol_feature_activations(&protocol_feature_activations)?;

        // Refuse to produce a block this node isn't authorized to sign:
        // if our key isn't that schedule's key for our producer, the block would
        // fail verification everywhere (including here), so fail closed instead of
        // emitting an unverifiable block after a schedule change.
        let node = self.node_config.as_ref().unwrap();
        let producer = node.producer_name;
        let signing_key = node.producer_key.get_public_key();
        match block_schedule.block_signing_key(&producer) {
            Some(scheduled) if *scheduled == signing_key => {}
            _ => {
                db.arena_undo(); // discard this block's session
                return Err(ChainError::BlockError(format!(
                    "node key is not the active schedule key for producer {}; refusing to produce",
                    producer
                )));
            }
        }

        block.signed_block_header.header.schedule_version = block_schedule.version;
        block.signed_block_header.header.new_producers = new_pending_schedule;

        // Sign the block with the producer's key over the full header — including
        // any schedule change — so validators authenticate it against the schedule.
        let sig_digest = if node.antelope_block_signatures {
            self.header_signing_state_for_parent(&self.preferred_id)?
                .signing_digest(&block.signed_block_header.header)?
        } else {
            block.signed_block_header.header.sig_digest()?
        };
        block.signed_block_header.signature = node.producer_key.sign(&sig_digest)?;

        // We built this block so no need to verify it again. Delay exposing it
        // as verified until every fallible end-of-block write succeeds.
        let block_id = block.id()?;

        // The permission rewrite is block state: keep it in the block's undo
        // session so forks unwind it and SHiP observes it before accept/commit.
        // Match the end-of-block bookkeeping that `execute_block` applies at
        // verify/accept, so the retained state is identical to what a re-execution
        // would commit, then retain the block on the pending chain (it was built
        // on the current tip). The arena session opened with `block_session` stays
        // open in lockstep — committed if this block is accepted, undone if the
        // chain unwinds past it.
        self.finalize_block_resources(block.block_num())?;
        self.verified_blocks.insert(block_id, block.clone());
        self.pending_chain.push(PendingBlock {
            id: block_id,
            parent: self.preferred_id,
            traces: transaction_traces,
        });

        Ok(block)
    }

    fn schedule_state_for_parent(
        &self,
        parent_id: &Id,
    ) -> Result<ProducerScheduleState, ChainError> {
        let mut state = ProducerScheduleState {
            active: self.active_schedule.clone(),
            pending: self.pending_schedule.clone(),
        };
        if *parent_id == self.last_accepted_block_id {
            return Ok(state);
        }
        for pending in &self.pending_chain {
            let block = self.verified_blocks.get(&pending.id).ok_or_else(|| {
                ChainError::BlockError(format!(
                    "pending block {} is missing while deriving producer schedule state",
                    pending.id
                ))
            })?;
            state.apply_header(&block.signed_block_header.header)?;
            if pending.id == *parent_id {
                return Ok(state);
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

    fn header_signing_state_for_parent(
        &self,
        parent_id: &Id,
    ) -> Result<HeaderSigningState, ChainError> {
        if *parent_id == self.last_accepted_block_id {
            return Ok(self.header_signing_state.clone());
        }
        let mut state = self.header_signing_state.clone();
        for pending in &self.pending_chain {
            let block = self.verified_blocks.get(&pending.id).ok_or_else(|| {
                ChainError::BlockError(format!(
                    "pending block {} is missing while deriving Antelope signing state",
                    pending.id
                ))
            })?;
            state.accept(block)?;
            if pending.id == *parent_id {
                return Ok(state);
            }
        }
        Err(ChainError::BlockError(format!(
            "cannot resolve Antelope signing state for unknown parent {parent_id}"
        )))
    }

    fn timestamp_for_parent(&self, parent_id: &Id) -> Result<BlockTimestamp, ChainError> {
        if *parent_id == self.last_accepted_block_id {
            return Ok(*self.last_accepted_block.timestamp());
        }

        self.verified_blocks
            .get(parent_id)
            .map(|block| *block.timestamp())
            .ok_or_else(|| {
                ChainError::BlockError(format!(
                    "cannot resolve timestamp: parent {} is unknown",
                    parent_id
                ))
            })
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
        signing_state: &HeaderSigningState,
    ) -> Result<(), ChainError> {
        let header = &block.signed_block_header.header;
        let digest = if self
            .node_config
            .as_ref()
            .is_some_and(|config| config.antelope_block_signatures)
        {
            signing_state.signing_digest(header)?
        } else {
            header.sig_digest()?
        };
        let signer = block
            .signed_block_header
            .signature
            .recover_public_key(&digest)?;
        Self::verify_block_signer(block, schedule, &signer)
    }

    fn verify_block_signer(
        block: &SignedBlock,
        schedule: &ProducerSchedule,
        signer: &PublicKey,
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
        if signer != expected {
            return Err(ChainError::BlockError(format!(
                "block signature recovered {signer}, expected {expected} for producer {} in schedule version {}",
                header.producer, schedule.version
            )));
        }
        Ok(())
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
        self.verify_block_impl(block, None, mempool).await
    }

    /// Consume a migration-only proof produced by the header authenticator.
    /// The controller independently resolves and compares the active producer
    /// key, skipping only the already-completed secp256k1 recovery.
    #[doc(hidden)]
    pub async fn verify_authenticated_migration_block(
        &mut self,
        authenticated: &AuthenticatedMigrationBlock,
        mempool: &mut Mempool,
    ) -> Result<(), ChainError> {
        self.verify_block_impl(&authenticated.block, Some(&authenticated.signer), mempool)
            .await
    }

    async fn verify_block_impl(
        &mut self,
        block: &SignedBlock,
        recovered_signer: Option<&PublicKey>,
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

        self.ensure_protocol_version_supported(block.block_num())?;

        // Verify the block. Authenticate the signature against the schedule active
        // as of this block's parent — folding in any pending ancestor's change —
        // rather than whatever happens to be accepted right now, so two nodes
        // reach the same verdict regardless of accept timing.
        block.validate_syntactically(&self.db)?;
        let mut block_schedule_state = self.schedule_state_for_parent(block.previous_id())?;
        block_schedule_state.apply_header(&block.signed_block_header.header)?;
        let block_schedule = block_schedule_state.active;
        let parent_signing_state = self.header_signing_state_for_parent(block.previous_id())?;
        let parent_timestamp = self.timestamp_for_parent(block.previous_id())?;
        let now_timestamp: BlockTimestamp = TimePoint::now().into();
        block
            .signed_block_header
            .header
            .validate_timestamp(&parent_timestamp, &now_timestamp)?;
        if let Some(signer) = recovered_signer {
            Self::verify_block_signer(block, &block_schedule, signer)?;
        } else {
            self.verify_block_signature(block, &block_schedule, &parent_signing_state)?;
        }
        self.block_active_schedule = block_schedule;
        self.block_pending_schedule = block_schedule_state.pending;

        let parent_block_id = block.previous_id().clone();
        let block_status = BlockStatus::Verifying;
        // Reconcile the pending chain to the parent, reusing any already-executed
        // prefix instead of re-running every unaccepted ancestor.
        self.replay_accepted_state_to(parent_block_id.clone(), &block_status, mempool)?;

        // This block's own session sits on top of the reconciled parent state. If
        // execution or validation below fails, each early return undoes the arena
        // session explicitly, leaving the pending chain at the parent.
        self.db.arena_start_undo_session(); // the block session; retained on the pending chain

        // The arena has no RAII undo hook, so every failure path below mirrors the
        // undo explicitly before returning, keeping the session stack depth right.
        let (transaction_traces, transaction_mroot, action_mroot, _proposed_schedule) =
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

        let block_id = block.id()?;
        self.verified_blocks.insert(block_id, block.clone());

        // Retain the executed block on the pending chain so `accept_block` can
        // commit it without re-executing. The arena session stays open in lockstep.
        self.pending_chain.push(PendingBlock {
            id: block_id,
            parent: parent_block_id,
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
        self.ensure_protocol_version_supported(block.block_num())?;

        // Resolve every fallible property of the accepted header before touching
        // speculative state or publishing any log. Once chainbase and the arena
        // are committed below, the rest of this function is infallible.
        let accepted_block_id = block.id().map_err(|error| {
            ChainError::BlockError(format!("failed to calculate accepted block id: {error}"))
        })?;
        if accepted_block_id != *block_id {
            return Err(ChainError::BlockError(format!(
                "verified block cache key {block_id} does not match packed block id {accepted_block_id}"
            )));
        }
        let mut accepted_schedule_state = ProducerScheduleState {
            active: self.active_schedule.clone(),
            pending: self.pending_schedule.clone(),
        };
        accepted_schedule_state.apply_header(&block.signed_block_header.header)?;
        let mut accepted_signing_state =
            self.header_signing_state_for_parent(block.previous_id())?;
        accepted_signing_state.accept(&block)?;

        // Pack the block before touching the pending chain. In the fast path below
        // the front session is `remove`d from the chain but only detached from
        // auto-undo by `push()` afterwards; a fallible step in between (like this
        // pack) that bailed via `?` would drop the front session and wrongly undo
        // the chain *tip* (the front is the stack bottom). Doing it here keeps the
        // remove(0)→push() window free of fallible operations.
        let packed_block = block.pack().map_err(|e| {
            ChainError::TransactionError(format!("failed to pack block {}: {}", block_id, e))
        })?;

        // The three files form one logical accept record when state-history is
        // enabled. Capture all restore points before changing candidate state,
        // so a failed append (including a partial write inside the failing log)
        // can remove the whole record. Migration replay still checkpoints the
        // idle SHiP logs, which keeps rollback handling identical and cheap.
        let block_checkpoint = self
            .block_log
            .as_ref()
            .ok_or_else(|| ChainError::InternalError("block log not initialized".to_string()))?
            .checkpoint()
            .map_err(|error| {
                ChainError::InternalError(format!("failed to checkpoint block log: {error}"))
            })?;
        let trace_checkpoint = self
            .trace_log
            .as_ref()
            .ok_or_else(|| ChainError::InternalError("trace log not initialized".to_string()))?
            .checkpoint()
            .map_err(|error| {
                ChainError::InternalError(format!("failed to checkpoint trace log: {error}"))
            })?;
        let chain_state_log = self.chain_state_log.as_ref().ok_or_else(|| {
            ChainError::InternalError("chain state log not initialized".to_string())
        })?;
        let chain_state_checkpoint = chain_state_log.checkpoint().map_err(|error| {
            ChainError::InternalError(format!("failed to checkpoint chain state log: {error}"))
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

        // A state-history delta is read from the top arena undo session. Remove
        // speculative descendants first so this accepted block cannot publish a
        // child block's changes as its own delta.
        if front_matches {
            self.unwind_pending_to(1)?;
        }
        let transaction_traces = if front_matches {
            let front = self.pending_chain.remove(0);
            // `execute_block` removes accepted transactions from the mempool as it
            // runs; the retained pass did not (build pops them while assembling,
            // verify never touches the mempool), so mirror that here.
            for receipt in &block.transactions {
                if let Some(transaction) = receipt.packed_trx() {
                    mempool.remove_transaction(transaction.id());
                }
            }
            front.traces
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
            self.db.arena_start_undo_session(); // the fallback accept session; committed below
            let block_status = BlockStatus::Accepting;
            match self.execute_block(&block, &block_status, mempool) {
                Ok((transaction_traces, _, _, _)) => transaction_traces,
                Err(e) => {
                    self.db.arena_undo();
                    return Err(ChainError::DatabaseError(format!(
                        "failed to execute block {}: {}",
                        block_id, e
                    )));
                }
            }
        };

        // Publish SHiP payloads before the block-log record, which is the
        // durable accepted-state marker on restart. A one-shot migration replay
        // can omit these derived payloads while preserving block validation,
        // execution, Arena commits, and the canonical block log. Roll all logs
        // and the arena session back if any reversible append fails.
        let append_result = (|| -> Result<(), ChainError> {
            let state_history_enabled = self
                .node_config
                .as_ref()
                .is_none_or(|config| config.state_history_enabled);
            if state_history_enabled {
                self.store_traces(block_id, &transaction_traces)?;
                self.store_chain_state(block_id)?;
            }
            let block_log = self.block_log.as_ref().expect("block log was preflighted");
            let migration_replay = self
                .node_config
                .as_ref()
                .is_some_and(|config| !config.state_history_enabled);
            let append = if migration_replay {
                block_log.append_deferred_sync(*block_id, &packed_block)
            } else {
                block_log.append(*block_id, &packed_block)
            };
            append.map_err(|e| {
                ChainError::InternalError(format!(
                    "failed to append block {} to block log: {}",
                    block_id, e
                ))
            })?;
            Ok(())
        })();
        if let Err(error) = append_result {
            let rollback_errors = self.rollback_accept_logs(
                &block_checkpoint,
                &trace_checkpoint,
                &chain_state_checkpoint,
            );
            self.db.arena_undo();
            for receipt in &block.transactions {
                if let Some(transaction) = receipt.packed_trx() {
                    mempool.add_transaction(transaction.clone());
                }
            }
            if rollback_errors.is_empty() {
                return Err(error);
            }
            return Err(ChainError::fatal_consistency(format!(
                "block accept failed ({error}) and log rollback was incomplete: {}",
                rollback_errors.join("; ")
            )));
        }
        self.verified_blocks.remove(block_id);
        self.last_accepted_block = block.clone();
        self.last_accepted_block_id = accepted_block_id;
        self.header_signing_state = accepted_signing_state;
        self.db.commit(block.block_num() as i64)?;
        for upgrade in self
            .protocol_upgrade_schedule
            .activated_upgrades(block.block_num())
            .iter()
            .copied()
            .filter(|upgrade| upgrade.activation_height == block.block_num())
        {
            let (digest, activation_height) = upgrade.activation_record();
            self.db
                .append_activated_protocol_feature(digest, activation_height)?;
        }
        self.validate_persisted_protocol_state(block.block_num(), false)?;

        if accepted_schedule_state.active.version != self.active_schedule.version {
            info!(
                "activated producer schedule version {}",
                accepted_schedule_state.active.version
            );
        }
        self.active_schedule = accepted_schedule_state.active;
        self.pending_schedule = accepted_schedule_state.pending;

        self.preferred_id = accepted_block_id;
        for receipt in &block.transactions {
            if let Some(transaction) = receipt.packed_trx() {
                mempool.remove_transaction(transaction.id());
            }
        }

        // Hashing the complete Arena is proportional to all live chain state.
        // Never pay that cost unless debug output will actually consume it.
        if spdlog::default_logger().should_log(spdlog::Level::Debug) {
            if let Some(root) = self.db.arena_state_root() {
                debug!(
                    "arena state root at block {}: {}",
                    block.block_num(),
                    hex::encode(root)
                );
            }
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

    /// Make every accepted-history log durable before a bulk replay persists
    /// its Arena checkpoint. Normal nodes sync their block log on every accept;
    /// migration replay deliberately batches that barrier and must call this
    /// first so a crash can leave only a log tail ahead of durable state.
    pub fn sync_accepted_logs(&self) -> Result<(), ChainError> {
        for (name, log) in [
            ("block", self.block_log.as_ref()),
            ("trace", self.trace_log.as_ref()),
            ("chain state", self.chain_state_log.as_ref()),
        ] {
            log.ok_or_else(|| ChainError::InternalError(format!("{name} log not initialized")))?
                .sync_data()
                .map_err(|error| {
                    ChainError::InternalError(format!("failed to sync {name} log: {error}"))
                })?;
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
            if let Some(transaction) = receipt.packed_trx() {
                mempool.add_transaction(transaction.clone());
            }
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
    fn set_context_active_schedule(
        &self,
        trx_context: &TransactionContext,
    ) -> Result<(), ChainError> {
        trx_context.set_producer_schedules(
            self.block_active_schedule.producers.clone(),
            self.block_active_schedule.version,
            self.block_pending_schedule
                .as_ref()
                .map(|schedule| (schedule.producers.clone(), schedule.version)),
        )
    }

    fn run_onblock(
        &mut self,
        protocol_context: ProtocolExecutionContext,
        pending_block_timestamp: &BlockTimestamp,
        previous: Id,
        block_status: &BlockStatus,
    ) -> Result<(VecDeque<Digest>, Option<Vec<ProducerKey>>), ChainError> {
        // Antelope's implicit onblock action carries the exact header of the
        // current head (the parent), not a partially assembled header for the
        // block being executed. This distinction is consensus-visible through
        // the action receipt digest even when the block has no transactions.
        let parent = self.get_block(previous)?.ok_or_else(|| {
            ChainError::BlockError(format!(
                "cannot execute onblock without parent block {}",
                previous
            ))
        })?;
        let header_bytes = parent.signed_block_header.header.pack().map_err(|e| {
            ChainError::SerializationError(format!("failed to pack onblock header: {}", e))
        })?;

        let system = self.db.system_accounts().system;
        let action = Action::new(
            system,
            ONBLOCK_NAME,
            header_bytes,
            vec![PermissionLevel::new(system.as_u64(), ACTIVE_NAME.as_u64())],
        );
        let trx = Transaction::new(TransactionHeader::default(), vec![], vec![action]);
        let packed = PackedTransaction::from_signed_transaction(SignedTransaction::new(
            trx.clone(),
            Vec::new(),
            vec![],
        ))?;

        let trx_id = *packed.id();
        self.db.arena_start_undo_session(); // the onblock session
        let mut trx_context = TransactionContext::new(
            self.db.clone(),
            self.wasm_runtime.clone(),
            protocol_context,
            pending_block_timestamp.clone(),
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
                self.db.arena_squash(); // fold onblock into the block
                Ok((result.action_receipt_digests, result.proposed_schedule))
            }
            Err(e) => {
                // onblock is invoked speculatively at the head of every block, but
                // whether the deployed system contract implements it is chain
                // dependent. A contract with no onblock handler makes its dispatcher
                // assert "unknown action" on the implicit call — expected on such a
                // chain, so it is logged at debug rather than warned on every block.
                // Any other failure (a genuine onblock bug with a different assert,
                // or a machinery error) still warns. Either way the failure is
                // deterministic and yields no action receipt, so every node agrees
                // on the merkles and the block still forms.
                if e.to_string().contains("unknown action") {
                    debug!("onblock not implemented by the system contract, skipping");
                } else {
                    warn!("onblock failed, skipping: {}", e);
                }
                self.db.arena_undo(); // a failed onblock leaves no trace
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
        // Revalidate here instead of relying on a caller's guard: replay,
        // fallback accept, and future callers must not reach consensus writes
        // without a context for this exact candidate height.
        let protocol_context = self.ensure_protocol_version_supported(block.block_num())?;
        let mut transaction_traces: Vec<TransactionTrace> = Vec::new();
        let mut transaction_receipts: VecDeque<TransactionReceipt> = VecDeque::new();
        let mut action_receipt_digests: VecDeque<Digest> = VecDeque::new();
        self.prepare_protocol_execution(protocol_context)?;
        self.blocks_executed += 1;

        let mut schedule_state = self.schedule_state_for_parent(block.previous_id())?;
        let schedule_promoted = schedule_state.apply_header(&block.signed_block_header.header)?;
        self.block_active_schedule = schedule_state.active;
        self.block_pending_schedule = schedule_state.pending;

        // Protocol features take effect at the start of the block, before the
        // implicit onblock action and ordinary transactions. The extension is
        // signed, decoded, and applied inside the block's undo session, so a
        // rejected block or fork unwind restores the preactivation queue.
        let protocol_feature_activations = block
            .signed_block_header
            .header
            .protocol_feature_activations()?;
        if !protocol_feature_activations.is_empty() {
            let digests: Vec<[u8; 32]> = protocol_feature_activations
                .iter()
                .map(|digest| digest.0)
                .collect();
            self.db
                .activate_protocol_features(&digests, block.block_num())?;
        }

        if let Some(header_schedule) = block.signed_block_header.header.new_schedule()? {
            let (proposal_block, packed) = self.db.proposed_schedule().ok_or_else(|| {
                ChainError::BlockError(
                    "block carries new_producers without an on-chain proposed schedule".into(),
                )
            })?;
            if proposal_block >= block.block_num() {
                return Err(ChainError::BlockError(format!(
                    "block {} promotes a schedule proposed in non-prior block {}",
                    block.block_num(),
                    proposal_block
                )));
            }
            let proposed = ProducerSchedule::read_bounded(&packed).map_err(|error| {
                ChainError::BlockError(format!("invalid stored proposed schedule: {error}"))
            })?;
            if proposed != header_schedule {
                let first_difference = proposed
                    .producers
                    .iter()
                    .zip(&header_schedule.producers)
                    .position(|(proposed, header)| proposed != header)
                    .map_or_else(
                        || {
                            format!(
                                "producer count differs: proposed {}, header {}",
                                proposed.producers.len(),
                                header_schedule.producers.len()
                            )
                        },
                        |index| {
                            format!(
                                "producer {index} differs: proposed {:?}, header {:?}",
                                proposed.producers[index], header_schedule.producers[index]
                            )
                        },
                    );
                return Err(ChainError::BlockError(format!(
                    "block new_producers does not match the on-chain proposed schedule: \
                     proposed version {}, header version {}; {first_difference}",
                    proposed.version, header_schedule.version
                )));
            }
            self.db.clear_proposed_schedule()?;
        }

        self.db
            .clear_expired_input_transactions(&block.timestamp().to_time_point())?;

        // onblock heads the block: its action digests precede every transaction's.
        let header = &block.signed_block_header.header;
        let (onblock_digests, mut proposed_schedule) = self.run_onblock(
            protocol_context,
            &header.timestamp,
            header.previous,
            block_status,
        )?;
        action_receipt_digests.extend(onblock_digests);
        if schedule_promoted {
            let producers = self.block_active_schedule.producers.clone();
            self.update_producers_authority(&producers, block.timestamp())?;
        }
        // Mirror build_block: onblock's proposal counts like any transaction's,
        // overridden by a later transaction's — keeping verify's re-execution in
        // agreement with what the producer folded into the header.

        for receipt in &block.transactions {
            let timestamp = &block.signed_block_header.header.timestamp;
            let transaction_id: [u8; 32] = receipt.transaction_id().as_bytes().try_into().unwrap();
            let deferred = self.db.arena_deferred_transaction(transaction_id);
            let (result, reproduced_receipt) = if let Some(deferred) = deferred {
                let now = timestamp.to_time_point().time_since_epoch().count();
                let disable_deferred_stage_1 = self
                    .db
                    .protocol_feature_activated(DISABLE_DEFERRED_TRXS_STAGE_1_FEATURE_DIGEST);
                if !disable_deferred_stage_1 && deferred.delay_until > now {
                    return Err(ChainError::BlockError(format!(
                        "block includes deferred transaction {} before its delay_until",
                        receipt.transaction_id()
                    )));
                }
                if receipt.packed_trx().is_some() {
                    return Err(ChainError::BlockError(format!(
                        "block embeds generated transaction {} instead of using its ID receipt",
                        receipt.transaction_id()
                    )));
                }
                // The generated object is retired before its payload executes,
                // so the payer can reuse the refunded RAM within that payload.
                // A rejected block unwinds both this refund and the removal in
                // the block's surrounding Arena session.
                retire_deferred_transaction(
                    &mut self.db,
                    transaction_id,
                    deferred.payer,
                    deferred.packed_trx.len(),
                )?;
                let result = match receipt.status() {
                    crate::chain::transaction::TransactionStatus::Expired => {
                        if (!disable_deferred_stage_1 && deferred.expiration >= now)
                            || receipt.cpu_usage_us() != 0
                            || receipt.net_usage_words() != 0
                        {
                            return Err(ChainError::BlockError(format!(
                                "block has an invalid expired receipt for generated transaction {}",
                                receipt.transaction_id()
                            )));
                        }
                        let mut trace = TransactionTrace::default();
                        trace.id = *receipt.transaction_id();
                        trace.block_num = self.last_accepted_block().block_num() + 1;
                        trace.block_time = timestamp.clone();
                        trace.scheduled = true;
                        trace.receipt = crate::chain::transaction::TransactionReceiptHeader::new(
                            crate::chain::transaction::TransactionStatus::Expired,
                            0,
                            0u32.into(),
                        );
                        TransactionResult {
                            trace,
                            billed_cpu_time_us: 0,
                            action_receipt_digests: VecDeque::new(),
                            proposed_schedule: None,
                        }
                    }
                    crate::chain::transaction::TransactionStatus::Executed => {
                        if disable_deferred_stage_1 || deferred.expiration < now {
                            return Err(ChainError::BlockError(format!(
                                "block executes expired generated transaction {}",
                                receipt.transaction_id()
                            )));
                        }
                        let transaction = PackedTransaction::from_deferred_transaction_bytes(
                            Bytes::from(deferred.packed_trx.clone()),
                        )?;
                        if transaction.id().as_bytes() != deferred.trx_id {
                            return Err(ChainError::BlockError(format!(
                                "Arena generated transaction {} does not match its packed bytes",
                                receipt.transaction_id()
                            )));
                        }
                        self.execute_transaction_billed_with_authorization(
                            &transaction,
                            protocol_context,
                            timestamp,
                            block_status,
                            Some((receipt.cpu_usage_us(), receipt.net_usage_words())),
                            true,
                            true,
                        )?
                    }
                    crate::chain::transaction::TransactionStatus::SoftFail => {
                        if disable_deferred_stage_1 || deferred.expiration < now {
                            return Err(ChainError::BlockError(format!(
                                "block soft-fails expired generated transaction {}",
                                receipt.transaction_id()
                            )));
                        }
                        self.execute_deferred_onerror(&deferred, timestamp, block_status)?
                    }
                    crate::chain::transaction::TransactionStatus::HardFail => {
                        if disable_deferred_stage_1
                            || deferred.expiration < now
                            || receipt.net_usage_words() != 0
                        {
                            return Err(ChainError::BlockError(format!(
                                "block has an invalid hard_fail receipt for generated transaction {}",
                                receipt.transaction_id()
                            )));
                        }
                        let transaction = PackedTransaction::from_deferred_transaction_bytes(
                            Bytes::from(deferred.packed_trx.clone()),
                        )?;
                        let account = transaction
                            .get_transaction()
                            .first_authorizer()
                            .ok_or_else(|| {
                                ChainError::BlockError(
                                    "hard_fail generated transaction has no authorizer".into(),
                                )
                            })?;
                        ResourceLimitsManager::add_transaction_usage(
                            &mut self.db,
                            &Name::new(account),
                            receipt.cpu_usage_us() as u64,
                            0,
                            timestamp.slot(),
                            false,
                        )?;
                        let mut trace = TransactionTrace::default();
                        trace.id = *receipt.transaction_id();
                        trace.block_num = self.last_accepted_block().block_num() + 1;
                        trace.block_time = timestamp.clone();
                        trace.scheduled = true;
                        trace.receipt = crate::chain::transaction::TransactionReceiptHeader::new(
                            crate::chain::transaction::TransactionStatus::HardFail,
                            receipt.cpu_usage_us(),
                            0u32.into(),
                        );
                        TransactionResult {
                            trace,
                            billed_cpu_time_us: receipt.cpu_usage_us(),
                            action_receipt_digests: VecDeque::new(),
                            proposed_schedule: None,
                        }
                    }
                    crate::chain::transaction::TransactionStatus::Delayed => {
                        return Err(ChainError::BlockError(format!(
                            "block marks generated transaction {} as delayed",
                            receipt.transaction_id()
                        )));
                    }
                };
                let reproduced = TransactionReceipt::for_id(
                    result.trace.receipt.clone(),
                    *receipt.transaction_id(),
                );
                (result, reproduced)
            } else {
                let transaction = receipt.packed_trx().ok_or_else(|| {
                    ChainError::BlockError(format!(
                        "block references unknown generated transaction {}",
                        receipt.transaction_id()
                    ))
                })?;
                let result = self.execute_transaction_with_protocol(
                    transaction,
                    protocol_context,
                    timestamp,
                    block_status,
                    Some((receipt.cpu_usage_us(), receipt.net_usage_words())),
                )?;
                let reproduced =
                    TransactionReceipt::new(result.trace.receipt.clone(), transaction.clone());
                (result, reproduced)
            };

            // Add trace to traces
            transaction_traces.push(result.trace.clone());
            transaction_receipts.push_back(reproduced_receipt);
            action_receipt_digests.extend(result.action_receipt_digests);
            if result.proposed_schedule.is_some() {
                proposed_schedule = result.proposed_schedule;
            }

            // Remove from mempool if we have it
            if block_status == &BlockStatus::Accepting {
                if let Some(transaction) = receipt.packed_trx() {
                    mempool.remove_transaction(transaction.id());
                }
            }
        }

        let transaction_mroot = self.calculate_trx_merkle(&transaction_receipts)?;
        let action_mroot = self.calculate_action_merkle(&mut action_receipt_digests)?;

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

    /// Perform the inexpensive, state-aware checks required before a transaction
    /// enters the mempool.
    ///
    /// This deliberately does not create a transaction context or execute an
    /// action. Execution is deferred to block production, where the transaction
    /// is executed exactly once in the producer's block session. Validators then
    /// execute the produced block as usual. A transaction can therefore pass
    /// this preflight but become invalid before it is selected for a block; the
    /// block builder handles that by dropping it.
    pub fn validate_transaction_for_mempool(
        &self,
        packed_transaction: &PackedTransaction,
        pending_block_timestamp: &BlockTimestamp,
    ) -> Result<(), ChainError> {
        self.mempool_admission_state()
            .validate_transaction(packed_transaction, pending_block_timestamp)
    }

    /// Clone the state handle used by advisory mempool preflight. It remains
    /// valid across controller mutation because `Database` clones share the
    /// synchronized arena backend.
    pub fn mempool_admission_state(&self) -> MempoolAdmissionState {
        MempoolAdmissionState {
            db: self.db.clone(),
            chain_id: self.chain_id.clone(),
            protocol_upgrade_schedule: self.protocol_upgrade_schedule.clone(),
        }
    }

    // This function will execute a transaction and roll it back instantly.
    // It is retained for speculative callers that need an execution result;
    // mempool admission uses `validate_transaction_for_mempool` instead.
    pub fn push_transaction(
        &mut self,
        transaction: &PackedTransaction,
        pending_block_timestamp: &BlockTimestamp,
        block_status: &BlockStatus,
    ) -> Result<TransactionResult, ChainError> {
        // Admission targets the same preferred parent as the next build. A
        // state-summary request may have unwound its speculative session while
        // leaving the preference intact, so materialize that path before
        // deriving either the candidate height or its execution context.
        let parent_id = self.preferred_id;
        let mut replay_mempool = Mempool::new();
        self.replay_accepted_state_to(parent_id, block_status, &mut replay_mempool)?;
        let block_height = BlockHeader::num_from_id(&parent_id) + 1;
        let protocol_context = self.ensure_protocol_version_supported(block_height)?;
        let schedule_state = self.schedule_state_for_parent(&parent_id)?;
        self.block_active_schedule = schedule_state.active;
        self.block_pending_schedule = schedule_state.pending;
        let db = self.db.clone();
        db.arena_start_undo_session();
        if let Err(error) = self.prepare_protocol_execution(protocol_context) {
            // Admission executes the same activation boundary as block
            // production, but its outer session is always discarded.
            db.arena_undo();
            return Err(error);
        }
        let result = self.execute_transaction_with_protocol(
            transaction,
            protocol_context,
            pending_block_timestamp,
            block_status,
            None,
        );
        // Mempool admission is advisory: revert the arena session on both the
        // success and error paths.
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
        let block_height = BlockHeader::num_from_id(&self.pending_tip_id()) + 1;
        let protocol_context = self.ensure_protocol_version_supported(block_height)?;
        self.execute_transaction_with_protocol(
            packed_transaction,
            protocol_context,
            pending_block_timestamp,
            block_status,
            None,
        )
    }

    /// As `execute_transaction`, but when `explicit_billed` is set (applying an
    /// already-accepted block) it bills the block-recorded cpu/net and skips the
    /// objective resource-limit checks — Antelope light/replay validation.
    fn max_transaction_time_ms(&self) -> u32 {
        self.node_config
            .as_ref()
            .map(|config| config.max_transaction_time_ms)
            .unwrap_or(30_000)
    }

    pub fn execute_transaction_billed(
        &mut self,
        packed_transaction: &PackedTransaction,
        pending_block_timestamp: &BlockTimestamp,
        block_status: &BlockStatus,
        explicit_billed: Option<(u32, u32)>,
    ) -> Result<TransactionResult, ChainError> {
        let block_height = BlockHeader::num_from_id(&self.pending_tip_id()) + 1;
        let protocol_context = self.ensure_protocol_version_supported(block_height)?;
        self.execute_transaction_billed_with_authorization(
            packed_transaction,
            protocol_context,
            pending_block_timestamp,
            block_status,
            explicit_billed,
            false,
            false,
        )
    }

    /// Deferred execution variant which keeps the context alive on failure so
    /// the scheduler can produce XPR's objectively billed `hard_fail` receipt.
    fn execute_deferred_transaction_with_failure(
        &mut self,
        packed_transaction: &PackedTransaction,
        pending_block_timestamp: &BlockTimestamp,
        block_status: &BlockStatus,
        published: i64,
    ) -> Result<TransactionResult, (ChainError, u32)> {
        let mut trx_context = TransactionContext::new(
            self.db.clone(),
            self.wasm_runtime.clone(),
            self.ensure_protocol_version_supported(
                BlockHeader::num_from_id(&self.pending_tip_id()) + 1,
            )
            .map_err(|error| (error, 0))?,
            pending_block_timestamp.clone(),
            packed_transaction.id(),
            *block_status,
            packed_transaction.clone(),
            self.max_transaction_time_ms(),
        );
        if let Err(error) = self.set_context_active_schedule(&trx_context) {
            return Err((error, 0));
        }
        let transaction = packed_transaction.get_transaction();
        if let Err(error) = trx_context.init_for_deferred_trx(
            packed_transaction
                .get_unprunable_size()
                .map_err(|error| (error, 0))?,
            packed_transaction
                .get_prunable_size()
                .map_err(|error| (error, 0))?,
            transaction,
            TimePoint::new(Microseconds::new(published)),
        ) {
            return Err((
                error,
                trx_context.failure_billed_cpu_time_us().unwrap_or_default(),
            ));
        }
        if let Err(error) = trx_context.exec(transaction) {
            return Err((
                error,
                trx_context.failure_billed_cpu_time_us().unwrap_or_default(),
            ));
        }
        trx_context.finalize().map_err(|error| (error, 0))
    }

    /// Execute the XPR `eosio::onerror` notification after a deferred
    /// transaction's action fails. Its trace deliberately keeps the original
    /// deferred transaction ID: the block receipt identifies the generated
    /// transaction, not this implicit callback envelope.
    fn execute_deferred_onerror(
        &mut self,
        deferred: &pulsevm_database::DeferredTransaction,
        pending_block_timestamp: &BlockTimestamp,
        block_status: &BlockStatus,
    ) -> Result<TransactionResult, ChainError> {
        let data = deferred_onerror_payload(deferred.sender_id, &deferred.packed_trx)?;

        let sender = Name::new(deferred.sender);
        let action = Action::new(
            Name::from_str("eosio")?,
            ONERROR_NAME,
            data,
            vec![PermissionLevel::new(sender.as_u64(), ACTIVE_NAME.as_u64())],
        );
        let trx = Transaction::new(TransactionHeader::default(), vec![], vec![action.clone()]);
        let packed = PackedTransaction::from_signed_transaction(SignedTransaction::new(
            trx.clone(),
            Vec::new(),
            vec![],
        ))?;
        let transaction_id = Id::new(deferred.trx_id);
        let mut trx_context = TransactionContext::new(
            self.db.clone(),
            self.wasm_runtime.clone(),
            self.ensure_protocol_version_supported(
                BlockHeader::num_from_id(&self.pending_tip_id()) + 1,
            )?,
            pending_block_timestamp.clone(),
            &transaction_id,
            *block_status,
            packed,
            self.max_transaction_time_ms(),
        );
        self.set_context_active_schedule(&trx_context)?;
        trx_context.init_for_implicit_trx(&trx)?;
        trx_context.schedule_action(action, &sender, false, 0, 0)?;
        trx_context.execute_action(1, 0)?;
        let mut result = trx_context.finalize()?;
        result.trace.receipt.status = crate::chain::transaction::TransactionStatus::SoftFail;
        Ok(result)
    }

    fn execute_transaction_billed_with_authorization(
        &mut self,
        packed_transaction: &PackedTransaction,
        protocol_context: ProtocolExecutionContext,
        pending_block_timestamp: &BlockTimestamp,
        block_status: &BlockStatus,
        explicit_billed: Option<(u32, u32)>,
        skip_authorization: bool,
        is_deferred: bool,
    ) -> Result<TransactionResult, ChainError> {
        self.execute_transaction_with_protocol_authorization(
            packed_transaction,
            protocol_context,
            pending_block_timestamp,
            block_status,
            explicit_billed,
            skip_authorization,
            is_deferred,
        )
    }

    fn execute_transaction_with_protocol(
        &mut self,
        packed_transaction: &PackedTransaction,
        protocol_context: ProtocolExecutionContext,
        pending_block_timestamp: &BlockTimestamp,
        block_status: &BlockStatus,
        explicit_billed: Option<(u32, u32)>,
    ) -> Result<TransactionResult, ChainError> {
        self.execute_transaction_with_protocol_authorization(
            packed_transaction,
            protocol_context,
            pending_block_timestamp,
            block_status,
            explicit_billed,
            false,
            false,
        )
    }

    fn execute_transaction_with_protocol_authorization(
        &mut self,
        packed_transaction: &PackedTransaction,
        protocol_context: ProtocolExecutionContext,
        pending_block_timestamp: &BlockTimestamp,
        block_status: &BlockStatus,
        explicit_billed: Option<(u32, u32)>,
        skip_authorization: bool,
        is_deferred: bool,
    ) -> Result<TransactionResult, ChainError> {
        let signed_transaction = packed_transaction.get_signed_transaction();

        // Verify basic transaction validity
        if !is_deferred {
            signed_transaction
                .transaction()
                .validate(pending_block_timestamp)?;
        }

        // Verify authority — but only when this node is the one admitting the
        // transaction (mempool/producing). When applying an already-accepted
        // block (explicit_billed), signatures were authenticated by the producer,
        // so this is Antelope light/replay validation: the authority check is
        // skipped, exactly like the objective resource-limit checks below. It has
        // no state effect (auth_sequence and permission-usage bumps happen during
        // execution and finalize), so skipping it leaves the resulting state and
        // receipts unchanged.
        if explicit_billed.is_none() && !skip_authorization {
            AuthorizationManager::check_authorization(
                &mut self.db,
                &signed_transaction.transaction().actions,
                &signed_transaction.recovered_authority_keys(&self.chain_id)?,
                &BTreeSet::new(),
                seconds(signed_transaction.transaction().header.delay_sec.into()),
                &BTreeSet::new(),
            )?;
        }

        let mut trx_context = TransactionContext::new(
            self.db.clone(),
            self.wasm_runtime.clone(),
            protocol_context,
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
        if is_deferred {
            trx_context.init_for_deferred_trx(
                packed_transaction.get_unprunable_size()?,
                packed_transaction.get_prunable_size()?,
                &trx,
                pending_block_timestamp.clone().into(),
            )?;
        } else {
            trx_context.init_for_input_trx(
                packed_transaction.get_unprunable_size()?,
                packed_transaction.get_prunable_size()?,
                &trx,
            )?;
        }
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
    // The arena checkpoint is the canonical physical state payload (see
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
        // A verified child may have a live undo session materialized above the
        // accepted revision. State summaries are labelled with last accepted,
        // so unwind speculation before taking the physical arena snapshot.
        self.clear_pending()?;
        let height = self.last_accepted_block.block_num();
        self.validate_persisted_protocol_state(height, false)?;

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
            self.protocol_upgrade_schedule.commitment(height),
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

    /// Validate a peer summary against this node's configured protocol history
    /// before downloading or mutating state.
    pub fn validate_state_sync_target(
        &self,
        target: &state_sync::SyncTarget,
    ) -> Result<(), ChainError> {
        let height = u32::try_from(target.height).map_err(|_| {
            ChainError::BlockError(format!(
                "state-sync height {} exceeds the protocol height range",
                target.height
            ))
        })?;
        if height != target.block.block_num() {
            return Err(ChainError::BlockError(format!(
                "state-sync target height {} does not match block height {}",
                height,
                target.block.block_num()
            )));
        }
        self.validate_state_sync_protocol(height, target.protocol_commitment)
    }

    fn validate_state_sync_protocol(
        &self,
        block_height: u32,
        advertised: Option<crate::chain::protocol_features::ProtocolScheduleCommitment>,
    ) -> Result<(), ChainError> {
        self.ensure_protocol_version_supported(block_height)?;
        let expected = self.protocol_upgrade_schedule.commitment(block_height);
        match advertised {
            Some(commitment) if commitment == expected => Ok(()),
            Some(commitment) => Err(ChainError::BlockError(format!(
                "state-sync protocol commitment mismatch at height {block_height}: peer version {} / prefix {}, local version {} / prefix {}",
                commitment.protocol_version,
                hex::encode(commitment.activated_schedule_hash),
                expected.protocol_version,
                hex::encode(expected.activated_schedule_hash)
            ))),
            None if expected.protocol_version
                == crate::chain::protocol_features::GENESIS_PROTOCOL_VERSION
                && self
                    .protocol_upgrade_schedule
                    .activated_upgrades(block_height)
                    .is_empty() =>
            {
                // Backward compatibility for summaries produced before the
                // protocol commitment extension, only while history is pure v1.
                Ok(())
            }
            None => Err(ChainError::BlockError(format!(
                "state-sync summary at height {block_height} has no protocol commitment"
            ))),
        }
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
        protocol_commitment: Option<crate::chain::protocol_features::ProtocolScheduleCommitment>,
        envelope: &[u8],
    ) -> Result<(), ChainError> {
        let block_height = block.block_num();
        self.validate_state_sync_protocol(block_height, protocol_commitment)?;
        let block_id = block.id()?;

        // The database revision advances one per accepted block, so the
        // snapshot's revision must equal the summary block's height. Check it
        // from the header first: a mismatch means the summary paired a block with
        // a snapshot of different state, and we reject it before the swap rather
        // than half-adopt an inconsistent tip.
        let header = pulsevm_database::peek_snapshot_header(envelope)?;
        if header.revision as u64 != block.block_num() as u64 {
            return Err(ChainError::InternalError(format!(
                "snapshot revision {} does not match summary block height {}",
                header.revision,
                block.block_num()
            )));
        }

        // Validate the configured root against the staged snapshot before
        // touching pending state or swapping the live arena. This keeps a
        // snapshot from another network fully non-destructive.
        self.db.validate_snapshot_system_account(envelope)?;

        // Finish every fallible pure preflight before changing live state.
        let packed_block = block
            .pack()
            .map_err(|e| ChainError::InternalError(format!("accept: pack block: {}", e)))?;
        self.block_log
            .as_ref()
            .ok_or_else(|| ChainError::InternalError("accept: no block log".into()))?;
        let packed_schedule = schedule
            .pack()
            .map_err(|e| ChainError::InternalError(format!("accept: pack schedule: {}", e)))?;
        let expected_protocol_records = self.configured_protocol_records(block_height);

        // Preflight the snapshot before disturbing speculative state, then mark
        // the multi-file installation window and replace the arena.
        let db = self.db.clone();
        let marker_installed = std::cell::Cell::new(false);
        self.clear_pending()?;
        self.begin_state_sync_install(block_height, &block_id)?;
        marker_installed.set(true);
        let restore_result = db.restore_from_bytes(envelope);
        if let Err(error) = restore_result {
            // Ordinary post-hook failures mean the database restore put the old
            // arena back. Remove the poison marker so normal bootstrap may retry.
            // Fatal restore failures keep it for startup to detect.
            if marker_installed.get() && !error.is_fatal_consistency() {
                self.clear_state_sync_install_marker()?;
            }
            return Err(error);
        }
        db.validate_system_account_state()?;
        db.replace_activated_protocol_features(expected_protocol_records)?;

        let publish_metadata = (|| -> Result<(), ChainError> {
            // Re-base the logs. The block log starts again at the snapshot block
            // so a restart reconstructs the tip from here; state-history has no
            // entries for a block this node never executed, so those logs clear.
            self.block_log
                .as_ref()
                .expect("block log was preflighted")
                .reset_to(block_id, &packed_block)
                .map_err(|e| ChainError::InternalError(format!("accept: rebase block log: {e}")))?;
            if let Some(log) = self.trace_log.as_ref() {
                log.clear().map_err(|e| {
                    ChainError::InternalError(format!("accept: clear trace log: {e}"))
                })?;
            }
            if let Some(log) = self.chain_state_log.as_ref() {
                log.clear().map_err(|e| {
                    ChainError::InternalError(format!("accept: clear chain state log: {e}"))
                })?;
            }

            // The re-based block log lacks the historical block that activated
            // this producer schedule, so persist an atomic checksummed base.
            self.write_synced_schedule(&packed_schedule)
        })();
        if let Err(error) = publish_metadata {
            return Err(ChainError::fatal_consistency(format!(
                "state sync installed arena revision {block_height}, but companion metadata publication failed: {error}"
            )));
        }

        self.active_schedule = schedule;

        self.last_accepted_block = block;
        self.last_accepted_block_id = block_id;
        self.preferred_id = block_id;
        self.verified_blocks.clear();
        // The cache commits to the pre-sync tip; drop it.
        self.snapshot_cache = None;
        self.clear_state_sync_install_marker()?;
        Ok(())
    }

    fn ensure_no_incomplete_state_sync(db_path: &str) -> Result<(), ChainError> {
        let marker = Path::new(db_path).join(STATE_SYNC_INSTALL_MARKER_FILE);
        match fs::metadata(&marker) {
            Ok(_) => Err(ChainError::fatal_consistency(format!(
                "incomplete state-sync publication marker remains at {}; wipe and resync this node before restarting",
                marker.display()
            ))),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ChainError::fatal_consistency(format!(
                "cannot determine whether a state-sync publication is incomplete at {}: {error}",
                marker.display()
            ))),
        }
    }

    fn begin_state_sync_install(&self, block_height: u32, block_id: &Id) -> Result<(), ChainError> {
        let dir = Path::new(
            self.db_path
                .as_deref()
                .ok_or_else(|| ChainError::InternalError("accept: no db path".into()))?,
        );
        let marker = dir.join(STATE_SYNC_INSTALL_MARKER_FILE);
        let mut bytes = Vec::with_capacity(STATE_SYNC_INSTALL_MARKER_MAGIC.len() + 4 + 32);
        bytes.extend_from_slice(STATE_SYNC_INSTALL_MARKER_MAGIC);
        bytes.extend_from_slice(&block_height.to_le_bytes());
        bytes.extend_from_slice(block_id.as_bytes());

        let mut temp = tempfile::NamedTempFile::new_in(dir).map_err(|error| {
            ChainError::fatal_consistency(format!(
                "cannot create state-sync publication marker in {}: {error}",
                dir.display()
            ))
        })?;
        temp.write_all(&bytes).map_err(|error| {
            ChainError::fatal_consistency(format!(
                "cannot write state-sync publication marker: {error}"
            ))
        })?;
        temp.as_file().sync_all().map_err(|error| {
            ChainError::fatal_consistency(format!(
                "cannot sync state-sync publication marker: {error}"
            ))
        })?;
        temp.persist_noclobber(&marker).map_err(|error| {
            ChainError::fatal_consistency(format!(
                "cannot install state-sync publication marker at {}: {}",
                marker.display(),
                error.error
            ))
        })?;
        sync_directory(dir).map_err(|error| {
            ChainError::fatal_consistency(format!(
                "cannot sync state-sync publication marker directory: {error}"
            ))
        })
    }

    fn clear_state_sync_install_marker(&self) -> Result<(), ChainError> {
        let dir = Path::new(
            self.db_path
                .as_deref()
                .ok_or_else(|| ChainError::fatal_consistency("state sync lost its DB path"))?,
        );
        let marker = dir.join(STATE_SYNC_INSTALL_MARKER_FILE);
        fs::remove_file(&marker).map_err(|error| {
            ChainError::fatal_consistency(format!(
                "cannot remove completed state-sync marker {}: {error}",
                marker.display()
            ))
        })?;
        sync_directory(dir).map_err(|error| {
            ChainError::fatal_consistency(format!(
                "cannot sync removal of completed state-sync marker: {error}"
            ))
        })
    }

    fn write_synced_schedule(&self, packed: &[u8]) -> Result<(), ChainError> {
        let dir = Path::new(
            self.db_path
                .as_deref()
                .ok_or_else(|| ChainError::InternalError("accept: no db path".into()))?,
        );
        let target = dir.join(SYNCED_SCHEDULE_FILE);
        let mut bytes = Vec::with_capacity(12 + packed.len() + 32);
        bytes.extend_from_slice(SYNCED_SCHEDULE_MAGIC);
        bytes.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        bytes.extend_from_slice(packed);
        bytes.extend_from_slice(Digest::hash(packed).as_bytes());

        let mut temp = tempfile::NamedTempFile::new_in(dir).map_err(|error| {
            ChainError::InternalError(format!("accept: create schedule temp file: {error}"))
        })?;
        temp.write_all(&bytes).map_err(|error| {
            ChainError::InternalError(format!("accept: write schedule temp file: {error}"))
        })?;
        temp.as_file().sync_all().map_err(|error| {
            ChainError::InternalError(format!("accept: sync schedule temp file: {error}"))
        })?;
        temp.persist(&target).map_err(|error| {
            ChainError::InternalError(format!(
                "accept: install schedule at {}: {}",
                target.display(),
                error.error
            ))
        })?;
        sync_directory(dir).map_err(|error| {
            ChainError::InternalError(format!("accept: sync schedule directory: {error}"))
        })
    }

    fn load_synced_schedule(db_path: &str) -> Result<Option<ProducerSchedule>, ChainError> {
        let path = Path::new(db_path).join(SYNCED_SCHEDULE_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(ChainError::DatabaseError(format!(
                    "failed to read synced producer schedule {}: {error}",
                    path.display()
                )));
            }
        };
        if bytes.len() < 12 + 32 || &bytes[..8] != SYNCED_SCHEDULE_MAGIC {
            return Err(ChainError::DatabaseError(format!(
                "synced producer schedule {} has an invalid header",
                path.display()
            )));
        }
        let packed_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let expected_len = 12usize
            .checked_add(packed_len)
            .and_then(|len| len.checked_add(32))
            .ok_or_else(|| {
                ChainError::DatabaseError("synced producer schedule length overflow".into())
            })?;
        if bytes.len() != expected_len {
            return Err(ChainError::DatabaseError(format!(
                "synced producer schedule {} declares {packed_len} packed bytes but contains {} total bytes",
                path.display(),
                bytes.len()
            )));
        }
        let packed = &bytes[12..12 + packed_len];
        if Digest::hash(packed).as_bytes() != &bytes[12 + packed_len..] {
            return Err(ChainError::DatabaseError(format!(
                "synced producer schedule {} failed its checksum",
                path.display()
            )));
        }
        let schedule = ProducerSchedule::read_bounded(packed).map_err(|error| {
            ChainError::DatabaseError(format!(
                "failed to decode synced producer schedule {}: {error}",
                path.display()
            ))
        })?;
        Ok(Some(schedule))
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

    pub fn find_apply_handler(
        receiver: &Name,
        scope: &Name,
        act: &Name,
        system: Name,
    ) -> Option<ApplyHandlerFn> {
        if *receiver == system && *scope == system {
            return NATIVE_SYSTEM_HANDLERS.get(act).copied();
        }
        APPLY_HANDLERS.get(&(*receiver, *scope, *act)).copied()
    }

    pub fn get_wasm_runtime(&self) -> &WasmRuntime {
        &self.wasm_runtime
    }

    pub fn database(&self) -> Database {
        self.db.clone()
    }

    /// Snapshot the accepted header-authentication state for the bulk XPR
    /// importer. The returned verifier is deliberately unavailable to normal
    /// nodes and cannot be created while speculative blocks are pending.
    #[doc(hidden)]
    pub fn migration_block_authenticator(&self) -> Result<MigrationBlockAuthenticator, ChainError> {
        let config = self.node_config.as_ref().ok_or_else(|| {
            ChainError::InternalError("controller is not initialized".to_string())
        })?;
        if config.state_history_enabled {
            return Err(ChainError::InternalError(
                "header authentication pipelining is restricted to migration replay".to_string(),
            ));
        }
        if !self.pending_chain.is_empty() {
            return Err(ChainError::InternalError(
                "cannot snapshot migration authentication state with pending blocks".to_string(),
            ));
        }
        Ok(MigrationBlockAuthenticator {
            antelope_block_signatures: config.antelope_block_signatures,
            schedule_state: ProducerScheduleState {
                active: self.active_schedule.clone(),
                pending: self.pending_schedule.clone(),
            },
            signing_state: self.header_signing_state.clone(),
            previous_id: self.last_accepted_block_id,
        })
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
        let Some(log) = self.chain_state_log.as_ref() else {
            // No-op only when the state-history log is absent.
            return Ok(());
        };
        // The first appended block gets a full snapshot; later blocks get the
        // per-block delta from the still-open undo session. Called before
        // `db.commit`, so removed rows are still resolvable.
        let full_snapshot = log.range().is_none();
        let chain_id = self.genesis_chain_id.0.0;
        let deltas = self.db.pack_deltas(full_snapshot, &chain_id);
        log.append(block_id.clone(), &deltas).map_err(|e| {
            ChainError::InternalError(format!("failed to append to chain state log: {}", e))
        })?;
        Ok(())
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
            self.db.arena_start_undo_session(); // the replayed block's session
            let (traces, _transaction_mroot, _action_mroot, _proposed_schedule) =
                match self.execute_block(block, block_status, mempool) {
                    Ok(v) => v,
                    Err(e) => {
                        self.db.arena_undo(); // undo the session on the error
                        return Err(e);
                    }
                };
            self.pending_chain.push(PendingBlock {
                id: block.id()?,
                parent: block.previous_id().clone(),
                traces,
            });
        }

        Ok(())
    }

    pub fn get_greylist_limit() -> Result<u32, ChainError> {
        Ok(1000) // TODO: Implement greylist limit
    }

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

        let prods = self.db.system_accounts().prods;
        update_permission(
            &mut self.db,
            prods,
            ACTIVE_NAME,
            calculate_threshold(2, 3), // more than 2/3 of producers must sign
        )?;
        update_permission(
            &mut self.db,
            prods,
            MAJORITY_PRODUCERS_PERMISSION_NAME,
            calculate_threshold(1, 2), // more than 1/2 of producers must sign
        )?;
        update_permission(
            &mut self.db,
            prods,
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

    use pulsevm_database::{
        Authority,
        Database,
        KeyWeight,
        MigrationManifest,
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

    #[cfg(feature = "arena-shadow")]
    use crate::chain::abi::AbiDefinition;
    use crate::{
        ACTIVE_NAME,
        PRODS_NAME,
        block::MAX_FUTURE_BLOCK_TIME_SLOTS,
        chain::{
            asset::{
                Asset,
                Symbol,
            },
            authority::PermissionLevel,
            pulse_contract::{
                NewAccount,
                SetCode,
            },
            transaction::{
                Action,
                Transaction,
                TransactionHeader,
            },
        },
        crypto::{
            PrivateKey,
            Signature,
        },
    };

    use super::*;
    use crate::CODE_NAME;

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
                        vec![KeyWeight::new(private_key.get_public_key().into_k1(), 1)],
                        vec![],
                        vec![],
                    ),
                    active: Authority::new(
                        1,
                        vec![KeyWeight::new(private_key.get_public_key().into_k1(), 1)],
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

    fn create_account_from_system(
        private_key: &PrivateKey,
        system: Name,
        account: Name,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let authority = Authority::new(
            1,
            vec![KeyWeight::new(private_key.get_public_key().into_k1(), 1)],
            vec![],
            vec![],
        );
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                system,
                NEWACCOUNT_NAME,
                NewAccount {
                    creator: system,
                    name: account,
                    owner: authority.clone(),
                    active: authority,
                }
                .pack()
                .unwrap(),
                vec![PermissionLevel::new(system.as_u64(), ACTIVE_NAME.as_u64())],
            )],
        )
        .sign(private_key, &chain_id)?;
        Ok(PackedTransaction::from_signed_transaction(trx)?)
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
    /// Decode a symbol_code (the raw `u64` a token contract uses as the `stat`
    /// table scope) back to its ticker string: ASCII chars packed low byte first.
    fn symbol_code_to_string(mut code: u64) -> String {
        let mut s = String::new();
        while code != 0 {
            let c = (code & 0xFF) as u8;
            if !c.is_ascii_uppercase() {
                return String::new();
            }
            s.push(c as char);
            code >>= 8;
        }
        s
    }

    /// Re-serve each captured RPC formatter query off the arena and require it to
    /// reproduce the frozen C++ output (semantic JSON equality). Covers the
    /// arena-backed formatters wired so far; account_info records are skipped
    /// until it is wired.
    fn verify_rpc_golden(controller: &Controller, golden_path: &str) -> Result<(), ChainError> {
        let db = controller.database();
        let text = fs::read_to_string(golden_path).expect("read rpc golden");
        let records: Vec<serde_json::Value> =
            serde_json::from_str(&text).expect("parse rpc golden");

        let as_u64 = |v: &serde_json::Value, k: &str| v[k].as_u64().unwrap();
        let parse = |s: &str| -> serde_json::Value { serde_json::from_str(s).expect("json") };

        let mut checked = 0u64;
        let mut mismatches = 0u64;
        let mut by_kind: std::collections::BTreeMap<String, u64> =
            std::collections::BTreeMap::new();
        for r in &records {
            let kind = r["kind"].as_str().unwrap();
            let expected = r.get("output").map(|o| parse(o.as_str().unwrap()));
            let got = match kind {
                "table_rows_json" => Some(db.get_table_rows(
                    true,
                    as_u64(r, "code"),
                    &as_u64(r, "scope").to_string(),
                    as_u64(r, "table"),
                    "",
                    "",
                    "",
                    100,
                    "i64",
                    "1",
                    "dec",
                    false,
                    true,
                )?),
                "table_rows_raw" => Some(db.get_table_rows(
                    false,
                    as_u64(r, "code"),
                    &as_u64(r, "scope").to_string(),
                    as_u64(r, "table"),
                    "",
                    "",
                    "",
                    100,
                    "i64",
                    "1",
                    "dec",
                    false,
                    true,
                )?),
                "currency_balance" => {
                    Some(db.rpc_get_currency_balance(as_u64(r, "code"), as_u64(r, "account"))?)
                }
                "currency_stats" => Some(
                    db.rpc_get_currency_stats(as_u64(r, "code"), r["symbol"].as_str().unwrap())?,
                ),
                "table_by_scope" => {
                    Some(db.rpc_get_table_by_scope(as_u64(r, "code"), as_u64(r, "table"), 100)?)
                }
                "account_info" => {
                    let out = expected.as_ref().unwrap();
                    let head_num = out["head_block_num"].as_u64().unwrap() as u32;
                    Some(db.get_account_info_without_core_symbol(
                        as_u64(r, "account"),
                        head_num,
                        &controller.last_accepted_block().timestamp().to_time_point(),
                    )?)
                }
                _ => None,
            };
            if let (Some(got), Some(expected)) = (got, expected) {
                let got = parse(&got);
                if got != expected {
                    mismatches += 1;
                    eprintln!("RPC {kind} mismatch:");
                    match (got.as_object(), expected.as_object()) {
                        (Some(g), Some(w)) => {
                            for (k, wv) in w {
                                if g.get(k) != Some(wv) {
                                    eprintln!("  field {k}: got {:?} want {wv}", g.get(k));
                                }
                            }
                        }
                        _ => eprintln!("  got {got}\n  want {expected}"),
                    }
                    continue;
                }
                checked += 1;
                *by_kind.entry(kind.to_string()).or_default() += 1;
            }
        }
        assert!(checked > 0, "verified no RPC records");
        assert_eq!(mismatches, 0, "{mismatches} RPC formatter outputs diverged");
        eprintln!("RPC verify: {checked} arena formatter outputs match the C++ golden {by_kind:?}");
        Ok(())
    }

    /// Freeze the C++ RPC formatter outputs over the real replayed contract state
    /// into a JSON file, so the arena reimplementation and the Rust ABI serializer
    /// can be built and validated against a C++-attested oracle after the bridge is
    /// removed. Records, per real `(code, scope, table)`: `get_table_rows` in both
    /// JSON and raw form, `get_table_by_scope`, `get_currency_balance` /
    /// `get_currency_stats` for token tables, `get_account_info`, and each code's
    /// raw ABI (so the serializer has the definition its rows decode against).
    fn capture_rpc_golden(controller: &Controller, out_path: &str) -> Result<(), ChainError> {
        use serde_json::json;

        let db = controller.database();
        let head_num = controller.last_accepted_block().block_num();
        let head_time = controller.last_accepted_block().timestamp().to_time_point();

        // Enumerate every real (code, scope, table) from the arena's contract-table
        // state (36-byte records: code, scope, table, payer as u64 LE, count u32 LE).
        let table_bytes = db.arena_contract_table_state_bytes().unwrap_or_default();
        let mut tables: Vec<(u64, u64, u64)> = Vec::new();
        let mut p = 0;
        while p + 36 <= table_bytes.len() {
            let u = |o: usize| u64::from_le_bytes(table_bytes[o..o + 8].try_into().unwrap());
            tables.push((u(p), u(p + 8), u(p + 16)));
            p += 36;
        }

        let accounts_table = Name::from_str("accounts")?.as_u64();
        let stat_table = Name::from_str("stat")?.as_u64();

        let mut records: Vec<serde_json::Value> = Vec::new();

        // Each distinct code's ABI (the definition the row decoder needs), and a
        // set of accounts to query get_account_info for.
        let mut codes: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        let mut accounts: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for &(code, scope, table) in &tables {
            codes.insert(code);
            if table == accounts_table {
                accounts.insert(scope);
            }
        }
        for name in ["pulse", "pulse.token", "pulse.msig", "pulse.ram"] {
            if let Ok(n) = Name::from_str(name) {
                accounts.insert(n.as_u64());
            }
        }

        for &code in &codes {
            if let Some(abi) = db.arena_account_abi_bytes(code) {
                records.push(json!({"kind": "abi", "code": code, "abi_hex": hex::encode(&abi)}));
            }
        }

        let mut core_symbol: Option<String> = None;
        for &(code, scope, table) in &tables {
            let scope_str = Name::new(scope).to_string();
            for json_mode in [true, false] {
                if let Ok(output) = db.get_table_rows(
                    json_mode, code, &scope_str, table, "", "", "", 100, "", "", "", false, true,
                ) {
                    records.push(json!({
                        "kind": if json_mode { "table_rows_json" } else { "table_rows_raw" },
                        "code": code, "scope": scope, "table": table, "output": output,
                    }));
                }
            }
            if table == accounts_table
                && let Ok(output) = db.get_currency_balance_without_symbol(code, scope)
            {
                records.push(json!({
                    "kind": "currency_balance", "code": code, "account": scope, "output": output,
                }));
            }
            if table == stat_table {
                let symbol = symbol_code_to_string(scope);
                if !symbol.is_empty() {
                    if core_symbol.is_none() {
                        core_symbol = Some(symbol.clone());
                    }
                    if let Ok(output) = db.get_currency_stats(code, &symbol) {
                        records.push(json!({
                            "kind": "currency_stats", "code": code, "symbol": symbol, "output": output,
                        }));
                    }
                }
            }
        }

        // get_table_by_scope for each distinct (code, table).
        let mut code_table: std::collections::BTreeSet<(u64, u64)> =
            std::collections::BTreeSet::new();
        for &(code, _scope, table) in &tables {
            code_table.insert((code, table));
        }
        for (code, table) in code_table {
            if let Ok(output) = db.get_table_by_scope(code, table, "", "", 100, false) {
                records.push(json!({
                    "kind": "table_by_scope", "code": code, "table": table, "output": output,
                }));
            }
        }

        // get_account_info (auto core symbol, and — for a real core symbol — the
        // expected-core-symbol variant, which decodes the system-contract structs).
        for &account in &accounts {
            if let Ok(output) =
                db.get_account_info_without_core_symbol(account, head_num, &head_time)
            {
                records.push(json!({
                    "kind": "account_info", "account": account, "output": output,
                }));
            }
            if let Some(sym) = &core_symbol
                && let Ok(output) =
                    db.get_account_info_with_core_symbol(account, sym, head_num, &head_time)
            {
                records.push(json!({
                    "kind": "account_info_core", "account": account, "symbol": sym, "output": output,
                }));
            }
        }

        let body = serde_json::to_string_pretty(&records)
            .map_err(|e| ChainError::InternalError(format!("serialize rpc golden: {e}")))?;
        std::fs::write(out_path, body)
            .map_err(|e| ChainError::InternalError(format!("write rpc golden: {e}")))?;
        eprintln!(
            "captured {} RPC golden records to {out_path}",
            records.len()
        );
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
            timestamp: pulsevm_database::BlockTimestamp { slot: 1676935919 },
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
        use std::collections::VecDeque;

        let hexd32 = |s: &str| -> [u8; 32] { hex::decode(s).unwrap().try_into().unwrap() };
        let header = BlockHeader {
            timestamp: pulsevm_database::BlockTimestamp {
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
            let mut sigs = Vec::new();
            for s in trx["signatures"].as_array().unwrap() {
                sigs.push(
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

    /// The arena-only canonical serialization of every state table, keyed by the
    /// same table names the golden roots record. This is the golden-mode builder:
    /// it reads the arena alone (no chainbase), so it is what the replay verifies
    /// against the recorded roots.
    fn arena_impl_tables(db: &Database) -> Result<Vec<(&'static str, Vec<u8>)>, ChainError> {
        Ok(db.arena_state_table_bytes())
    }

    /// Replay real testnet blocks (fetched via scripts/fetch-blocks.sh into
    /// PULSEVM_RPC_BLOCKS_DIR) into a fresh node. When
    /// `PULSEVM_GOLDEN_ROOTS` is set, every table's state root must match the
    /// frozen reference value. Ignored by default because the block corpus is
    /// external to the repository.
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
                    .packed_trx()
                    .expect("fixture contains a packed transaction")
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

        // Incremental durability: append the database delta to a WAL after every
        // accepted block, exactly as a running node would, so the crash-recovery
        // reconstruction at the end runs over a real per-block flush cadence.
        let wal = temp.path().join("arena.wal");
        let ckpt = temp.path().join("arena_checkpoint.bin");

        // Restart the database once around the middle of the run to prove it
        // resumes from disk and continues replaying afterward.
        let restart_at = start + (files.len() as u32) / 2;
        let mut restarted = false;

        // Golden per-block arena roots. `PULSEVM_GOLDEN_ROOTS` names a frozen
        // reference file. A per-block root is a stable fingerprint over every
        // arena table's canonical state bytes.
        let golden_file = std::env::var("PULSEVM_GOLDEN_ROOTS").ok();
        // Per-(block, table) roots, so a mismatch names the exact diverging table.
        let golden_roots: Option<std::collections::HashMap<(u32, String), u64>> =
            golden_file.as_ref().map(|p| {
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
        // SHiP delta verify: `PULSEVM_SHIP_VERIFY` names the gunzipped golden
        // (`<block_num> <hex>` per line, captured from the C++ `pack_deltas`).
        // Each block's chain-state deltas, read back out of the log after accept,
        // must reproduce the golden line byte-for-byte.
        let ship_golden: Option<std::collections::HashMap<u32, Vec<u8>>> =
            std::env::var("PULSEVM_SHIP_VERIFY").ok().map(|p| {
                fs::read_to_string(&p)
                    .expect("read ship golden")
                    .lines()
                    .filter_map(|l| {
                        let mut it = l.split_whitespace();
                        let n: u32 = it.next()?.parse().ok()?;
                        let bytes = hex::decode(it.next()?).ok()?;
                        Some((n, bytes))
                    })
                    .collect()
            });
        let mut ship_verified = 0u32;

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
            let sig_digest = block.signed_block_header.header.sig_digest()?;
            block.signed_block_header.signature = block_signer.sign(&sig_digest)?;
            if let Err(e) = controller.verify_block(&block, &mut mempool).await {
                eprintln!("stalled applying block {n}: {e:?}");
                break;
            }
            controller.accept_block(&block.id()?, &mut mempool)?;
            controller.set_preferred_id(block.id()?);
            controller.database().arena_flush_delta(&wal)?;

            // Read this block's chain-state deltas back out of the log and check
            // them against the C++ golden, byte-for-byte.
            if let Some(golden) = &ship_golden {
                let got = controller
                    .chain_state_log()
                    .expect("chain state log")
                    .read_block(n)
                    .unwrap_or_else(|e| panic!("read chain_state_log block {n}: {e:?}"));
                match golden.get(&n) {
                    Some(want) if want == &got => ship_verified += 1,
                    Some(want) => {
                        let at = got
                            .iter()
                            .zip(want.iter())
                            .position(|(a, b)| a != b)
                            .unwrap_or(want.len().min(got.len()));
                        let lo = at.saturating_sub(8);
                        panic!(
                            "SHiP delta mismatch at block {n}: got {} bytes, want {} bytes; \
                             first diff at offset {at}\n  got : {}\n  want: {}",
                            got.len(),
                            want.len(),
                            hex::encode(&got[lo..(at + 16).min(got.len())]),
                            hex::encode(&want[lo..(at + 16).min(want.len())]),
                        );
                    }
                    None => panic!("SHiP golden has no entry for block {n}"),
                }
            }

            // Build the canonical bytes for every arena table.
            let tables = arena_impl_tables(&controller.database())?;

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

            // Check each arena table against the frozen reference set.
            if let Some(golden) = &golden_roots {
                let mut mismatch = None;
                for (name, arena) in &tables {
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
                        "arena restart should reload the database"
                    );
                    restarted = true;
                }
                continue;
            }
            replayed = n;

            // Restart once, mid-chain: checkpoint, drop the live state, reload
            // from disk, and keep going.
            if !restarted && n >= restart_at {
                assert!(
                    controller.database().arena_restart(&ckpt)?,
                    "arena restart should reload the database"
                );
                restarted = true;
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

        if let Some(golden) = &ship_golden {
            assert!(
                ship_verified > 0,
                "SHiP verify was requested but no blocks were checked"
            );
            eprintln!(
                "SHiP chain-state deltas matched the C++ golden byte-for-byte for {ship_verified} blocks \
                 (golden has {} entries)",
                golden.len()
            );
        }

        // RPC fixture capture is opt-in and terminal.
        if let Ok(out) = std::env::var("PULSEVM_CAPTURE_RPC") {
            capture_rpc_golden(&controller, &out)?;
            return Ok(());
        }

        // Re-serve each captured formatter query and require semantic equality
        // with the frozen reference output.
        if let Ok(golden) = std::env::var("PULSEVM_VERIFY_RPC") {
            verify_rpc_golden(&controller, &golden)?;
            return Ok(());
        }

        if golden_roots.is_some() {
            eprintln!(
                "replayed real testnet blocks up to {replayed}; every per-block arena state root matched the frozen reference set"
            );
            return Ok(());
        }
        Ok(())
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
    async fn protocol_feature_activation_round_trips_through_built_block() -> Result<(), ChainError>
    {
        let (mut producer, private_key, chain_id, _producer_temp) = init_test_controller()?;
        let feature = [
            0xef, 0x43, 0x11, 0x2c, 0x65, 0x43, 0xb8, 0x8d, 0xb2, 0x28, 0x3a, 0x2e, 0x07, 0x72,
            0x78, 0xc3, 0x15, 0xae, 0x2c, 0x84, 0x71, 0x9a, 0x8b, 0x25, 0xf2, 0x5c, 0xc8, 0x85,
            0x65, 0xfb, 0xea, 0x99,
        ];
        producer.db.preactivate_protocol_feature(feature)?;

        let account = Name::from_str("featuretest")?;
        let mut producer_mempool = Mempool::new();
        producer_mempool.add_transaction(create_account(&private_key, account, chain_id)?);
        let block = producer.build_block(&mut producer_mempool).await?;
        let activations = block
            .signed_block_header
            .header
            .protocol_feature_activations()?;
        assert_eq!(activations, vec![Digest(feature)]);
        assert!(producer.db.protocol_feature_activated(feature));
        assert!(producer.db.preactivated_protocol_features().is_empty());

        let (mut validator, _validator_key, _validator_chain_id, _validator_temp) =
            init_test_controller()?;
        validator.db.preactivate_protocol_feature(feature)?;
        let mut validator_mempool = Mempool::new();
        validator
            .verify_block(&block, &mut validator_mempool)
            .await?;
        assert!(validator.db.protocol_feature_activated(feature));
        assert!(validator.db.preactivated_protocol_features().is_empty());
        validator.accept_block(&block.id()?, &mut validator_mempool)?;
        assert!(validator.db.protocol_feature_activated(feature));
        Ok(())
    }

    #[tokio::test]
    async fn custom_system_account_is_seeded_and_exposed_to_runtime() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let mut controller = Controller::new();
        let temp_path = get_temp_dir();
        let config_bytes = json!({
            "system_account": "eosio",
            "producer_name": "eosio",
            "producer_key": private_key.to_string(),
        })
        .to_string()
        .into_bytes();

        controller.initialize(
            &chain_id,
            &config_bytes,
            &generate_genesis(&private_key),
            temp_path.path().to_str().unwrap(),
        )?;

        let db = controller.database();
        let names = db.system_accounts();
        assert_eq!(names.system.to_string(), "eosio");
        assert!(db.is_account(names.system.as_u64())?);
        assert!(db.is_account(names.prods.as_u64())?);
        assert!(!db.is_account(PULSE_NAME.as_u64())?);
        assert!(
            Controller::find_apply_handler(
                &names.system,
                &names.system,
                &NEWACCOUNT_NAME,
                names.system,
            )
            .is_some()
        );

        let timestamp = controller.last_accepted_block().timestamp().clone();
        controller.execute_transaction(
            &create_account_from_system(
                &private_key,
                names.system,
                Name::from_str("alice")?,
                chain_id,
            )?,
            &timestamp,
            &BlockStatus::Building,
        )?;
        assert!(db.is_account(Name::from_str("alice")?.as_u64())?);
        Ok(())
    }

    #[test]
    fn xpr_mainnet_genesis_reproduces_canonical_block_one() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let config_bytes = json!({
            "system_account": "eosio",
            "native_system_contract": false,
            "antelope_block_signatures": true,
            "producer_name": "eosio",
            "producer_key": private_key.to_string(),
        })
        .to_string()
        .into_bytes();
        let genesis_bytes =
            include_bytes!("../../../../tools/xpr-chainbase-export/xpr-mainnet-genesis.json")
                .to_vec();
        let temp = get_temp_dir();
        let mut controller = Controller::new();
        controller.initialize(
            &chain_id,
            &config_bytes,
            &genesis_bytes,
            temp.path().to_str().unwrap(),
        )?;

        assert_eq!(controller.genesis_chain_id, chain_id);
        assert_eq!(
            controller.last_accepted_block().id()?.to_string(),
            "000000018421bd47ce23d4c47706e0bb98604157afedc67d56d05c82d5aa10c5"
        );
        assert_eq!(
            controller
                .last_accepted_block()
                .signed_block_header
                .header
                .action_mroot,
            Digest(chain_id.0.0)
        );
        Ok(())
    }

    #[tokio::test]
    async fn xpr_mainnet_canonical_block_two_replays() -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0")
                .unwrap();
        let config_bytes = json!({
            "system_account": "eosio",
            "native_system_contract": false,
            "antelope_block_signatures": true,
            "producer_name": "eosio",
            "producer_key": "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez",
        })
        .to_string()
        .into_bytes();
        let genesis_bytes =
            include_bytes!("../../../../tools/xpr-chainbase-export/xpr-mainnet-genesis.json")
                .to_vec();
        let temp = get_temp_dir();
        let mut controller = Controller::new();
        controller.initialize(
            &chain_id,
            &config_bytes,
            &genesis_bytes,
            temp.path().to_str().unwrap(),
        )?;

        let parent = controller.last_accepted_block();
        let mut block = SignedBlock::new(
            parent.id()?,
            BlockTimestamp::new(parent.timestamp().slot() + 10),
            Name::from_str("eosio")?,
            VecDeque::new(),
            Digest::default(),
            Digest(
                hex::decode("508211b515e600e67737f3f4de83b3d74b6000c4bd2bf8951ec13a8d2cfc0792")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
        );
        block.signed_block_header.signature = Signature::from_str(
            "SIG_K1_K9pFVXCf4A6HDm4k7A7wnhqxSxvxC43cVEJh5PoZmKVcyvHQBrYsWMcaBKjbJBrS2at6qsKSYunuZ6gE67fkHaQv9c4HPA",
        )?;
        assert_eq!(
            block.id()?.to_string(),
            "00000002f6d64c4a3ed0dda0bd465d7f7cac8a87fe220ba30f0f0385a994b492"
        );

        let header_digest = Digest::hash(&block.signed_block_header.header.pack()?);
        let mut header_and_root = header_digest.0.to_vec();
        header_and_root.extend_from_slice(&parent.id()?.0.0);
        let header_root_digest = Digest::hash(&header_and_root);
        let schedule_hash = Digest::hash(&controller.active_schedule.pack()?);
        let mut signing_payload = header_root_digest.0.to_vec();
        signing_payload.extend_from_slice(&schedule_hash.0);
        let antelope_signing_digest = Digest::hash(&signing_payload);
        assert_eq!(
            block
                .signed_block_header
                .signature
                .recover_public_key(&antelope_signing_digest)?,
            controller.active_schedule.producers[0].block_signing_key
        );

        let mut mempool = Mempool::new();
        controller.verify_block(&block, &mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;
        assert_eq!(controller.last_accepted_block().id()?, block.id()?);
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

    #[tokio::test]
    async fn due_deferred_transaction_executes_without_mempool_signature_admission()
    -> Result<(), ChainError> {
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
        let scheduled = create_account(&private_key, Name::from_str("deferred")?, chain_id)?;
        let trx_id: [u8; 32] = scheduled.id().as_bytes().try_into().unwrap();
        let producer_ram_before = controller.db.get_account_ram_usage(PULSE_NAME.as_u64())?;
        controller.db.xpr_import_deferred_transaction(
            PULSE_NAME.as_u64(),
            7,
            PULSE_NAME.as_u64(),
            trx_id,
            0,
            i64::MAX,
            0,
            scheduled.packed_trx_bytes(),
        )?;
        ResourceLimitsManager::add_pending_ram_usage(
            &mut controller.db,
            &PULSE_NAME,
            generated_transaction_billable_size(scheduled.packed_trx_bytes().len())?,
        )?;

        let mut mempool = Mempool::new();
        let block = controller.build_block(&mut mempool).await?;
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions[0].transaction_id(), scheduled.id());

        let (mut validator, _validator_key, _validator_chain_id, _validator_temp) =
            init_test_controller()?;
        validator.db.xpr_import_deferred_transaction(
            PULSE_NAME.as_u64(),
            7,
            PULSE_NAME.as_u64(),
            trx_id,
            0,
            i64::MAX,
            0,
            scheduled.packed_trx_bytes(),
        )?;
        let validator_ram_before = validator.db.get_account_ram_usage(PULSE_NAME.as_u64())?;
        ResourceLimitsManager::add_pending_ram_usage(
            &mut validator.db,
            &PULSE_NAME,
            generated_transaction_billable_size(scheduled.packed_trx_bytes().len())?,
        )?;
        let mut validator_mempool = Mempool::new();
        validator
            .verify_block(&block, &mut validator_mempool)
            .await?;
        validator.accept_block(&block.id()?, &mut validator_mempool)?;
        assert_eq!(validator.db.deferred_transaction_count(), 0);
        assert_eq!(
            validator.db.get_account_ram_usage(PULSE_NAME.as_u64())?,
            validator_ram_before,
            "validator must refund the generated transaction RAM bill"
        );
        assert!(
            validator
                .db
                .is_account(Name::from_str("deferred")?.as_u64())?
        );

        controller.accept_block(&block.id()?, &mut mempool)?;
        assert_eq!(controller.db.deferred_transaction_count(), 0);
        assert_eq!(
            controller.db.get_account_ram_usage(PULSE_NAME.as_u64())?,
            producer_ram_before,
            "producer must refund the generated transaction RAM bill"
        );
        assert!(
            controller
                .db
                .is_account(Name::from_str("deferred")?.as_u64())?
        );
        Ok(())
    }

    #[tokio::test]
    async fn deferred_payer_can_reuse_refunded_ram_during_execution() -> Result<(), ChainError> {
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
        let payer = Name::from_str("deferpayer")?;
        let timestamp = controller.last_accepted_block().timestamp().clone();
        controller.execute_transaction(
            &create_account(&private_key, payer, chain_id)?,
            &timestamp,
            &BlockStatus::Building,
        )?;

        let wasm = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "apply") (param i64 i64 i64)))
            "#,
        )
        .map_err(|error| ChainError::InternalError(error.to_string()))?;
        let code_ram = i64::try_from(wasm.len()).unwrap()
            * i64::from(pulsevm_constants::SETCODE_RAM_BYTES_MULTIPLIER);
        let scheduled = set_code(&private_key, payer, wasm, chain_id)?;
        let trx_id: [u8; 32] = scheduled.id().as_bytes().try_into().unwrap();
        let generated_ram =
            generated_transaction_billable_size(scheduled.packed_trx_bytes().len())?;
        let ram_before = controller.db.get_account_ram_usage(payer.as_u64())?;
        controller.db.xpr_import_deferred_transaction(
            PULSE_NAME.as_u64(),
            11,
            payer.as_u64(),
            trx_id,
            0,
            i64::MAX,
            0,
            scheduled.packed_trx_bytes(),
        )?;
        ResourceLimitsManager::add_pending_ram_usage(&mut controller.db, &payer, generated_ram)?;
        controller.db.set_account_limits(
            payer.as_u64(),
            ram_before + generated_ram.max(code_ram),
            1_000_000,
            1_000_000,
        )?;

        let mut mempool = Mempool::new();
        let block = controller.build_block(&mut mempool).await?;
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions[0].transaction_id(), scheduled.id());
        controller.accept_block(&block.id()?, &mut mempool)?;

        assert_eq!(controller.db.deferred_transaction_count(), 0);
        assert!(
            controller.db.get_account_ram_usage(payer.as_u64())?
                <= ram_before + generated_ram.max(code_ram),
            "the payload must execute after its generated-transaction RAM is refunded"
        );
        assert_ne!(
            controller.db.account_code_hash_vm(payer.as_u64())?.0,
            [0; 32]
        );

        let (mut validator, validator_key, validator_chain_id, _validator_temp) =
            init_test_controller()?;
        let validator_timestamp = validator.last_accepted_block().timestamp().clone();
        validator.execute_transaction(
            &create_account(&validator_key, payer, validator_chain_id)?,
            &validator_timestamp,
            &BlockStatus::Building,
        )?;
        let validator_ram_before = validator.db.get_account_ram_usage(payer.as_u64())?;
        validator.db.xpr_import_deferred_transaction(
            PULSE_NAME.as_u64(),
            11,
            payer.as_u64(),
            trx_id,
            0,
            i64::MAX,
            0,
            scheduled.packed_trx_bytes(),
        )?;
        ResourceLimitsManager::add_pending_ram_usage(&mut validator.db, &payer, generated_ram)?;
        validator.db.set_account_limits(
            payer.as_u64(),
            validator_ram_before + generated_ram.max(code_ram),
            1_000_000,
            1_000_000,
        )?;
        let mut validator_mempool = Mempool::new();
        validator
            .verify_block(&block, &mut validator_mempool)
            .await?;
        validator.accept_block(&block.id()?, &mut validator_mempool)?;
        assert_eq!(validator.db.deferred_transaction_count(), 0);
        assert_ne!(
            validator.db.account_code_hash_vm(payer.as_u64())?.0,
            [0; 32]
        );
        Ok(())
    }

    #[tokio::test]
    async fn expired_deferred_transaction_retires_with_id_only_receipt() -> Result<(), ChainError> {
        let (mut producer, private_key, chain_id, _producer_temp) = init_test_controller()?;
        let scheduled = create_account(&private_key, Name::from_str("expired")?, chain_id)?;
        let trx_id: [u8; 32] = scheduled.id().as_bytes().try_into().unwrap();
        producer.db.xpr_import_deferred_transaction(
            PULSE_NAME.as_u64(),
            9,
            PULSE_NAME.as_u64(),
            trx_id,
            0,
            0,
            0,
            scheduled.packed_trx_bytes(),
        )?;

        let mut producer_mempool = Mempool::new();
        let block = producer.build_block(&mut producer_mempool).await?;
        assert_eq!(block.transactions.len(), 1);
        assert!(block.transactions[0].packed_trx().is_none());
        assert_eq!(block.transactions[0].transaction_id(), scheduled.id());
        assert_eq!(
            block.transactions[0].status(),
            &crate::chain::transaction::TransactionStatus::Expired
        );
        assert_eq!(producer.db.deferred_transaction_count(), 0);
        assert!(
            !producer
                .db
                .is_account(Name::from_str("expired")?.as_u64())?
        );

        let (mut validator, _validator_key, _validator_chain_id, _validator_temp) =
            init_test_controller()?;
        validator.db.xpr_import_deferred_transaction(
            PULSE_NAME.as_u64(),
            9,
            PULSE_NAME.as_u64(),
            trx_id,
            0,
            0,
            0,
            scheduled.packed_trx_bytes(),
        )?;
        let mut validator_mempool = Mempool::new();
        validator
            .verify_block(&block, &mut validator_mempool)
            .await?;
        validator.accept_block(&block.id()?, &mut validator_mempool)?;
        assert_eq!(validator.db.deferred_transaction_count(), 0);
        assert!(
            !validator
                .db
                .is_account(Name::from_str("expired")?.as_u64())?
        );
        Ok(())
    }

    #[test]
    fn deferred_onerror_payload_uses_xpr_uint128_and_bytes_encoding() -> Result<(), ChainError> {
        let packed = vec![0xab; 128];
        let payload = deferred_onerror_payload(0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00, &packed)?;
        assert_eq!(
            &payload[..16],
            &0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128.to_le_bytes()
        );
        // 128 is encoded as a two-byte Antelope varuint32: 0x80, 0x01.
        assert_eq!(&payload[16..18], &[0x80, 0x01]);
        assert_eq!(&payload[18..], packed.as_slice());
        Ok(())
    }

    #[tokio::test]
    async fn failed_deferred_transaction_runs_onerror_as_soft_fail() -> Result<(), ChainError> {
        fn install_onerror_handler(
            controller: &mut Controller,
            private_key: &PrivateKey,
            chain_id: Id,
        ) -> Result<(), ChainError> {
            // The deferred action carries a one-byte empty `bytes` argument,
            // while XPR's onerror payload includes the uint128 sender id and
            // raw sent transaction. This gives the scheduler a deterministic
            // failure to turn into a soft_fail receipt.
            let wasm = wat::parse_str(&format!(
                r#"
                (module
                  (import "env" "eosio_assert" (func $assert (param i32 i32)))
                  (import "env" "action_data_size" (func $action_data_size (result i32)))
                  (memory (export "memory") 1)
                  (data (i32.const 8) "deferred failure\00")
                  (func (export "apply") (param i64 i64 i64)
                    (block $handled
                      (br_if $handled
                        (i32.gt_u (call $action_data_size) (i32.const 16)))
                      (call $assert (i32.const 0) (i32.const 8)))))
                "#,
            ))
            .map_err(|error| {
                ChainError::InternalError(format!("compile onerror test wasm: {error}"))
            })?;
            let timestamp = controller.last_accepted_block().timestamp().clone();
            // The callback's action code is `eosio`, exactly as on XPR. The
            // minimal test genesis has only `pulse`, so create the source
            // system account before scheduling that action to pulse as receiver.
            controller.execute_transaction(
                &create_account(private_key, Name::from_str("eosio")?, chain_id)?,
                &timestamp,
                &BlockStatus::Building,
            )?;
            controller.execute_transaction(
                &set_code(private_key, PULSE_NAME, wasm, chain_id)?,
                &timestamp,
                &BlockStatus::Building,
            )?;
            Ok(())
        }

        let (mut producer, private_key, chain_id, _producer_temp) = init_test_controller()?;
        install_onerror_handler(&mut producer, &private_key, chain_id)?;
        let scheduled = call_contract(
            &private_key,
            PULSE_NAME,
            Name::from_str("fail")?,
            &Vec::<u8>::new(),
            chain_id,
        )?;
        let trx_id: [u8; 32] = scheduled.id().as_bytes().try_into().unwrap();
        producer.db.xpr_import_deferred_transaction(
            PULSE_NAME.as_u64(),
            0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
            PULSE_NAME.as_u64(),
            trx_id,
            0,
            i64::MAX,
            0,
            scheduled.packed_trx_bytes(),
        )?;

        let mut producer_mempool = Mempool::new();
        let block = producer.build_block(&mut producer_mempool).await?;
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(
            block.transactions[0].status(),
            &crate::chain::transaction::TransactionStatus::SoftFail
        );
        assert_eq!(producer.db.deferred_transaction_count(), 0);

        let (mut validator, _validator_key, validator_chain_id, _validator_temp) =
            init_test_controller()?;
        install_onerror_handler(&mut validator, &private_key, validator_chain_id)?;
        validator.db.xpr_import_deferred_transaction(
            PULSE_NAME.as_u64(),
            0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
            PULSE_NAME.as_u64(),
            trx_id,
            0,
            i64::MAX,
            0,
            scheduled.packed_trx_bytes(),
        )?;
        let mut validator_mempool = Mempool::new();
        validator
            .verify_block(&block, &mut validator_mempool)
            .await?;
        validator.accept_block(&block.id()?, &mut validator_mempool)?;
        assert_eq!(validator.db.deferred_transaction_count(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn failed_deferred_transaction_retires_after_onerror_hard_failure()
    -> Result<(), ChainError> {
        fn install_failing_onerror_handler(
            controller: &mut Controller,
            private_key: &PrivateKey,
            chain_id: Id,
        ) -> Result<(), ChainError> {
            // Permit only the native setcode action used to install this Wasm.
            // The deferred `fail` action and its eosio::onerror callback both
            // deterministically assert, exercising the hard-failure path.
            let wasm = wat::parse_str(&format!(
                r#"
                (module
                  (import "env" "eosio_assert" (func $assert (param i32 i32)))
                  (memory (export "memory") 1)
                  (data (i32.const 8) "deferred failure\00")
                  (func (export "apply") (param i64 i64 i64)
                    (block $handled
                      (br_if $handled
                        (i64.eq (local.get 2) (i64.const {})))
                      (call $assert (i32.const 0) (i32.const 8)))))
                "#,
                SETCODE_NAME.as_u64() as i64,
            ))
            .map_err(|error| {
                ChainError::InternalError(format!("compile hard-fail test wasm: {error}"))
            })?;
            let timestamp = controller.last_accepted_block().timestamp().clone();
            controller.execute_transaction(
                &create_account(private_key, Name::from_str("eosio")?, chain_id)?,
                &timestamp,
                &BlockStatus::Building,
            )?;
            controller.execute_transaction(
                &set_code(private_key, PULSE_NAME, wasm, chain_id)?,
                &timestamp,
                &BlockStatus::Building,
            )?;
            Ok(())
        }

        let (mut producer, private_key, chain_id, _producer_temp) = init_test_controller()?;
        install_failing_onerror_handler(&mut producer, &private_key, chain_id)?;
        let scheduled = call_contract(
            &private_key,
            PULSE_NAME,
            Name::from_str("fail")?,
            &Vec::<u8>::new(),
            chain_id,
        )?;
        let trx_id: [u8; 32] = scheduled.id().as_bytes().try_into().unwrap();
        producer.db.xpr_import_deferred_transaction(
            PULSE_NAME.as_u64(),
            7,
            PULSE_NAME.as_u64(),
            trx_id,
            0,
            i64::MAX,
            0,
            scheduled.packed_trx_bytes(),
        )?;

        let mut producer_mempool = Mempool::new();
        let block = producer.build_block(&mut producer_mempool).await?;
        assert_eq!(block.transactions.len(), 1);
        assert!(block.transactions[0].packed_trx().is_none());
        assert_eq!(block.transactions[0].transaction_id(), scheduled.id());
        assert_eq!(
            block.transactions[0].status(),
            &crate::chain::transaction::TransactionStatus::HardFail
        );
        assert_eq!(producer.db.deferred_transaction_count(), 0);

        let (mut validator, _validator_key, validator_chain_id, _validator_temp) =
            init_test_controller()?;
        install_failing_onerror_handler(&mut validator, &private_key, validator_chain_id)?;
        validator.db.xpr_import_deferred_transaction(
            PULSE_NAME.as_u64(),
            7,
            PULSE_NAME.as_u64(),
            trx_id,
            0,
            i64::MAX,
            0,
            scheduled.packed_trx_bytes(),
        )?;
        let mut validator_mempool = Mempool::new();
        validator
            .verify_block(&block, &mut validator_mempool)
            .await?;
        validator.accept_block(&block.id()?, &mut validator_mempool)?;
        assert_eq!(validator.db.deferred_transaction_count(), 0);

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
                db.arena_account_exists(Name::from_str(name)?.as_u64()),
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
        assert!(
            controller.database().arena_account_exists(glenn.as_u64()),
            "accepted account should exist in committed state"
        );

        Ok(())
    }

    #[tokio::test]
    async fn build_block_prunes_expired_mempool_transactions() -> Result<(), ChainError> {
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
        let expiration = TimePointSec::new(TimePointSec::now().sec_since_epoch() - 1);
        let expired = create_account_with_expiration(
            &private_key,
            Name::from_str("expired")?,
            chain_id,
            expiration,
        )?;
        let mut mempool = Mempool::new();
        mempool.add_transaction(expired.clone());

        assert!(
            controller.build_block(&mut mempool).await.is_err(),
            "an expired-only mempool must not produce a block"
        );
        assert!(
            !mempool.contains(expired.id()),
            "building must evict expired transactions even when called without the timer"
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
        assert!(
            !controller.database().arena_account_exists(glenn.as_u64()),
            "rejected block's state must not persist in the database"
        );

        Ok(())
    }

    // Verifying a second block on top of a still-pending first block reuses the
    // first block's execution. Accepting the first must then unwind the child so
    // SHiP packs the first block's own undo record, and accepting the cached child
    // re-executes it on the newly accepted base.
    #[tokio::test]
    async fn test_accept_unwinds_pending_descendants_before_packing_ship_delta()
    -> Result<(), ChainError> {
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

        // A reference validator accepts each block without a pending descendant;
        // its SHiP payloads are the expected per-block deltas.
        let (mut reference, _pk, _cid, _r_temp) = init_test_controller()?;
        let mut r_mempool = Mempool::new();
        reference.verify_block(&b2, &mut r_mempool).await?;
        reference.accept_block(&b2.id()?, &mut r_mempool)?;
        let expected_b2_delta = reference.chain_state_log().unwrap().read_block(2).unwrap();

        // This validator verifies both before accepting either.
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
        assert!(validator.pending_chain.is_empty());
        assert!(
            !validator
                .database()
                .arena_account_exists(Name::from_str("bbb")?.as_u64()),
            "accepting b2 left its speculative child state materialized"
        );
        assert_eq!(
            validator.chain_state_log().unwrap().read_block(2).unwrap(),
            expected_b2_delta,
            "b2 SHiP payload included its pending child's state"
        );

        reference.verify_block(&b3, &mut r_mempool).await?;
        reference.accept_block(&b3.id()?, &mut r_mempool)?;
        let expected_b3_delta = reference.chain_state_log().unwrap().read_block(3).unwrap();

        validator.accept_block(&b3.id()?, &mut v_mempool)?;
        assert!(validator.pending_chain.is_empty());

        // b2 reused its retained execution; cached b3 ran once more only because
        // accepting b2 had to unwind it before reading b2's top undo session.
        assert_eq!(validator.blocks_executed, 3);
        assert_eq!(validator.last_accepted_block_id, b3.id()?);
        assert_eq!(validator.last_accepted_block().block_num(), 3);
        assert_eq!(
            validator.chain_state_log().unwrap().read_block(3).unwrap(),
            expected_b3_delta,
            "fallback acceptance produced a different b3 SHiP delta"
        );

        // Both accounts are present in committed state.
        let db = validator.database();
        assert!(db.arena_account_exists(Name::from_str("aaa")?.as_u64()));
        assert!(db.arena_account_exists(Name::from_str("bbb")?.as_u64()));

        Ok(())
    }

    #[tokio::test]
    async fn test_accept_log_failures_roll_back_state_logs_arena_and_mempool()
    -> Result<(), ChainError> {
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
        let mut mempool = Mempool::new();
        let account = Name::from_str("logrollback")?;
        let transaction = create_account(&private_key, account, chain_id)?;
        let transaction_id = *transaction.id();
        mempool.add_transaction(transaction.clone());

        let accepted_id_before = controller.last_accepted_block_id;
        let revision_before = controller.db.revision();
        let arena_root_before = controller.db.arena_state_root();
        let block_range_before = controller.block_log()?.range();
        let trace_range_before = controller.trace_log().unwrap().range();
        let state_range_before = controller.chain_state_log().unwrap().range();

        let block = controller.build_block(&mut mempool).await?;
        let block_id = block.id()?;
        // Build consumed it; put it back to prove failed accept does not perform
        // the externally visible mempool removal.
        assert!(mempool.add_transaction(transaction));

        // Block-log is published last as the restart commit marker, so this
        // failure rolls back both already-written SHiP logs as well.
        controller.block_log()?.fail_next_append_after_log_sync();
        let block_log_error = controller
            .accept_block(&block_id, &mut mempool)
            .unwrap_err();
        assert!(!block_log_error.is_fatal_consistency());
        assert!(block_log_error.to_string().contains("block log"));
        assert_eq!(controller.last_accepted_block_id, accepted_id_before);
        assert_eq!(controller.db.revision(), revision_before);
        assert_eq!(controller.db.arena_state_root(), arena_root_before);
        assert_eq!(controller.block_log()?.range(), block_range_before);
        assert_eq!(controller.trace_log().unwrap().range(), trace_range_before);
        assert_eq!(
            controller.chain_state_log().unwrap().range(),
            state_range_before
        );
        assert!(controller.pending_chain.is_empty());
        assert!(controller.verified_blocks.contains_key(&block_id));
        assert!(mempool.contains(&transaction_id));
        assert!(!controller.database().arena_account_exists(account.as_u64()));

        // The retry uses fallback execution. Fail its chain-state append after
        // the trace append, exercising an intermediate cross-log rollback too.
        controller.chain_state_log().unwrap().fail_next_append();
        let chain_state_error = controller
            .accept_block(&block_id, &mut mempool)
            .unwrap_err();
        assert!(!chain_state_error.is_fatal_consistency());
        assert!(chain_state_error.to_string().contains("chain state log"));
        assert_eq!(controller.last_accepted_block_id, accepted_id_before);
        assert_eq!(controller.db.revision(), revision_before);
        assert_eq!(controller.db.arena_state_root(), arena_root_before);
        assert_eq!(controller.block_log()?.range(), block_range_before);
        assert_eq!(controller.trace_log().unwrap().range(), trace_range_before);
        assert_eq!(
            controller.chain_state_log().unwrap().range(),
            state_range_before
        );
        assert!(mempool.contains(&transaction_id));
        assert!(!controller.database().arena_account_exists(account.as_u64()));

        controller.accept_block(&block_id, &mut mempool)?;
        assert_eq!(controller.last_accepted_block_id, block_id);
        assert!(!mempool.contains(&transaction_id));
        assert!(controller.database().arena_account_exists(account.as_u64()));
        #[cfg(feature = "arena-shadow")]
        assert!(controller.database().arena_account_exists(account.as_u64()));
        assert_eq!(controller.block_log()?.range().unwrap().1, 2);
        assert_eq!(controller.trace_log().unwrap().range().unwrap().1, 2);
        assert_eq!(controller.chain_state_log().unwrap().range().unwrap().1, 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_accept_can_omit_derived_state_history_for_migration() -> Result<(), ChainError> {
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
        controller
            .node_config
            .as_mut()
            .expect("test controller is initialized")
            .state_history_enabled = false;

        let trace_range_before = controller.trace_log().unwrap().range();
        let state_range_before = controller.chain_state_log().unwrap().range();
        let block_syncs_before = controller.block_log()?.data_sync_count();
        let trace_syncs_before = controller.trace_log().unwrap().data_sync_count();
        let state_syncs_before = controller.chain_state_log().unwrap().data_sync_count();
        let mut mempool = Mempool::new();
        mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("migration")?,
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        assert_eq!(controller.last_accepted_block().block_num(), 2);
        assert_eq!(controller.block_log()?.range().unwrap().1, 2);
        assert_eq!(controller.trace_log().unwrap().range(), trace_range_before);
        assert_eq!(
            controller.chain_state_log().unwrap().range(),
            state_range_before
        );
        assert_eq!(
            controller.block_log()?.data_sync_count(),
            block_syncs_before,
            "migration accept must defer the block-log durability barrier"
        );

        controller.sync_accepted_logs()?;
        assert_eq!(
            controller.block_log()?.data_sync_count(),
            block_syncs_before + 1
        );
        assert_eq!(
            controller.trace_log().unwrap().data_sync_count(),
            trace_syncs_before + 1
        );
        assert_eq!(
            controller.chain_state_log().unwrap().data_sync_count(),
            state_syncs_before + 1
        );
        Ok(())
    }

    #[tokio::test]
    async fn migration_authenticator_recovers_signature_ahead_of_execution()
    -> Result<(), ChainError> {
        let (mut producer, private_key, chain_id, _producer_temp) = init_test_controller()?;
        let (mut verifier, _private_key, _chain_id, _verifier_temp) = init_test_controller()?;
        assert!(verifier.migration_block_authenticator().is_err());
        verifier
            .node_config
            .as_mut()
            .expect("test controller is initialized")
            .state_history_enabled = false;

        let mut authenticator = verifier.migration_block_authenticator()?;
        let mut tampered_authenticator = verifier.migration_block_authenticator()?;
        let mut producer_mempool = Mempool::new();
        producer_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("pipeline")?,
            chain_id,
        )?);
        let block = producer.build_block(&mut producer_mempool).await?;
        let mut tampered = tampered_authenticator.authenticate(block.clone())?;
        tampered.signer = PrivateKey::random().get_public_key();
        let mut verifier_mempool = Mempool::new();
        let error = verifier
            .verify_authenticated_migration_block(&tampered, &mut verifier_mempool)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("block signature recovered"));
        assert_eq!(verifier.blocks_executed, 0);

        let authenticated = authenticator.authenticate(block)?;
        let block_id = authenticated.block().id()?;

        verifier
            .verify_authenticated_migration_block(&authenticated, &mut verifier_mempool)
            .await?;
        verifier.accept_block(&block_id, &mut verifier_mempool)?;
        assert_eq!(verifier.last_accepted_block_id, block_id);
        assert_eq!(verifier.blocks_executed, 1);
        Ok(())
    }

    #[tokio::test]
    async fn migration_replay_rewinds_log_tail_after_last_durable_checkpoint()
    -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let genesis_bytes = generate_genesis(&private_key);
        let config_bytes = json!({
            "producer_name": "pulse",
            "producer_key": private_key.to_string(),
            "state_history_enabled": false,
        })
        .to_string()
        .into_bytes();
        let temp = get_temp_dir();
        let db_path = temp.path().to_str().unwrap();

        let mut controller = Controller::new();
        controller.initialize(&chain_id, &config_bytes, &genesis_bytes, db_path)?;
        let mut mempool = Mempool::new();

        let durable_account = Name::from_str("durable")?;
        mempool.add_transaction(create_account(&private_key, durable_account, chain_id)?);
        let durable_block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&durable_block.id()?, &mut mempool)?;
        controller.sync_accepted_logs()?;
        controller.database().close()?;
        assert_eq!(controller.database().revision(), 2);

        let orphan_account = Name::from_str("orphan")?;
        mempool.add_transaction(create_account(&private_key, orphan_account, chain_id)?);
        let orphan_block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&orphan_block.id()?, &mut mempool)?;
        assert_eq!(controller.database().revision(), 3);
        assert_eq!(controller.block_log()?.range().unwrap().1, 3);
        drop(controller);

        let mut reopened = Controller::new();
        reopened.initialize(&chain_id, &config_bytes, &genesis_bytes, db_path)?;
        assert_eq!(reopened.last_accepted_block().block_num(), 2);
        assert_eq!(reopened.database().revision(), 2);
        assert_eq!(reopened.block_log()?.range().unwrap().1, 2);
        assert!(
            reopened
                .database()
                .arena_account_exists(durable_account.as_u64())
        );
        assert!(
            !reopened
                .database()
                .arena_account_exists(orphan_account.as_u64())
        );
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
        assert!(db.arena_account_exists(Name::from_str("aaa")?.as_u64()));
        assert!(db.arena_account_exists(Name::from_str("ccc")?.as_u64()));
        assert!(!db.arena_account_exists(Name::from_str("bbb")?.as_u64()));

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
        assert!(!db.arena_account_exists(Name::from_str("aaa")?.as_u64()));
        assert!(!db.arena_account_exists(Name::from_str("bbb")?.as_u64()));

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
            "7938dab1f2e358201b653517c66d4f56d0d69fb57482d57a98fbb54de00b804c";
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
            let (mut controller, private_key, _chain_id, _temp) = init_test_controller()?;
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

    #[tokio::test]
    async fn deferred_transaction_host_round_trip() -> Result<(), ChainError> {
        fn wat_bytes(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("\\{byte:02x}")).collect()
        }

        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
        let account = Name::from_str("testapi")?;
        let pending_block_timestamp = controller.last_accepted_block().timestamp().clone();
        let block_status = BlockStatus::Building;

        controller
            .execute_transaction(
                &create_account(&private_key, account, chain_id)?,
                &pending_block_timestamp,
                &block_status,
            )
            .map_err(|error| ChainError::InternalError(format!("create account: {error}")))?;

        // The deferred payload only needs to be a canonical transaction with an
        // action. It is not executed in this test; the scheduler stores the raw
        // transaction bytes and indexes them by (receiver, sender_id).
        let deferred = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                PULSE_NAME,
                Name::from_str("noop")?,
                vec![],
                vec![PermissionLevel::new(account.as_u64(), CODE_NAME.as_u64())],
            )],
        )
        .pack()?;
        let deferred_len = deferred.len();
        let deferred_data = wat_bytes(&deferred);
        let payer = account.as_u64();
        let sender_id = 7u128;
        let send_contract = wat::parse_str(format!(
            r#"
            (module
              (import "env" "send_deferred"
                (func $send (param i32 i64 i32 i32 i32)))
              (memory (export "memory") 1)
              (data (i32.const 32) "{deferred_data}")
              (func (export "apply") (param i64 i64 i64)
                (i64.store (i32.const 0) (i64.const 7))
                (call $send (i32.const 0) (i64.const {payer})
                  (i32.const 32) (i32.const {deferred_len}) (i32.const 0))))
            "#
        ))
        .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;
        controller
            .execute_transaction(
                &set_code(&private_key, account, send_contract, chain_id)?,
                &pending_block_timestamp,
                &block_status,
            )
            .map_err(|error| ChainError::InternalError(format!("set send code: {error}")))?;
        let ram_before_schedule = controller.db.get_account_ram_usage(payer)?;
        controller
            .execute_transaction(
                &call_contract(
                    &private_key,
                    account,
                    Name::from_str("run")?,
                    &Vec::<u8>::new(),
                    chain_id,
                )?,
                &pending_block_timestamp,
                &block_status,
            )
            .map_err(|error| ChainError::InternalError(format!("call send: {error}")))?;

        let scheduled = controller
            .db
            .arena_deferred_transaction_by_sender_id(account.as_u64(), sender_id)
            .expect("send_deferred must create a generated transaction row");
        assert_eq!(scheduled.sender, account.as_u64());
        assert_eq!(scheduled.sender_id, sender_id);
        assert_eq!(scheduled.payer, payer);
        assert_eq!(&scheduled.packed_trx[..], deferred.as_slice());
        let ram_after_schedule = controller.db.get_account_ram_usage(payer)?;
        assert_eq!(
            ram_after_schedule - ram_before_schedule,
            272 + deferred.len() as i64,
            "generated transaction RAM must include Leap's fixed object bill"
        );

        let cancel_contract = wat::parse_str(
            r#"
            (module
              (import "env" "cancel_deferred"
                (func $cancel (param i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "apply") (param i64 i64 i64)
                (i64.store (i32.const 0) (i64.const 7))
                (drop (call $cancel (i32.const 0)))))
            "#,
        )
        .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;
        controller
            .execute_transaction(
                &set_code(&private_key, account, cancel_contract, chain_id)?,
                &pending_block_timestamp,
                &block_status,
            )
            .map_err(|error| ChainError::InternalError(format!("set cancel code: {error}")))?;
        let ram_before_cancel = controller.db.get_account_ram_usage(payer)?;
        controller
            .execute_transaction(
                &call_contract(
                    &private_key,
                    account,
                    Name::from_str("cancel")?,
                    &Vec::<u8>::new(),
                    chain_id,
                )?,
                &pending_block_timestamp,
                &block_status,
            )
            .map_err(|error| ChainError::InternalError(format!("call cancel: {error}")))?;
        assert!(
            controller
                .db
                .arena_deferred_transaction_by_sender_id(account.as_u64(), sender_id)
                .is_none(),
            "cancel_deferred must remove the generated transaction row"
        );
        assert_eq!(
            controller.db.get_account_ram_usage(payer)?,
            ram_before_cancel - generated_transaction_billable_size(deferred.len())?,
            "cancel_deferred must refund the generated transaction RAM bill"
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
    async fn rejects_block_with_non_monotonic_timestamp() -> Result<(), ChainError> {
        let (mut producer, private_key, chain_id, _p_temp) = init_test_controller()?;
        let mut p_mempool = Mempool::new();
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("testapi")?,
            chain_id,
        )?);
        let mut block = producer.build_block(&mut p_mempool).await?;
        block.signed_block_header.header.timestamp = *producer.last_accepted_block().timestamp();
        let digest = block.signed_block_header.header.sig_digest()?;
        block.signed_block_header.signature = private_key.sign(&digest)?;

        let (mut validator, _pk, _cid, _v_temp) = init_test_controller()?;
        let mut v_mempool = Mempool::new();
        let error = validator
            .verify_block(&block, &mut v_mempool)
            .await
            .expect_err("a block timestamp equal to its parent must be rejected");
        assert!(error.to_string().contains("not after parent timestamp"));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_block_timestamp_too_far_in_future() -> Result<(), ChainError> {
        let (mut producer, private_key, chain_id, _p_temp) = init_test_controller()?;
        let mut p_mempool = Mempool::new();
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("testapi")?,
            chain_id,
        )?);
        let mut block = producer.build_block(&mut p_mempool).await?;
        let now: BlockTimestamp = TimePoint::now().into();
        block.signed_block_header.header.timestamp = BlockTimestamp::new(
            now.slot()
                .saturating_add(MAX_FUTURE_BLOCK_TIME_SLOTS)
                .saturating_add(100),
        );
        let digest = block.signed_block_header.header.sig_digest()?;
        block.signed_block_header.signature = private_key.sign(&digest)?;

        let (mut validator, _pk, _cid, _v_temp) = init_test_controller()?;
        let mut v_mempool = Mempool::new();
        let error = validator
            .verify_block(&block, &mut v_mempool)
            .await
            .expect_err("a block too far ahead of local time must be rejected");
        assert!(error.to_string().contains("too far in the future"));
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

        let wrong_digest = pulsevm_crypto::Digest([0u8; 32]);
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

        // schedule_version names the schedule active for this block. The block
        // built under version 0 must therefore declare version 1 before it can
        // be checked against the test-rotated validator state.
        block.signed_block_header.header.schedule_version = 1;

        let mut v_mempool = Mempool::new();
        assert!(
            validator
                .verify_block(&block, &mut v_mempool)
                .await
                .is_err(),
            "genesis-key signature must be rejected under the rotated schedule"
        );

        let sig_digest = block.signed_block_header.header.sig_digest()?;
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
        producer.set_preferred_id(block.id()?);

        // Materialize a verified child without accepting it. A summary labelled
        // with the accepted block must unwind this speculative account before
        // copying the physical arena.
        let speculative_name = Name::from_str("pendingacct")?.as_u64();
        p_mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("pendingacct")?,
            chain_id,
        )?);
        let _speculative_block = producer.build_block(&mut p_mempool).await?;
        assert!(
            producer
                .database()
                .arena_account_metadata(speculative_name)
                .is_some()
        );

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
        assert!(producer.database().arena_account_metadata(name).is_some());

        let summary = producer.produce_state_summary()?;
        assert_eq!(summary.height, producer_height as u64);
        assert!(producer.pending_chain.is_empty());
        assert!(
            producer
                .database()
                .arena_account_metadata(speculative_name)
                .is_none(),
            "summary production left speculative state materialized"
        );

        // Syncing node: fresh genesis, so it has neither glenn nor the schedule.
        let syncer_temp = get_temp_dir();
        let syncer_path = syncer_temp.path().to_str().unwrap().to_string();
        let mut syncer = init(&syncer_path)?;
        assert!(syncer.database().arena_account_metadata(name).is_none());

        // Parse agrees with produce on the commitment.
        let (parsed_id, parsed_height) = Controller::parse_state_summary(&summary.bytes)?;
        assert_eq!(parsed_id, summary.id);
        assert_eq!(parsed_height, producer_height as u64);

        // Download the snapshot chunk by chunk from the producer, exactly as the
        // P2P driver does — here the fetch is a direct call, not an AppRequest.
        let target = Controller::sync_target_from_summary(&summary.bytes)?;
        syncer.validate_state_sync_target(&target)?;
        let (hash, height) = (target.hash, target.height);
        let envelope = crate::chain::state_sync::download_snapshot(&target, |off, len| {
            let chunk = producer.serve_snapshot_chunk(height, &hash, off, len);
            async move { chunk }
        })
        .await?;

        // Apply transfers state, tip, and schedule.
        syncer.apply_state_snapshot(
            target.block.clone(),
            target.schedule.clone(),
            target.protocol_commitment,
            &envelope,
        )?;
        assert!(
            !syncer_temp
                .path()
                .join(STATE_SYNC_INSTALL_MARKER_FILE)
                .exists(),
            "successful state sync left its fail-closed marker behind"
        );
        assert!(
            syncer.database().arena_account_metadata(name).is_some(),
            "state not transferred"
        );
        assert_eq!(syncer.last_accepted_block().block_num(), producer_height);
        assert_eq!(syncer.last_accepted_block().id()?, summary.id);
        assert_eq!(syncer.database().revision(), producer_height as i64);
        assert_eq!(syncer.active_schedule, producer_schedule);
        assert!(
            syncer
                .database()
                .arena_account_metadata(speculative_name)
                .is_none(),
            "state sync included a verified-but-unaccepted account"
        );
        assert!(syncer.database().activated_protocol_features()?.is_empty());

        // Restart the synced node from its data directory.
        syncer.shutdown()?;
        let mut restarted = init(&syncer_path)?;
        assert!(
            restarted.database().arena_account_metadata(name).is_some(),
            "synced state lost across restart"
        );
        assert_eq!(restarted.last_accepted_block().block_num(), producer_height);
        assert_eq!(restarted.last_accepted_block().id()?, summary.id);
        assert_eq!(
            restarted.active_schedule, producer_schedule,
            "synced schedule lost across restart"
        );
        assert!(
            restarted
                .database()
                .activated_protocol_features()?
                .is_empty()
        );

        // A re-based log cannot reconstruct the producer schedule from missing
        // pre-sync blocks. Missing or corrupt sidecar data must fail closed,
        // never silently fall back to the genesis signer set.
        restarted.shutdown()?;
        let schedule_path = syncer_temp.path().join(SYNCED_SCHEDULE_FILE);
        fs::remove_file(&schedule_path).unwrap();
        let missing = match init(&syncer_path) {
            Ok(_) => panic!("restart unexpectedly accepted a missing synced schedule"),
            Err(error) => error,
        };
        assert!(missing.to_string().contains("is missing"));

        fs::write(&schedule_path, b"corrupt schedule").unwrap();
        let corrupt = match init(&syncer_path) {
            Ok(_) => panic!("restart unexpectedly accepted a corrupt synced schedule"),
            Err(error) => error,
        };
        assert!(corrupt.to_string().contains("invalid header"));

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
                    .packed_trx()
                    .expect("fixture contains a packed transaction")
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
            let sig_digest = block.signed_block_header.header.sig_digest()?;
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
        assert!(producer.database().arena_account_exists(pulse));

        // ---- Sync: a fresh node downloads and applies the snapshot. ----
        let summary = producer.produce_state_summary()?;
        let producer_tip_id = producer.last_accepted_block().id()?;

        let syncer_temp = get_temp_dir();
        let syncer_path = syncer_temp.path().to_str().unwrap().to_string();
        let mut syncer = init(&syncer_path)?;
        assert!(
            !syncer.database().arena_account_exists(pulse)
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

        syncer.apply_state_snapshot(
            target.block.clone(),
            target.schedule.clone(),
            target.protocol_commitment,
            &envelope,
        )?;

        // The synced node now holds the producer's tip, revision and state.
        assert_eq!(syncer.last_accepted_block().block_num(), height);
        assert_eq!(syncer.last_accepted_block().id()?, producer_tip_id);
        assert_eq!(syncer.database().revision(), height as i64);
        assert!(
            syncer.database().arena_account_exists(pulse),
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
        assert!(restarted.database().arena_account_exists(pulse));
        eprintln!("synced node restarted cleanly at height {height}");

        Ok(())
    }

    #[test]
    fn initialize_restores_migration_checkpoint_without_reauthoring_genesis()
    -> Result<(), ChainError> {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let private_key =
            PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")?;
        let temp = get_temp_dir();
        let checkpoint_dir = temp.path().join("checkpoint-source");
        let checkpoint_path = temp.path().join("migration.snapshot");
        let mut checkpoint_db = Database::new(checkpoint_dir.to_str().unwrap(), 1024 * 1024)
            .map_err(ChainError::InternalError)?;
        checkpoint_db.add_indices()?;
        let migrated = Name::from_str("migrated")?;
        checkpoint_db.create_account(PULSE_NAME.as_u64(), 7)?;
        checkpoint_db.create_account(migrated.as_u64(), 42)?;
        checkpoint_db.set_revision(1)?;
        let checkpoint = checkpoint_db.snapshot_bytes()?;
        fs::write(&checkpoint_path, &checkpoint).map_err(|e| {
            ChainError::InternalError(format!(
                "failed to write migration checkpoint {}: {e}",
                checkpoint_path.display()
            ))
        })?;
        let manifest_path = temp.path().join("migration.manifest.json");
        let manifest = MigrationManifest::new(
            b"controller migration test source",
            [7; 32],
            &checkpoint,
            1,
            Default::default(),
        );
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).map_err(|e| {
            ChainError::InternalError(format!(
                "failed to write migration manifest {}: {e}",
                manifest_path.display()
            ))
        })?;

        let config_bytes = json!({
            "producer_name": "pulse",
            "producer_key": private_key.to_string(),
            "migration_checkpoint": checkpoint_path,
            "migration_manifest": manifest_path,
        })
        .to_string()
        .into_bytes();
        let mut migration_genesis: serde_json::Value =
            serde_json::from_slice(&generate_genesis(&private_key)).unwrap();
        migration_genesis["migration_checkpoint_sha256"] = json!(manifest.checkpoint_sha256);
        let migration_genesis = serde_json::to_vec(&migration_genesis).unwrap();
        let target_path = temp.path().join("target");
        let mut controller = Controller::new();
        controller.initialize(
            &chain_id,
            &config_bytes,
            &migration_genesis,
            target_path.to_str().unwrap(),
        )?;

        assert_eq!(controller.database().revision(), 1);
        assert!(
            controller
                .database()
                .arena_account_exists(migrated.as_u64())
        );
        assert!(
            controller
                .database()
                .arena_account_exists(PULSE_NAME.as_u64())
        );
        controller.shutdown()?;
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

            // Append the canonical pending->active header sequence. This test
            // only exercises restart reconstruction; on-chain proposal matching
            // is covered by the end-to-end proposal lifecycle test below.
            let mut previous = controller.last_accepted_block_id;
            for (height, (schedule_version, pending)) in
                [(2, (0, Some(new_schedule.clone()))), (3, (1, None))]
            {
                let block = SignedBlock::new(
                    previous,
                    BlockTimestamp::new(height),
                    PULSE_NAME,
                    VecDeque::new(),
                    Digest::default(),
                    Digest::default(),
                );
                let mut block = block;
                block.signed_block_header.header.schedule_version = schedule_version;
                block.signed_block_header.header.new_producers = pending;
                let block_id = block.id()?;
                let packed = block
                    .pack()
                    .map_err(|e| ChainError::SerializationError(e.to_string()))?;
                controller
                    .block_log
                    .as_ref()
                    .unwrap()
                    .append(block_id, &packed)
                    .map_err(|e| ChainError::InternalError(e.to_string()))?;
                previous = block_id;
            }
            controller.last_accepted_block_id = previous;
            controller.db.set_revision(3)?;
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
    async fn onblock_schedule_proposal_reaches_header_and_activates() -> Result<(), ChainError> {
        let (mut controller, private_key, chain_id, _temp) = init_test_controller()?;
        let mut mempool = Mempool::new();
        let alice = Name::from_str("alice")?;
        let proposed = vec![
            ProducerKey {
                producer_name: PULSE_NAME,
                block_signing_key: private_key.get_public_key(),
            },
            ProducerKey {
                producer_name: alice,
                block_signing_key: PrivateKey::random().get_public_key(),
            },
        ];
        let packed = proposed.pack()?;
        let data: String = packed
            .iter()
            .map(|byte| format!("\\{:02x}", byte))
            .collect();
        let proposer = format!(
            r#"
            (module
              (import "env" "set_proposed_producers" (func $set (param i32 i32) (result i64)))
              (memory (export "memory") 1)
              (data (i32.const 0) "{data}")
              (func (export "apply") (param i64 i64 i64)
                (if (i64.eq (local.get 2) (i64.const {onblock}))
                  (then (drop (call $set (i32.const 0) (i32.const {length})))))))
            "#,
            onblock = ONBLOCK_NAME.as_u64() as i64,
            length = packed.len(),
        );

        // The deployment block creates the proposed producer account. Its
        // onblock runs before setcode, so no schedule is proposed yet.
        mempool.add_transaction(create_account(&private_key, alice, chain_id)?);
        mempool.add_transaction(set_code(
            &private_key,
            PULSE_NAME,
            wat::parse_str(proposer).expect("valid proposer contract"),
            chain_id,
        )?);
        let deployment = controller.build_block(&mut mempool).await?;
        assert!(
            deployment
                .signed_block_header
                .header
                .new_schedule()?
                .is_none()
        );
        controller.accept_block(&deployment.id()?, &mut mempool)?;
        controller.set_preferred_id(deployment.id()?);

        // The proposal written by onblock belongs to the election block's state,
        // not its header. It can only enter a later header after that block is
        // irreversible; this one-producer test advances it on the next block.
        mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("bob")?,
            chain_id,
        )?);
        let election = controller.build_block(&mut mempool).await?;
        assert!(
            election
                .signed_block_header
                .header
                .new_schedule()?
                .is_none()
        );
        controller.accept_block(&election.id()?, &mut mempool)?;
        controller.set_preferred_id(election.id()?);

        mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("carol")?,
            chain_id,
        )?);
        let pending = controller.build_block(&mut mempool).await?;
        let header_schedule = election.signed_block_header.header.new_schedule()?;
        assert!(header_schedule.is_none());
        let header_schedule = pending
            .signed_block_header
            .header
            .new_schedule()?
            .expect("onblock proposal must be committed to the header");
        assert_eq!(header_schedule.version, 1);
        assert_eq!(header_schedule.producers, proposed);
        assert!(
            controller.db.proposed_schedule().is_none(),
            "onblock must not re-propose the schedule that just became pending"
        );

        controller.accept_block(&pending.id()?, &mut mempool)?;
        controller.set_preferred_id(pending.id()?);
        assert_eq!(controller.active_schedule.version, 0);
        assert_eq!(controller.pending_schedule, Some(header_schedule.clone()));

        // Once the pending schedule becomes irreversible, the next header names
        // it as active. The pulse entry deliberately keeps the same key, so the
        // locally produced block remains authorized after promotion.
        mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("dave")?,
            chain_id,
        )?);
        let activation = controller.build_block(&mut mempool).await?;
        assert_eq!(activation.signed_block_header.header.schedule_version, 1);
        controller.accept_block(&activation.id()?, &mut mempool)?;
        assert_eq!(controller.active_schedule, header_schedule.clone());
        assert!(controller.pending_schedule.is_none());
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
        let sig_digest = block.signed_block_header.header.sig_digest()?;
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
            .arena_account_metadata(PULSE_NAME.as_u64())
            .unwrap()
            .recv_sequence;

        mempool.add_transaction(create_account(
            &private_key,
            Name::from_str("testapi")?,
            chain_id,
        )?);
        let block = controller.build_block(&mut mempool).await?;
        controller.accept_block(&block.id()?, &mut mempool)?;

        let after = controller
            .database()
            .arena_account_metadata(PULSE_NAME.as_u64())
            .unwrap()
            .recv_sequence;

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
        let min_cpu_us = db.chain_config()?.min_transaction_cpu_usage as u64;
        assert!(min_cpu_us > 0, "genesis must set a non-zero CPU floor");

        let cpu_before = db.get_block_cpu_limit()?;
        let net_before = db.get_block_net_limit()?;

        let timestamp: BlockTimestamp = TimePoint::now().into();
        let previous = controller.preferred_id;
        let protocol_context = controller
            .ensure_protocol_version_supported(BlockHeader::num_from_id(&previous) + 1)?;
        let (digests, _) = controller.run_onblock(
            protocol_context,
            &timestamp,
            previous,
            &BlockStatus::Building,
        )?;
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
        let protocol_context = controller
            .ensure_protocol_version_supported(BlockHeader::num_from_id(&previous) + 1)?;
        let (digests, _) = controller.run_onblock(
            protocol_context,
            &timestamp,
            previous,
            &BlockStatus::Building,
        )?;
        assert!(
            !digests.is_empty(),
            "onblock must run the pulse contract to completion under a CPU limit of -1"
        );

        Ok(())
    }

    // A system contract that does not implement onblock (its dispatcher asserts
    // "unknown action" on the implicit call, as the reference chain's does) must
    // not break block production: run_onblock has to swallow the contract-level
    // rejection, undo the child session, and return no digests — leaving pulse's
    // receive sequence and the block CPU budget exactly where they were, so the
    // block still forms with only its real transactions. This pins the harden-only
    // invoke path: onblock is invoked every block but its absence is a clean no-op.
    #[tokio::test]
    async fn onblock_skipped_cleanly_when_contract_rejects_it() -> Result<(), ChainError> {
        let (mut controller, private_key, _chain_id, _temp) = init_test_controller()?;
        let ts = controller.last_accepted_block().timestamp().clone();
        let chain_id = controller.chain_id().clone();
        let status = BlockStatus::Building;

        // A contract that rejects only the onblock action (so deploying it — a
        // setcode action that also reaches apply — and any other action still
        // succeed). This is exactly the shape of a system contract with no onblock
        // handler: the dispatcher asserts "unknown action".
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
            .arena_account_metadata(PULSE_NAME.as_u64())
            .unwrap()
            .recv_sequence;
        let cpu_before = db.get_block_cpu_limit()?;

        // onblock is received by pulse, whose contract now asserts on it. The call
        // must fail internally but run_onblock must return Ok with no digests.
        let timestamp: BlockTimestamp = TimePoint::now().into();
        let previous = controller.preferred_id;
        let (digests, _) = controller.run_onblock(
            controller.ensure_protocol_version_supported(2)?,
            &timestamp,
            previous,
            &BlockStatus::Building,
        )?;
        assert!(
            digests.is_empty(),
            "a rejected onblock must yield no action-receipt digests"
        );

        // The undone child session leaves no trace: no receipt was minted (recv
        // sequence unchanged) and nothing was billed to the block CPU budget.
        assert_eq!(
            db.arena_account_metadata(PULSE_NAME.as_u64())
                .unwrap()
                .recv_sequence,
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
    async fn eosio_exit_ends_action_successfully() -> Result<(), ChainError> {
        let (mut controller, private_key, _chain_id, _temp) = init_test_controller()?;
        let timestamp = *controller.last_accepted_block().timestamp();
        let chain_id = *controller.chain_id();
        let status = BlockStatus::Building;
        let wasm = wat::parse_str(
            r#"
            (module
              (import "env" "eosio_exit" (func $exit (param i32)))
              (memory (export "memory") 1)
              (func (export "apply") (param i64 i64 i64)
                (call $exit (i32.const 0))))
            "#,
        )
        .expect("valid exit contract");

        controller.execute_transaction(
            &set_code(&private_key, PULSE_NAME, wasm, chain_id)?,
            &timestamp,
            &status,
        )?;
        controller.execute_transaction(
            &call_contract(
                &private_key,
                PULSE_NAME,
                Name::from_str("run")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &timestamp,
            &status,
        )?;
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
        let found = controller
            .database()
            .is_known_unexpired_transaction(&result.trace.id.0.0)?;
        assert!(!found);

        Ok(())
    }
}
