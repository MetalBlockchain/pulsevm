use std::{
    cmp::min,
    collections::{
        BTreeSet,
        VecDeque,
    },
    sync::{
        Arc,
        RwLock,
    },
    time::{
        Duration,
        Instant,
    },
};

use crate::{
    authorization_manager::AuthorizationManager,
    block::BlockStatus,
    chain::{
        apply_context::{
            ApplyContext,
            validate_inline_action,
        },
        id::Id,
        name::Name,
        producer_schedule::{
            ProducerKey,
            ProducerSchedule,
        },
        protocol_features::{
            ProtocolExecutionContext,
            ProtocolFeature,
            ProtocolVersion,
        },
        resource_limits::ResourceLimitsManager,
        transaction::{
            ACTION_RETURN_VALUE_FEATURE_DIGEST,
            Action,
            ActionReceipt,
            ActionTrace,
            Transaction,
            TransactionStatus,
            TransactionTrace,
            generate_action_digest,
        },
        utils::pulse_assert,
        wasm_runtime::WasmRuntime,
    },
    transaction::PackedTransaction,
};
use pulsevm_constants::MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER;
use pulsevm_crypto::Digest;
use pulsevm_database::{
    BlockTimestamp,
    Database,
    Microseconds,
    TimePoint,
    TransactionDependencies,
    seconds,
};
use pulsevm_error::ChainError;
use pulsevm_serialization::{
    CanonicalMap,
    VarUint32,
    Write,
};

// Leap's ONLY_BILL_FIRST_AUTHORIZER feature changes transaction CPU/NET
// billing from every action authorizer to only the first authorizer. XPR has
// this feature active; keeping the gate matters for replaying earlier history
// and for chains that have not activated it yet.
const ONLY_BILL_FIRST_AUTHORIZER_FEATURE_DIGEST: [u8; 32] = [
    0x8b, 0xa5, 0x2f, 0xe7, 0xa3, 0x95, 0x6c, 0x5c, 0xd3, 0xa6, 0x56, 0xa3, 0x17, 0x4b, 0x93, 0x1d,
    0x3b, 0xb2, 0xab, 0xb4, 0x55, 0x78, 0xbe, 0xfc, 0x59, 0xf2, 0x83, 0xec, 0xd8, 0x16, 0xa4, 0x05,
];

const EOSIO_NULL: u64 = 6_138_663_588_472_832_000;
const NONCE: u64 = 11_323_884_548_116_185_088;
const BENCHMARK: u64 = 4_226_213_497_500_860_416;

fn is_xpr_mechanics_benchmark_transaction(transaction: &Transaction) -> bool {
    let [context_free] = transaction.context_free_actions.as_slice() else {
        return false;
    };
    let [cpu] = transaction.actions.as_slice() else {
        return false;
    };
    let [authorization] = cpu.authorization() else {
        return false;
    };

    context_free.account().as_u64() == EOSIO_NULL
        && context_free.name().as_u64() == NONCE
        && context_free.authorization().is_empty()
        && context_free.data().len() == 8
        && cpu.account().as_u64() == super::xpr_native_replay::MECHANICS
        && cpu.name().as_u64() == super::xpr_native_replay::CPU
        && cpu.data().is_empty()
        && authorization.actor() == super::xpr_native_replay::MECHANICS
        && authorization.permission() == BENCHMARK
}

/// Execute the historical XPR CPU benchmark transaction without allocating a
/// TransactionContext/ApplyContext graph. The deployed `mechanics::cpu` body is
/// a code-hash-pinned, state-free loop; accepted replay takes its CPU/NET bill
/// from the signed receipt. Every persistent side effect of the transaction is
/// still reproduced here.
pub(super) fn try_execute_xpr_mechanics_from_block(
    db: &mut Database,
    cache: &mut super::xpr_native_replay::DirectBotOracleCache,
    transaction: &Transaction,
    transaction_id: &Id,
    pending: &BlockTimestamp,
    cpu_usage_us: u32,
    net_usage_words: u32,
) -> Result<Option<VecDeque<Digest>>, ChainError> {
    if !db.xpr_native_replay_enabled()
        || !db.protocol_feature_activated(ONLY_BILL_FIRST_AUTHORIZER_FEATURE_DIGEST)
        || !is_xpr_mechanics_benchmark_transaction(transaction)
    {
        return Ok(None);
    }

    transaction.validate(pending)?;
    let expiration: TimePoint = transaction.header.expiration().into();
    let pending_time: TimePoint = (*pending).into();
    let max_lifetime = db.chain_config()?.max_transaction_lifetime;
    if expiration < pending_time {
        return Err(ChainError::TransactionError("transaction expired".into()));
    }
    if expiration > pending_time + seconds(i64::from(max_lifetime)) {
        return Err(ChainError::TransactionError(
            "transaction has too long lifetime".into(),
        ));
    }

    let context_free = &transaction.context_free_actions[0];
    let cpu = &transaction.actions[0];
    if !db.is_account(EOSIO_NULL)? || !db.is_account(super::xpr_native_replay::MECHANICS)? {
        return Err(ChainError::TransactionError(
            "mechanics benchmark references a non-existent account".into(),
        ));
    }
    let authorization = &cpu.authorization()[0];
    if AuthorizationManager::find_permission(&db.read()?, authorization)?.is_none() {
        return Err(ChainError::TransactionError(format!(
            "action's authorizations include a non-existent permission: {authorization}"
        )));
    }

    let null_metadata = db.action_execution_metadata(EOSIO_NULL, EOSIO_NULL)?;
    let mechanics_metadata = db.action_execution_metadata(
        super::xpr_native_replay::MECHANICS,
        super::xpr_native_replay::MECHANICS,
    )?;
    if null_metadata.code_hash != [0; 32]
        || mechanics_metadata.code_hash != super::xpr_native_replay::XPR_MECHANICS_CODE_HASH
    {
        return Ok(None);
    }

    let billed_account = Name::new(super::xpr_native_replay::MECHANICS);
    db.record_transaction(
        &transaction_id.0.0,
        transaction.header.expiration().sec_since_epoch(),
    )
    .map_err(|error| ChainError::DatabaseError(format!("duplicate tx: {error}")))?;

    let action_digests = VecDeque::from([
        direct_action_receipt_digest(
            db,
            context_free,
            Name::new(EOSIO_NULL),
            null_metadata.code_sequence,
            null_metadata.abi_sequence,
        )?,
        direct_action_receipt_digest(
            db,
            cpu,
            billed_account,
            mechanics_metadata.code_sequence,
            mechanics_metadata.abi_sequence,
        )?,
    ]);
    cache.record_permission_usage(authorization.actor(), authorization.permission());
    ResourceLimitsManager::add_transaction_usage(
        db,
        &billed_account,
        u64::from(cpu_usage_us),
        u64::from(net_usage_words) * 8,
        pending.slot(),
        true,
    )?;

    Ok(Some(action_digests))
}

/// Execute the common code-hash-pinned XPR bot transaction while replaying an
/// accepted block, without constructing the transaction/trace `Arc<RwLock>`
/// graph. This remains deliberately narrower than `TransactionContext`: every
/// unsupported shape returns `None` before consensus state is changed, and the
/// caller immediately uses the canonical path.
pub(super) fn try_execute_xpr_bot_from_block(
    db: &mut Database,
    cache: &mut super::xpr_native_replay::DirectBotOracleCache,
    transaction: &Transaction,
    transaction_id: &Id,
    pending: &BlockTimestamp,
    cpu_usage_us: u32,
    net_usage_words: u32,
) -> Result<Option<VecDeque<Digest>>, ChainError> {
    let profiling = super::replay_profile::enabled();
    let total_started = profiling.then(Instant::now);
    let admission_started = profiling.then(Instant::now);
    if !db.xpr_native_replay_enabled()
        || !db.protocol_feature_activated(ONLY_BILL_FIRST_AUTHORIZER_FEATURE_DIGEST)
    {
        super::replay_profile::record_native_decline("direct_bot_disabled");
        return Ok(None);
    }
    if !transaction.context_free_actions.is_empty() || transaction.actions.len() != 1 {
        super::replay_profile::record_native_decline("transaction_shape");
        return Ok(None);
    }

    let parent = &transaction.actions[0];
    if parent.account().as_u64() != super::xpr_native_replay::BOT
        || parent.name().as_u64() != super::xpr_native_replay::PROCESS
    {
        super::replay_profile::record_native_decline("non_bot_action");
        return Ok(None);
    }

    // These are the accepted-block portions of init_for_input_trx_from_block.
    // They are state/consensus checks, unlike producer-side signature and
    // objective bandwidth admission, and therefore cannot be skipped.
    transaction.validate(pending)?;
    let expiration: TimePoint = transaction.header.expiration().into();
    let pending_time: TimePoint = (*pending).into();
    let max_lifetime = db.chain_config()?.max_transaction_lifetime;
    if expiration < pending_time {
        return Err(ChainError::TransactionError("transaction expired".into()));
    }
    if expiration > pending_time + seconds(i64::from(max_lifetime)) {
        return Err(ChainError::TransactionError(
            "transaction has too long lifetime".into(),
        ));
    }
    let first_authorizer = parent.authorization().first().ok_or_else(|| {
        ChainError::TransactionError("transaction must have at least one authorization".into())
    })?;
    let oracle = Name::new(super::xpr_native_replay::ORACLES);
    let admission_elapsed = admission_started.map_or(Duration::ZERO, |started| started.elapsed());
    let metadata_started = profiling.then(Instant::now);
    let admission_key = (parent.authorization().len() == 1).then_some((
        parent.account().as_u64(),
        first_authorizer.actor(),
        first_authorizer.permission(),
    ));
    let (parent_metadata, oracle_metadata) =
        if let Some(metadata) = admission_key.and_then(|key| cache.admission(key)) {
            metadata
        } else {
            if !db.is_account(parent.account().as_u64())? {
                return Err(ChainError::TransactionError(format!(
                    "action {} references non-existent account {}",
                    parent.name(),
                    parent.account()
                )));
            }
            for authorization in parent.authorization() {
                if !db.is_account(authorization.actor())? {
                    return Err(ChainError::TransactionError(format!(
                        "action's authorizing actor '{}' does not exist",
                        Name::new(authorization.actor())
                    )));
                }
                if AuthorizationManager::find_permission(&db.read()?, authorization)?.is_none() {
                    return Err(ChainError::TransactionError(format!(
                        "action's authorizations include a non-existent permission: {authorization}"
                    )));
                }
            }
            let parent_metadata =
                db.action_execution_metadata(parent.account().as_u64(), parent.account().as_u64())?;
            let oracle_metadata = db.action_execution_metadata(oracle.as_u64(), oracle.as_u64())?;
            let parent_metadata = super::xpr_native_replay::CachedActionMetadata {
                privileged: parent_metadata.privileged,
                code_hash: parent_metadata.code_hash,
                code_sequence: parent_metadata.code_sequence,
                abi_sequence: parent_metadata.abi_sequence,
            };
            let oracle_metadata = super::xpr_native_replay::CachedActionMetadata {
                privileged: oracle_metadata.privileged,
                code_hash: oracle_metadata.code_hash,
                code_sequence: oracle_metadata.code_sequence,
                abi_sequence: oracle_metadata.abi_sequence,
            };
            if let Some(key) = admission_key {
                cache.cache_admission(key, parent_metadata, oracle_metadata);
            }
            (parent_metadata, oracle_metadata)
        };
    let metadata_elapsed = metadata_started.map_or(Duration::ZERO, |started| started.elapsed());

    // The typed block cache promotes a private clone only after the complete
    // native transition succeeds, so a decline cannot leave staged row bytes.
    let state_started = profiling.then(Instant::now);
    let mut result = {
        let Some(mut result) = super::xpr_native_replay::try_apply_bot_transaction_direct_cached(
            db,
            cache,
            *pending,
            transaction_id.0.0,
            parent,
            &parent_metadata.code_hash,
            &oracle_metadata.code_hash,
        )?
        else {
            return Ok(None);
        };
        result.profile.admission = admission_elapsed;
        result.profile.metadata = metadata_elapsed;
        let internal_state = result.profile.decode
            + result.profile.cache_clone
            + result.profile.bot_rows
            + result.profile.oracle_rows
            + result.profile.cache_commit;
        let measured_state = state_started.map_or(Duration::ZERO, |started| started.elapsed());
        // Attribute small glue costs inside the state transition to decode so
        // the reported phases still add up to the observed wall time.
        result.profile.decode += measured_state.saturating_sub(internal_state);
        if !result.inline_actions.is_empty() && db.chain_config()?.max_inline_action_depth == 0 {
            return Err(ChainError::TransactionError(
                "max inline action depth per transaction reached".into(),
            ));
        }
        let inline_auth_started = profiling.then(Instant::now);
        for inline in &result.inline_actions {
            let authorization = inline.authorization();
            let cache_key = (authorization.len() == 1).then(|| {
                (
                    parent.account().as_u64(),
                    inline.account().as_u64(),
                    inline.name().as_u64(),
                    authorization[0].actor,
                    authorization[0].permission,
                )
            });
            if cache_key.is_none_or(|key| !db.xpr_native_inline_authorization_cached(key)) {
                validate_inline_action(
                    db,
                    parent,
                    *parent.account(),
                    parent_metadata.privileged,
                    inline,
                )?;
                if let Some(key) = cache_key {
                    db.cache_xpr_native_inline_authorization(key);
                }
            }
        }
        result.profile.inline_auth =
            inline_auth_started.map_or(Duration::ZERO, |started| started.elapsed());
        result
    };

    // Everything below is required consensus mutation. Any failure rejects the
    // containing block, whose outer undo session restores these writes.
    let transaction_ram_started = profiling.then(Instant::now);
    let billed_account = Name::new(first_authorizer.actor());
    db.record_transaction(
        &transaction_id.0.0,
        transaction.header.expiration().sec_since_epoch(),
    )
    .map_err(|error| ChainError::DatabaseError(format!("duplicate tx: {error}")))?;

    let mut ram_accounts = Vec::with_capacity(result.ram_deltas.len());
    for (account, delta) in &result.ram_deltas {
        db.add_pending_ram_usage(*account, *delta)?;
        if !ram_accounts.contains(account) {
            ram_accounts.push(*account);
        }
    }
    for account in ram_accounts {
        ResourceLimitsManager::verify_account_ram_usage(db, &Name::new(account))?;
    }
    result.profile.transaction_and_ram =
        transaction_ram_started.map_or(Duration::ZERO, |started| started.elapsed());

    let receipts_started = profiling.then(Instant::now);
    let mut action_digests = VecDeque::with_capacity(1 + result.inline_actions.len());
    action_digests.push_back(direct_action_receipt_digest(
        db,
        parent,
        *parent.account(),
        parent_metadata.code_sequence,
        parent_metadata.abi_sequence,
    )?);
    for inline in &result.inline_actions {
        action_digests.push_back(direct_action_receipt_digest(
            db,
            inline,
            oracle,
            oracle_metadata.code_sequence,
            oracle_metadata.abi_sequence,
        )?);
    }
    result.profile.receipts = receipts_started.map_or(Duration::ZERO, |started| started.elapsed());

    let resources_started = profiling.then(Instant::now);
    for authorization in parent.authorization() {
        cache.record_permission_usage(authorization.actor(), authorization.permission());
    }
    // add_transaction_usage performs the same accumulator decay that
    // init_for_input_trx_from_block's preceding zero-unit update performs. No
    // audited bot action observes resource usage between init and finalize, so
    // one call produces byte-identical usage rows without the redundant Arena
    // write/undo entry.
    ResourceLimitsManager::add_transaction_usage(
        db,
        &billed_account,
        u64::from(cpu_usage_us),
        u64::from(net_usage_words) * 8,
        pending.slot(),
        true,
    )?;
    result.profile.resources =
        resources_started.map_or(Duration::ZERO, |started| started.elapsed());
    result.profile.total = total_started.map_or(Duration::ZERO, |started| started.elapsed());
    super::replay_profile::record_native_bot(result.profile);

    Ok(Some(action_digests))
}

fn direct_action_receipt_digest(
    db: &mut Database,
    action: &Action,
    receiver: Name,
    code_sequence: u64,
    abi_sequence: u64,
) -> Result<Digest, ChainError> {
    let auth_actors = action
        .authorization()
        .iter()
        .map(|authorization| authorization.actor)
        .collect::<Vec<_>>();
    let (global_sequence, recv_sequence, auth_sequences) =
        db.next_action_sequences(receiver.as_u64(), &auth_actors)?;
    let action_return_value = db
        .protocol_feature_activated(ACTION_RETURN_VALUE_FEATURE_DIGEST)
        .then_some(&[][..]);
    let mut receipt = ActionReceipt::new(
        receiver,
        generate_action_digest(action, action_return_value),
        global_sequence,
        recv_sequence,
        CanonicalMap::new(),
        code_sequence as u32,
        abi_sequence as u32,
    );
    for (authorization, sequence) in action.authorization().iter().zip(auth_sequences) {
        receipt.add_auth_sequence(authorization.actor, sequence);
    }
    receipt.digest().map_err(ChainError::from)
}

fn billed_accounts_for_transaction(
    transaction: &Transaction,
    first_authorizer: Name,
    only_bill_first: bool,
) -> BTreeSet<Name> {
    if only_bill_first {
        return [first_authorizer].into_iter().collect();
    }
    transaction
        .actions
        .iter()
        .flat_map(|action| {
            action
                .authorization()
                .iter()
                .map(|auth| Name::new(auth.actor()))
        })
        .collect()
}
#[derive(Default, Clone)]
struct Billing {
    paused_time: TimePoint,
    pseudo_start: TimePoint,
    billed_time: Microseconds,
}

pub struct TransactionResult {
    pub trace: TransactionTrace,
    pub billed_cpu_time_us: u32,
    pub action_receipt_digests: VecDeque<Digest>,
    // Set if a `set_proposed_producers` ran in this transaction; the controller
    // activates it when the block is accepted.
    pub proposed_schedule: Option<Vec<ProducerKey>>,
    /// Observation-only dependency report populated when parallel-wave
    /// telemetry is enabled. It never feeds transaction execution or hashing.
    pub dependencies: Option<TransactionDependencies>,
}

struct TransactionContextInner {
    initialized: bool,
    trace: TransactionTrace,
    bill_to_accounts: BTreeSet<Name>,
    validate_ram_usage: BTreeSet<Name>,
    explicit_billed_cpu_time: bool,
    // On trusted replay these carry the block-recorded CPU (µs) and NET (words)
    // so receipt reconstruction and quota accounting use the values this node
    // already validated instead of remeasuring them.
    explicit_cpu_us: u32,
    explicit_net_words: u32,
    eager_net_limit: u64,
    net_limit: u64,
    net_limit_due_to_greylist: bool,
    net_limit_due_to_block: bool,
    billing: Billing,
    // Raw wall-clock start for the subjective transaction watchdog. Unlike the
    // billing timer, this intentionally includes paused native/compilation time.
    start_time: TimePoint,
    max_transaction_time: Microseconds,
    enforce_subjective_deadline: bool,
    pending_block_timestamp: BlockTimestamp,
    published: TimePoint,
    cpu_limit: i64,
    cpu_limit_due_to_greylist: bool,
    cpu_limit_due_to_block: bool,
    executed_action_receipt_digests: VecDeque<Digest>,
    is_input: bool,
    proposed_schedule: Option<Vec<ProducerKey>>,
    active_producers: Vec<ProducerKey>,
    proposal_base_producers: Vec<ProducerKey>,
    proposal_base_schedule_version: u32,
}

#[derive(Clone)]
pub struct TransactionContext {
    db: Database,
    wasm_runtime: WasmRuntime,
    block_status: BlockStatus,
    // Consensus context selected and support-checked by the controller for the
    // exact block this transaction is executing in. Keeping it immutable and
    // carrying it through every clone prevents descendant/replay execution from
    // falling back to `last_accepted + 1`.
    protocol_context: ProtocolExecutionContext,
    packed_transaction: PackedTransaction,
    inner: Arc<RwLock<TransactionContextInner>>,
}

impl TransactionContext {
    pub fn new(
        db: Database,
        wasm_runtime: WasmRuntime,
        protocol_context: ProtocolExecutionContext,
        pending_block_timestamp: BlockTimestamp,
        transaction_id: &Id,
        block_status: BlockStatus,
        packed_transaction: PackedTransaction,
        max_transaction_time_ms: u32,
    ) -> Self {
        let mut trace = TransactionTrace::default();
        trace.id = *transaction_id;
        trace.block_num = protocol_context.block_height();
        trace.block_time = pending_block_timestamp.clone();

        Self {
            db,
            wasm_runtime,
            block_status,
            protocol_context,
            inner: Arc::new(RwLock::new(TransactionContextInner {
                initialized: false,
                trace,
                bill_to_accounts: BTreeSet::new(),
                validate_ram_usage: BTreeSet::new(),
                explicit_billed_cpu_time: false,
                explicit_cpu_us: 0,
                explicit_net_words: 0,
                eager_net_limit: 0,
                net_limit: 0,
                net_limit_due_to_greylist: false,
                net_limit_due_to_block: true,
                billing: Billing {
                    paused_time: TimePoint::default(),
                    pseudo_start: TimePoint::now(),
                    billed_time: Microseconds::default(),
                },
                start_time: TimePoint::now(),
                max_transaction_time: Microseconds::new(max_transaction_time_ms as i64 * 1_000),
                published: pending_block_timestamp.clone().into(),
                enforce_subjective_deadline: true,
                pending_block_timestamp,
                cpu_limit: 0,
                cpu_limit_due_to_greylist: false,
                cpu_limit_due_to_block: true,
                executed_action_receipt_digests: VecDeque::with_capacity(6),
                is_input: false,
                proposed_schedule: None,
                active_producers: Vec::new(),
                proposal_base_producers: Vec::new(),
                proposal_base_schedule_version: 0,
            })),
            packed_transaction,
        }
    }

    /// Validated consensus context for the block containing this transaction.
    pub fn protocol_context(&self) -> ProtocolExecutionContext {
        self.protocol_context
    }

    pub(crate) fn clear_xpr_inline_authorization_cache(&self) {
        self.db.clear_xpr_native_inline_authorization();
    }

    /// Number of the block containing this transaction.
    pub fn block_num(&self) -> u32 {
        self.protocol_context.block_height()
    }

    /// Consensus protocol version selected for this transaction's block.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_context.protocol_version()
    }

    /// Query a feature against the already support-checked block context.
    pub fn protocol_feature_enabled(&self, feature: ProtocolFeature) -> bool {
        self.protocol_context.feature_enabled(feature)
    }

    /// Record the active schedule and the schedule a new proposal must follow.
    /// Antelope exposes the active set through `get_active_producers`, but bases
    /// a new version on the pending set when one exists.
    pub fn set_producer_schedules(
        &self,
        active_producers: Vec<ProducerKey>,
        active_version: u32,
        pending_schedule: Option<(Vec<ProducerKey>, u32)>,
    ) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;
        inner.active_producers = active_producers.clone();
        let (proposal_base_producers, proposal_base_schedule_version) =
            pending_schedule.unwrap_or((active_producers, active_version));
        inner.proposal_base_producers = proposal_base_producers;
        inner.proposal_base_schedule_version = proposal_base_schedule_version;
        Ok(())
    }

    pub fn active_producers(&self) -> Result<Vec<ProducerKey>, ChainError> {
        Ok(self.inner.read()?.active_producers.clone())
    }

    pub fn init(
        &mut self,
        initial_net_usage: u64,
        first_authorizer: Option<u64>,
        is_input: bool,
    ) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;

        pulse_assert(
            inner.initialized == false,
            ChainError::TransactionError("cannot initialize twice".into()),
        )?;

        inner.initialized = true;
        inner.is_input = is_input;

        // Implicit transactions (onblock, etc.) have no CPU limit, but input transactions
        // are limited to the block's CPU limit.
        if inner.is_input {
            inner.cpu_limit = self.db.get_block_cpu_limit()? as i64;
        }

        inner.net_limit = self.db.get_block_net_limit()?;

        let net_usage_leeway = {
            let cfg = self.db.chain_config()?;

            // Possibly lower net_limit to the maximum net usage a transaction is allowed to be
            // billed
            if cfg.max_transaction_net_usage as u64 <= inner.net_limit {
                inner.net_limit = cfg.max_transaction_net_usage as u64;
                inner.net_limit_due_to_block = false;
            }

            // Possibly lower cpu_limit to the maximum cpu usage a transaction is allowed to be
            // billed
            if inner.is_input && cfg.max_transaction_cpu_usage as u64 <= inner.cpu_limit as u64 {
                inner.cpu_limit = cfg.max_transaction_cpu_usage as i64;
                inner.cpu_limit_due_to_block = false;
            }

            cfg.net_usage_leeway as u64
        };

        let trx = self.packed_transaction.get_transaction();
        let trx_specified_net_usage_limit = trx.header.max_net_usage_words().0 as u64 * 8;

        // Possibly lower net_limit to optional limit set in the transaction header
        if trx_specified_net_usage_limit > 0 && trx_specified_net_usage_limit <= inner.net_limit {
            inner.net_limit = trx_specified_net_usage_limit;
            inner.net_limit_due_to_block = false;
        }

        // Possibly lower cpu_limit to optional limit set in the transaction header
        if trx.header.max_cpu_usage() > 0 && trx.header.max_cpu_usage() as i64 <= inner.cpu_limit {
            inner.cpu_limit = trx.header.max_cpu_usage() as i64;
            inner.cpu_limit_due_to_block = false;
        }

        // Record accounts to be billed for network and CPU usage
        let Some(authorizer) = first_authorizer else {
            return Err(ChainError::TransactionError(
                "transaction has no authorizations".to_string(),
            ));
        };
        let first_authorizer_name = Name::new(authorizer);
        let only_bill_first = self
            .db
            .protocol_feature_activated(ONLY_BILL_FIRST_AUTHORIZER_FEATURE_DIGEST);
        inner.bill_to_accounts =
            billed_accounts_for_transaction(&trx, first_authorizer_name.clone(), only_bill_first);
        if inner.bill_to_accounts.is_empty() {
            return Err(ChainError::TransactionError(
                "transaction has no authorizations".to_string(),
            ));
        }

        // Update usage values of accounts to reflect new time
        for account in &inner.bill_to_accounts {
            ResourceLimitsManager::update_account_usage(
                &mut self.db,
                account,
                inner.pending_block_timestamp.slot(),
            )?;
        }

        inner.eager_net_limit = inner.net_limit;
        // When applying an accepted block the producer supplied the billed CPU
        // and net amounts.  The account-limit queries below are objective
        // admission checks only: they do not mutate state, and the explicit
        // replay path already deliberately skips their corresponding failures.
        // Avoid reading the same resource-limit rows once here and once again
        // in `finalize`; usage decay above and usage billing below are retained.
        if !inner.explicit_billed_cpu_time {
            let (account_net_limit, account_cpu_limit, greylisted_net, greylisted_cpu) =
                self.max_bandwidth_billed_accounts_can_pay(&inner.bill_to_accounts)?;

            inner.net_limit_due_to_greylist = greylisted_net;
            inner.cpu_limit_due_to_greylist = greylisted_cpu;

            let new_eager_net_limit = min(
                inner.eager_net_limit,
                (account_net_limit + net_usage_leeway as i64) as u64,
            );

            // Possibly lower eager_net_limit to what the billed account can pay plus some
            // (objective) leeway.
            if new_eager_net_limit < inner.eager_net_limit {
                inner.eager_net_limit = new_eager_net_limit;
            }

            inner.cpu_limit = min(inner.cpu_limit, account_cpu_limit);
        }
        inner.eager_net_limit = (inner.eager_net_limit / 8) * 8; // Round down to nearest multiple of word size (8 bytes)

        // add_net_usage re-locks inner; the guard must be released first or the
        // same thread deadlocks on its own write lock.
        drop(inner);

        if initial_net_usage > 0 {
            self.add_net_usage(initial_net_usage)?;
        }

        Ok(())
    }

    pub fn init_for_input_trx(
        &mut self,
        packed_trx_unprunable_size: u64,
        packed_trx_prunable_size: u64,
        transaction: &Transaction,
    ) -> Result<(), ChainError> {
        let mut discounted_size_for_pruned_data = packed_trx_prunable_size;
        let chain_config = self.db.chain_config()?;
        if chain_config.context_free_discount_net_usage_den > 0
            && chain_config.context_free_discount_net_usage_num
                < chain_config.context_free_discount_net_usage_den
        {
            discounted_size_for_pruned_data *=
                chain_config.context_free_discount_net_usage_num as u64;
            discounted_size_for_pruned_data = (discounted_size_for_pruned_data
                + chain_config.context_free_discount_net_usage_den as u64
                - 1)
                / chain_config.context_free_discount_net_usage_den as u64; // rounds up
        }

        let initial_net_usage: u64 = (chain_config.base_per_transaction_net_usage as u64)
            + packed_trx_unprunable_size
            + discounted_size_for_pruned_data;
        let first_authorizer = transaction.first_authorizer();

        self.validate_expiration(self.packed_transaction.get_transaction())?;
        self.validate_referenced_accounts(self.packed_transaction.get_transaction())?;
        self.init(initial_net_usage, first_authorizer, true)?;
        self.record_transaction(
            &transaction.id()?,
            transaction.header.expiration().sec_since_epoch(),
        )?;
        Ok(())
    }

    /// Initialize an input transaction carried by an already-accepted block.
    /// Its producer-recorded net usage makes packed-size accounting and all
    /// objective CPU/NET ceilings irrelevant, while expiration, referenced
    /// accounts, deduplication, billed-account selection, and usage decay remain
    /// consensus state and are executed normally.
    pub fn init_for_input_trx_from_block(
        &mut self,
        transaction: &Transaction,
    ) -> Result<(), ChainError> {
        self.validate_expiration(transaction)?;
        self.validate_referenced_accounts(transaction)?;

        let first_authorizer = transaction.first_authorizer().ok_or_else(|| {
            ChainError::TransactionError("transaction has no authorizations".into())
        })?;
        let only_bill_first = self
            .db
            .protocol_feature_activated(ONLY_BILL_FIRST_AUTHORIZER_FEATURE_DIGEST);
        let billed_accounts = billed_accounts_for_transaction(
            transaction,
            Name::new(first_authorizer),
            only_bill_first,
        );
        if billed_accounts.is_empty() {
            return Err(ChainError::TransactionError(
                "transaction has no authorizations".into(),
            ));
        }

        let (pending_slot, transaction_id) = {
            let mut inner = self.inner.write()?;
            pulse_assert(
                !inner.initialized,
                ChainError::TransactionError("cannot initialize twice".into()),
            )?;
            pulse_assert(
                inner.explicit_billed_cpu_time,
                ChainError::InternalError(
                    "accepted-block transaction is missing explicit billing".into(),
                ),
            )?;
            inner.initialized = true;
            inner.is_input = true;
            inner.bill_to_accounts = billed_accounts;
            (inner.pending_block_timestamp.slot(), inner.trace.id)
        };
        for account in &self.inner.read()?.bill_to_accounts {
            ResourceLimitsManager::update_account_usage(&mut self.db, account, pending_slot)?;
        }
        self.record_transaction(
            &transaction_id,
            transaction.header.expiration().sec_since_epoch(),
        )
    }

    /// Initialize a transaction retired from the durable deferred queue. Its
    /// delay and expiration were checked by the controller against the
    /// generated-transaction record, so this deliberately does not apply the
    /// input-transaction expiration/delay rule a second time. It remains an
    /// objectively billed transaction and records its id just like an input
    /// receipt, ensuring replay cannot execute it twice.
    pub fn init_for_deferred_trx(
        &mut self,
        packed_trx_unprunable_size: u64,
        packed_trx_prunable_size: u64,
        transaction: &Transaction,
        published: TimePoint,
    ) -> Result<(), ChainError> {
        self.inner.write()?.published = published;
        let mut discounted_size_for_pruned_data = packed_trx_prunable_size;
        let chain_config = self.db.chain_config()?;
        if chain_config.context_free_discount_net_usage_den > 0
            && chain_config.context_free_discount_net_usage_num
                < chain_config.context_free_discount_net_usage_den
        {
            discounted_size_for_pruned_data *=
                chain_config.context_free_discount_net_usage_num as u64;
            discounted_size_for_pruned_data = (discounted_size_for_pruned_data
                + chain_config.context_free_discount_net_usage_den as u64
                - 1)
                / chain_config.context_free_discount_net_usage_den as u64;
        }
        let initial_net_usage = chain_config.base_per_transaction_net_usage as u64
            + packed_trx_unprunable_size
            + discounted_size_for_pruned_data;
        self.validate_deferred_referenced_accounts(transaction)?;
        self.init(initial_net_usage, transaction.first_authorizer(), true)?;
        self.record_transaction(
            &transaction.id()?,
            transaction.header.expiration().sec_since_epoch(),
        )?;
        Ok(())
    }

    // Initialize for an implicit system transaction such as `onblock`. Unlike an
    // input transaction it carries no signature, is not deduplicated, bills no
    // account, and runs on behalf of the system account with no CPU ceiling —
    // so we skip expiration/authorization/net accounting entirely.
    pub fn init_for_implicit_trx(&mut self, transaction: &Transaction) -> Result<(), ChainError> {
        {
            let min_cpu = self.db.chain_config()?.min_transaction_cpu_usage;
            let mut inner = self.inner.write()?;
            inner.explicit_billed_cpu_time = true;
            inner.explicit_cpu_us = min_cpu;
            inner.cpu_limit = -1;
            inner.enforce_subjective_deadline = false;
        }
        self.init(0, transaction.first_authorizer(), false)
    }

    pub fn exec(&mut self, transaction: &Transaction) -> Result<(), ChainError> {
        // Reserve actions array
        {
            let mut inner = self.inner.write()?;
            inner
                .trace
                .action_traces
                .reserve(transaction.actions.len() + transaction.context_free_actions.len());
        }

        for action in transaction.context_free_actions.iter() {
            self.schedule_action(action.clone(), &action.account(), true, 0, 0)?;
        }

        for action in transaction.actions.iter() {
            self.schedule_action(action.clone(), &action.account(), false, 0, 0)?;
        }

        let num_original_actions_to_execute = {
            let inner = self.inner.read()?;
            inner.trace.action_traces.len()
        };

        for i in 1..=num_original_actions_to_execute {
            self.execute_action(i as u32, 0)?;
        }

        Ok(())
    }

    /// Execute the code-hash-pinned XPR bot/oracle transaction without the
    /// general ApplyContext graph. Every admission check that affects accepted
    /// replay is retained, including referenced accounts, inline authority,
    /// RAM limits, sequence allocation, receipt hashing, and resource billing.
    /// Unsupported layouts return `false` after undoing the speculative native
    /// transition so the deployed WASM path can execute unchanged.
    pub(crate) fn try_exec_xpr_bot_direct(
        &mut self,
        transaction: &Transaction,
    ) -> Result<bool, ChainError> {
        if !self.inner.read()?.explicit_billed_cpu_time
            || transaction.context_free_actions.len() != 0
            || transaction.actions.len() != 1
        {
            return Ok(false);
        }

        let parent = &transaction.actions[0];
        if parent.account().as_u64() != super::xpr_native_replay::BOT
            || parent.name().as_u64() != super::xpr_native_replay::PROCESS
        {
            return Ok(false);
        }
        let parent_metadata = self
            .db
            .action_execution_metadata(parent.account().as_u64(), parent.account().as_u64())?;
        let oracle = Name::new(super::xpr_native_replay::ORACLES);
        let oracle_metadata = self
            .db
            .action_execution_metadata(oracle.as_u64(), oracle.as_u64())?;
        let transaction_id = self.inner.read()?.trace.id.0.0;
        let pending = self.inner.read()?.pending_block_timestamp;

        self.db.xpr_native_start_row_session()?;
        let attempt = (|| {
            let Some(result) = super::xpr_native_replay::try_apply_bot_transaction_direct(
                &mut self.db,
                pending,
                transaction_id,
                parent,
                &parent_metadata.code_hash,
                &oracle_metadata.code_hash,
            )?
            else {
                return Ok(None);
            };

            if !result.inline_actions.is_empty()
                && self.db.chain_config()?.max_inline_action_depth == 0
            {
                return Err(ChainError::TransactionError(
                    "max inline action depth per transaction reached".into(),
                ));
            }
            for inline in &result.inline_actions {
                let authorization = inline.authorization();
                let cache_key = (authorization.len() == 1).then(|| {
                    (
                        parent.account().as_u64(),
                        inline.account().as_u64(),
                        inline.name().as_u64(),
                        authorization[0].actor,
                        authorization[0].permission,
                    )
                });
                if cache_key.is_none_or(|key| !self.db.xpr_native_inline_authorization_cached(key))
                {
                    validate_inline_action(
                        &mut self.db,
                        parent,
                        *parent.account(),
                        parent_metadata.privileged,
                        inline,
                    )?;
                    if let Some(key) = cache_key {
                        self.db.cache_xpr_native_inline_authorization(key);
                    }
                }
            }
            let mut ram_accounts = Vec::with_capacity(result.ram_deltas.len());
            for (account, delta) in &result.ram_deltas {
                self.db.add_pending_ram_usage(*account, *delta)?;
                if !ram_accounts.contains(account) {
                    ram_accounts.push(*account);
                }
            }
            for account in &ram_accounts {
                ResourceLimitsManager::verify_account_ram_usage(
                    &mut self.db,
                    &Name::new(*account),
                )?;
            }
            Ok(Some(result.inline_actions))
        })();

        let inline_actions = match attempt {
            Ok(Some(actions)) => {
                self.db.xpr_native_squash_row_session()?;
                actions
            }
            Ok(None) => {
                self.db.xpr_native_undo_row_session()?;
                return Ok(false);
            }
            Err(error) => {
                self.db.xpr_native_undo_row_session()?;
                return Err(error);
            }
        };

        self.append_direct_action_receipt(
            parent.clone(),
            *parent.account(),
            0,
            parent_metadata.code_sequence,
            parent_metadata.abi_sequence,
        )?;
        for inline in inline_actions {
            self.append_direct_action_receipt(
                inline,
                oracle,
                1,
                oracle_metadata.code_sequence,
                oracle_metadata.abi_sequence,
            )?;
        }
        Ok(true)
    }

    fn append_direct_action_receipt(
        &mut self,
        action: Action,
        receiver: Name,
        creator_action_ordinal: u32,
        code_sequence: u64,
        abi_sequence: u64,
    ) -> Result<(), ChainError> {
        let ordinal = self.schedule_action(
            action.clone(),
            &receiver,
            false,
            creator_action_ordinal,
            creator_action_ordinal,
        )?;
        let auth_actors = action
            .authorization()
            .iter()
            .map(|authorization| authorization.actor)
            .collect::<Vec<_>>();
        let (global_sequence, recv_sequence, auth_sequences) = self
            .db
            .next_action_sequences(receiver.as_u64(), &auth_actors)?;
        let action_return_value = self
            .db
            .protocol_feature_activated(ACTION_RETURN_VALUE_FEATURE_DIGEST)
            .then_some(&[][..]);
        let mut receipt = ActionReceipt::new(
            receiver,
            generate_action_digest(&action, action_return_value),
            global_sequence,
            recv_sequence,
            CanonicalMap::new(),
            code_sequence as u32,
            abi_sequence as u32,
        );
        for (authorization, sequence) in action.authorization().iter().zip(auth_sequences) {
            receipt.add_auth_sequence(authorization.actor, sequence);
        }
        self.add_executed_action_receipt_digest(receipt.digest()?)?;
        self.modify_action_trace(ordinal, |trace| trace.receipt = Some(receipt))
    }

    pub fn schedule_action(
        &mut self,
        act: Action,
        receiver: &Name,
        context_free: bool,
        creator_action_ordinal: u32,
        closest_unnotified_ancestor_action_ordinal: u32,
    ) -> Result<u32, ChainError> {
        let mut inner = self.inner.write()?;
        let (trx_id, block_num, block_time) = {
            (
                inner.trace.id,
                inner.trace.block_num,
                inner.trace.block_time.clone(),
            )
        };
        let new_action_ordinal = inner.trace.action_traces.len() as u32 + 1;

        inner.trace.action_traces.push(ActionTrace::new(
            trx_id,
            block_num,
            block_time,
            act,
            receiver.clone(),
            context_free,
            new_action_ordinal,
            creator_action_ordinal,
            closest_unnotified_ancestor_action_ordinal,
            CanonicalMap::new(),
        ));

        Ok(new_action_ordinal)
    }

    pub fn schedule_action_from_ordinal(
        &mut self,
        action_ordinal: u32,
        receiver: &Name,
        context_free: bool,
        creator_action_ordinal: u32,
        closest_unnotified_ancestor_action_ordinal: u32,
    ) -> Result<u32, ChainError> {
        let (trx_id, block_num, block_time, new_action_ordinal) = {
            let inner = self.inner.read()?;
            (
                inner.trace.id,
                inner.trace.block_num,
                inner.trace.block_time.clone(),
                inner.trace.action_traces.len() as u32 + 1,
            )
        };

        let provided = self.get_action_trace(action_ordinal)?;
        let mut inner = self.inner.write()?;
        inner.trace.action_traces.push(ActionTrace::new(
            trx_id,
            block_num,
            block_time,
            provided.action().clone(),
            receiver.clone(),
            context_free,
            new_action_ordinal,
            creator_action_ordinal,
            closest_unnotified_ancestor_action_ordinal,
            CanonicalMap::new(),
        ));

        Ok(new_action_ordinal)
    }

    pub fn execute_action(
        &mut self,
        action_ordinal: u32,
        recurse_depth: u32,
    ) -> Result<(), ChainError> {
        // Every top-level, notified, and inline action crosses this boundary.
        self.checktime()?;

        let (action, receiver, context_free) = self.with_action_trace(action_ordinal, |t| {
            (t.action().clone(), t.receiver().clone(), t.context_free())
        })?;

        let mut apply_context = ApplyContext::new(
            self.db.clone(),
            self.wasm_runtime.clone(),
            self.clone(),
            action.clone(),
            receiver.clone(),
            action_ordinal,
            recurse_depth,
            self.get_cpu_limit()?,
            context_free,
        )?;

        // Initialize the apply context with the action trace.
        let cpu_used = apply_context.exec(self)?;
        self.add_cpu_usage(cpu_used)?;

        Ok(())
    }

    pub fn get_action_trace(&self, action_ordinal: u32) -> Result<ActionTrace, ChainError> {
        let inner = self.inner.read()?;
        let trace = inner.trace.action_traces.get((action_ordinal as usize) - 1);

        match trace {
            Some(t) => Ok(t.clone()),
            None => Err(ChainError::TransactionError(format!(
                "failed to get action trace by ordinal {}",
                action_ordinal
            ))),
        }
    }

    #[inline]
    fn with_action_trace_mut<R>(
        &self,
        action_ordinal: u32,
        f: impl FnOnce(&mut ActionTrace) -> R,
    ) -> Result<R, ChainError> {
        let mut inner = self.inner.write()?;
        match inner
            .trace
            .action_traces
            .get_mut(action_ordinal as usize - 1)
        {
            Some(t) => Ok(f(t)),
            None => Err(ChainError::TransactionError(format!(
                "failed to update action trace by ordinal {}",
                action_ordinal
            ))),
        }
    }

    #[inline]
    fn with_action_trace<R>(
        &self,
        action_ordinal: u32,
        f: impl FnOnce(&ActionTrace) -> R,
    ) -> Result<R, ChainError> {
        let inner = self.inner.read()?;
        match inner.trace.action_traces.get(action_ordinal as usize - 1) {
            Some(t) => Ok(f(t)),
            None => Err(ChainError::TransactionError(format!(
                "failed to get action trace by ordinal {}",
                action_ordinal
            ))),
        }
    }

    #[inline]
    pub fn modify_action_trace<F>(&self, action_ordinal: u32, modify: F) -> Result<(), ChainError>
    where
        F: FnOnce(&mut ActionTrace),
    {
        self.with_action_trace_mut(action_ordinal, |t| modify(t))
    }

    pub fn pending_block_timestamp(&self) -> Result<BlockTimestamp, ChainError> {
        let inner = self.inner.read()?;
        Ok(inner.pending_block_timestamp.clone())
    }

    /// Source-compatible publication time for the currently executing
    /// transaction. Deferred execution replaces the pending block time with
    /// the durable generated transaction's original publication timestamp.
    pub fn publication_time(&self) -> Result<TimePoint, ChainError> {
        Ok(self.inner.read()?.published.clone())
    }

    /// Use the block-recorded CPU (µs) and NET (words) for receipt reconstruction
    /// and quota accounting. This is the Antelope light/replay path for a block
    /// that this node has already fully validated.
    pub fn set_explicit_billed(&self, cpu_us: u32, net_words: u32) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;
        inner.explicit_billed_cpu_time = true;
        inner.explicit_cpu_us = cpu_us;
        inner.explicit_net_words = net_words;
        inner.enforce_subjective_deadline = false;
        Ok(())
    }

    /// Disable only the node-local wall-clock watchdog. First-time block
    /// validation uses this while retaining deterministic resource metering and
    /// every objective CPU/NET limit check.
    pub fn disable_subjective_deadline(&self) -> Result<(), ChainError> {
        self.inner.write()?.enforce_subjective_deadline = false;
        Ok(())
    }

    /// Deterministic CPU amount to charge when an objectively executed deferred
    /// transaction fails before `finalize`. The trace already contains all
    /// metered action work; apply the same minimum floor used by successful
    /// transactions so a failed generated transaction cannot escape billing.
    pub fn failure_billed_cpu_time_us(&self) -> Result<u32, ChainError> {
        let inner = self.inner.read()?;
        if inner.explicit_billed_cpu_time {
            return Ok(inner.explicit_cpu_us);
        }
        Ok(inner
            .trace
            .receipt
            .cpu_usage_us
            .max(self.db.chain_config()?.min_transaction_cpu_usage))
    }

    pub fn finalize(mut self) -> Result<TransactionResult, ChainError> {
        let mut inner = self.inner.write()?;
        // On replay use the recorded usage: override the re-measured amounts so
        // the receipt (and its merkle root) and the billed accumulators match
        // the block exactly.
        if inner.explicit_billed_cpu_time {
            inner.trace.receipt.cpu_usage_us = inner.explicit_cpu_us;
            inner.trace.net_usage = inner.explicit_net_words as u64 * 8;
        }
        inner.trace.net_usage = ((inner.trace.net_usage + 7) / 8) * 8; // Round up to nearest multiple of word size (8 bytes)
        inner.trace.receipt.status = TransactionStatus::Executed;
        inner.trace.receipt.net_usage_words = VarUint32((inner.trace.net_usage / 8) as u32);

        if inner.is_input {
            let trx = self.packed_transaction.get_transaction();
            let time: TimePoint = (&inner.pending_block_timestamp).into();

            for action in trx.actions.iter() {
                for auth in action.authorization().iter() {
                    AuthorizationManager::update_permission_usage(
                        &mut self.db,
                        auth.actor(),
                        auth.permission(),
                        &time,
                    )?;
                }
            }
        }

        for account in inner.validate_ram_usage.iter() {
            ResourceLimitsManager::verify_account_ram_usage(&mut self.db, account)?;
        }

        if inner.bill_to_accounts.is_empty() {
            return Err(ChainError::TransactionError(
                "bill to accounts are not set".to_string(),
            ));
        }
        if !inner.explicit_billed_cpu_time {
            let (account_net_limit, account_cpu_limit, greylisted_net, greylisted_cpu) =
                self.max_bandwidth_billed_accounts_can_pay(&inner.bill_to_accounts)?;
            inner.net_limit_due_to_greylist = greylisted_net;
            inner.cpu_limit_due_to_greylist = greylisted_cpu;

            // Possibly lower net_limit to what the billed accounts can pay
            if account_net_limit as u64 <= inner.net_limit {
                inner.net_limit = account_net_limit as u64;
                inner.net_limit_due_to_block = false;
                inner.eager_net_limit = inner.net_limit;

                Self::check_net_usage_locked(&inner)?;
            }

            // Possibly lower cpu_limit to what the billed accounts can pay
            if account_cpu_limit as i64 <= inner.cpu_limit {
                inner.cpu_limit = account_cpu_limit as i64;
                inner.cpu_limit_due_to_block = false;
            }
        }

        Self::update_billed_cpu_time(&mut inner, &self.db)?;
        // Only enforce the minimum-CPU floor when we are the ones billing. On a
        // block we're replaying, the CPU usage is taken verbatim from the block
        // (explicit billing, above), so the producer already applied its own
        // minimum; re-checking against this node's minimum would spuriously
        // reject a valid block whenever the two configs differ.
        Self::validate_cpu_usage_to_bill(&inner, &self.db, !inner.explicit_billed_cpu_time)?;

        // During benchmarks this would throw an error because the accounts won't have enough CPU to
        // cover the billed time, so we skip this step if we're benchmarking.
        if self.block_status != BlockStatus::Benchmarking {
            for account in &inner.bill_to_accounts {
                ResourceLimitsManager::add_transaction_usage(
                    &mut self.db,
                    account,
                    inner.trace.receipt.cpu_usage_us as u64,
                    inner.trace.net_usage as u64,
                    inner.pending_block_timestamp.slot(),
                    true,
                )?;
            }
        }

        Ok(TransactionResult {
            trace: inner.trace.clone(),
            billed_cpu_time_us: inner.trace.receipt.cpu_usage_us,
            action_receipt_digests: inner.executed_action_receipt_digests.clone(),
            proposed_schedule: inner.proposed_schedule.clone(),
            dependencies: None,
        })
    }

    // Persist a producer schedule proposed by `set_proposed_producers` in the
    // block's undo session. A later block may move it into the signed header;
    // merely accepting this transaction never activates the schedule.
    pub fn set_proposed_producers(&self, producers: Vec<ProducerKey>) -> Result<i64, ChainError> {
        let mut inner = self.inner.write()?;
        let block_num = self.block_num();

        if let Some((proposal_block, packed)) = self.db.proposed_schedule() {
            let existing = ProducerSchedule::read_bounded(&packed).map_err(|error| {
                ChainError::SerializationError(format!(
                    "decode existing proposed producer schedule: {error}"
                ))
            })?;
            if existing.version <= inner.proposal_base_schedule_version {
                // Older PulseVM builds could re-propose the schedule that had
                // just become pending, leaving a stale row in a durable replay
                // checkpoint. Such a row is impossible in Leap: a proposal must
                // always follow the pending schedule, or the active one when no
                // pending schedule exists. Repair that invalid legacy state at
                // the first subsequent proposal.
                self.db.clear_proposed_schedule()?;
            } else {
                // Leap permits replacements only within the block that created the
                // proposal. Once that block is complete, later calls must wait for
                // the proposal to become pending instead of overwriting it.
                if proposal_block != block_num {
                    return Ok(-1);
                }
                if existing.producers == producers {
                    return Ok(-1);
                }
            }
        }

        if inner.proposal_base_producers == producers {
            return Ok(-1);
        }

        let version = inner
            .proposal_base_schedule_version
            .checked_add(1)
            .ok_or_else(|| ChainError::BlockError("producer schedule version overflow".into()))?;
        let schedule = ProducerSchedule {
            version,
            producers: producers.clone(),
        };
        let packed = schedule.pack()?;
        self.db.set_proposed_schedule(block_num, &packed)?;
        inner.proposed_schedule = Some(producers);
        Ok(i64::from(version))
    }

    pub fn add_cpu_usage(&self, cpu_usage: u64) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;

        // Widen the field, not the argument: narrowing `cpu_usage` to u32 first
        // would silently truncate any value above u32::MAX before the check runs.
        let total = (inner.trace.receipt.cpu_usage_us as u64)
            .checked_add(cpu_usage)
            .ok_or_else(|| ChainError::ActionValidationError("CPU usage overflow".to_string()))?;

        let total = u32::try_from(total)
            .map_err(|_| ChainError::ActionValidationError("CPU usage overflow".to_string()))?;

        inner.trace.receipt.cpu_usage_us = total;

        Ok(())
    }

    pub fn add_net_usage(&self, net_usage: u64) -> Result<(), ChainError> {
        {
            let mut inner = self.inner.write()?;
            inner.trace.net_usage =
                inner
                    .trace
                    .net_usage
                    .checked_add(net_usage)
                    .ok_or_else(|| {
                        ChainError::ActionValidationError("net usage overflow".to_string())
                    })?;
        }

        self.check_net_usage()?;

        Ok(())
    }

    pub fn add_ram_usage(&mut self, account: &Name, ram_delta: i64) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;

        ResourceLimitsManager::add_pending_ram_usage(&mut self.db, account, ram_delta)?;

        if ram_delta > 0 {
            inner.validate_ram_usage.insert(account.clone());
        }

        Ok(())
    }

    /// Flag `account` to have its RAM usage re-checked against its limit before
    /// the transaction commits. Lowering an account's RAM limit can leave it over
    /// quota without changing its usage, so the limit change alone won't schedule
    /// the check that `add_ram_usage` schedules on an increase.
    pub fn validate_ram_usage(&self, account: &Name) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;
        inner.validate_ram_usage.insert(account.clone());
        Ok(())
    }

    pub fn pause_billing_timer(&self) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;
        if inner.explicit_billed_cpu_time {
            return Ok(());
        }
        if inner.billing.pseudo_start == TimePoint::default() {
            return Ok(());
        }
        inner.billing.paused_time = TimePoint::now();
        inner.billing.billed_time = inner.billing.paused_time - inner.billing.pseudo_start;
        inner.billing.pseudo_start = TimePoint::default();
        Ok(())
    }

    pub fn resume_billing_timer(&self) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;
        if inner.explicit_billed_cpu_time {
            return Ok(());
        }
        if inner.billing.pseudo_start != TimePoint::default() {
            return Ok(());
        }
        let now = TimePoint::now();
        let _paused = now - inner.billing.paused_time; // if needed later
        inner.billing.pseudo_start = now - inner.billing.billed_time;
        Ok(())
    }

    /// Enforce the node-local wall-clock ceiling when requested. First-time
    /// validation and trusted replay disable this subjective check, while the
    /// deterministic resource meter remains active during validation.
    pub fn checktime(&self) -> Result<(), ChainError> {
        let inner = self.inner.read()?;
        Self::deadline_check(
            inner.enforce_subjective_deadline,
            inner.start_time,
            inner.max_transaction_time,
            TimePoint::now(),
        )
    }

    fn deadline_check(
        enforce: bool,
        start_time: TimePoint,
        max_transaction_time: Microseconds,
        now: TimePoint,
    ) -> Result<(), ChainError> {
        if !enforce {
            return Ok(());
        }
        let elapsed = now - start_time;
        if elapsed.count() > max_transaction_time.count() {
            return Err(ChainError::DeadlineError(format!(
                "transaction ran for {} us, over the {} us limit",
                elapsed.count(),
                max_transaction_time.count()
            )));
        }
        Ok(())
    }

    /// Instruction-meter budget for the current action. Accepted-block replay
    /// uses the producer's recorded bill and, like nodeos validation, does not
    /// stop execution at this node's objective account/block CPU allowance.
    pub fn get_cpu_limit(&self) -> Result<i64, ChainError> {
        let inner = self.inner.read()?;
        Ok(Self::execution_cpu_limit(
            inner.explicit_billed_cpu_time,
            inner.cpu_limit,
        ))
    }

    /// Whether this transaction is replaying a producer-recorded receipt.
    /// Migration-only native accelerators use this to remain unreachable from
    /// normal mempool execution, where local WASM metering is authoritative.
    pub(crate) fn is_explicitly_billed(&self) -> Result<bool, ChainError> {
        Ok(self.inner.read()?.explicit_billed_cpu_time)
    }

    /// Whether this is a controller-authored implicit transaction such as
    /// `onblock`, rather than an input or deferred transaction from a block.
    pub(crate) fn is_implicit(&self) -> Result<bool, ChainError> {
        Ok(!self.inner.read()?.is_input)
    }

    fn execution_cpu_limit(explicit_billed: bool, objective_limit: i64) -> i64 {
        if explicit_billed { -1 } else { objective_limit }
    }

    pub fn record_transaction(&mut self, id: &Id, expiration: u32) -> Result<(), ChainError> {
        self.db
            .record_transaction(&id.0.0, expiration)
            .map_err(|e| ChainError::DatabaseError(format!("duplicate tx: {}", e)))
    }

    pub fn add_executed_action_receipt_digest(&mut self, digest: Digest) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;
        inner.executed_action_receipt_digests.push_back(digest);
        Ok(())
    }

    pub fn get_packed_transaction(&self) -> &PackedTransaction {
        &self.packed_transaction
    }

    pub fn validate_expiration(&self, trx: &Transaction) -> Result<(), ChainError> {
        let inner = self.inner.read()?;
        let expiration: TimePoint = trx.header.expiration().into();
        let pending_block_timestamp: TimePoint = inner.pending_block_timestamp.into();
        let max_transaction_lifetime = self.db.chain_config()?.max_transaction_lifetime;

        if expiration < pending_block_timestamp {
            return Err(ChainError::TransactionError(
                "transaction expired".to_string(),
            ));
        }

        if expiration > pending_block_timestamp + seconds(max_transaction_lifetime as i64) {
            return Err(ChainError::TransactionError(
                "transaction has too long lifetime".to_string(),
            ));
        }

        Ok(())
    }

    pub fn validate_referenced_accounts(&self, trx: &Transaction) -> Result<(), ChainError> {
        self.validate_referenced_accounts_with_code_permission(trx, false)
    }

    /// Validate a generated transaction's account references. Deferred
    /// transactions are authorized by the scheduling receiver's implicit
    /// `receiver@eosio.code` permission, which does not need a permission
    /// object in chainbase. Ordinary input transactions remain strict.
    pub fn validate_deferred_referenced_accounts(
        &self,
        trx: &Transaction,
    ) -> Result<(), ChainError> {
        self.validate_referenced_accounts_with_code_permission(trx, true)
    }

    fn validate_referenced_accounts_with_code_permission(
        &self,
        trx: &Transaction,
        allow_code_permission: bool,
    ) -> Result<(), ChainError> {
        if !trx.context_free_actions.is_empty() {
            for action in trx.context_free_actions.iter() {
                if !self.db.is_account(action.account.as_u64())? {
                    return Err(ChainError::TransactionError(format!(
                        "context free action {} references non-existent account {}",
                        action.name(),
                        action.account()
                    )));
                }

                if action.authorization.len() > 0 {
                    return Err(ChainError::TransactionError(format!(
                        "context-free actions cannot have authorizations"
                    )));
                }
            }
        }

        let mut one_auth = false;

        for action in trx.actions.iter() {
            if !self.db.is_account(action.account.as_u64())? {
                return Err(ChainError::TransactionError(format!(
                    "action {} references non-existent account {}",
                    action.name(),
                    action.account()
                )));
            }

            for auth in action.authorization().iter() {
                one_auth = true;
                if !self.db.is_account(auth.actor())? {
                    return Err(ChainError::TransactionError(format!(
                        "action's authorizing actor '{}' does not exist",
                        Name::new(auth.actor)
                    )));
                }

                if !(allow_code_permission && auth.permission() == crate::CODE_NAME)
                    && AuthorizationManager::find_permission(&self.db.read()?, auth)?.is_none()
                {
                    return Err(ChainError::TransactionError(format!(
                        "action's authorizations include a non-existent permission: {}",
                        auth,
                    )));
                }
            }
        }

        if !one_auth {
            return Err(ChainError::TransactionError(format!(
                "transaction must have at least one authorization"
            )));
        }

        Ok(())
    }

    fn max_bandwidth_billed_accounts_can_pay(
        &self,
        accounts: &BTreeSet<Name>,
    ) -> Result<(i64, i64, bool, bool), ChainError> {
        let large_number_no_overflow = i64::MAX / 2;
        let mut account_net_limit = large_number_no_overflow;
        let mut account_cpu_limit = large_number_no_overflow;

        let mut net_greylisted = false;
        let mut cpu_greylisted = false;
        for account in accounts {
            let (net_limit, net_was_greylisted) = ResourceLimitsManager::get_account_net_limit(
                &self.db,
                account,
                Some(MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER),
            )?;
            if net_limit >= 0 {
                account_net_limit = min(account_net_limit, net_limit);
                net_greylisted |= net_was_greylisted;
            }

            let (cpu_limit, cpu_was_greylisted) = ResourceLimitsManager::get_account_cpu_limit(
                &self.db,
                account,
                Some(MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER),
            )?;
            if cpu_limit >= 0 {
                account_cpu_limit = min(account_cpu_limit, cpu_limit);
                cpu_greylisted |= cpu_was_greylisted;
            }
        }

        Ok((
            account_net_limit,
            account_cpu_limit,
            net_greylisted,
            cpu_greylisted,
        ))
    }

    pub fn check_net_usage(&self) -> Result<(), ChainError> {
        let inner = self.inner.read()?;
        Self::check_net_usage_locked(&inner)
    }

    /// The check body, callable while already holding the `inner` guard —
    /// calling `check_net_usage` there would deadlock on the re-lock.
    fn check_net_usage_locked(inner: &TransactionContextInner) -> Result<(), ChainError> {
        if inner.explicit_billed_cpu_time {
            return Ok(());
        }
        // TODO: Add unlikely hint here once it's stable
        // https://github.com/rust-lang/rust/issues/151619
        if inner.trace.net_usage > inner.eager_net_limit {
            if inner.net_limit_due_to_block {
                return Err(ChainError::TransactionError(format!(
                    "not enough space left in block: {} > {}",
                    inner.trace.net_usage, inner.eager_net_limit
                )));
            } else if inner.net_limit_due_to_greylist {
                return Err(ChainError::TransactionError(format!(
                    "greylisted transaction net usage is too high: {} > {}",
                    inner.trace.net_usage, inner.eager_net_limit
                )));
            } else {
                return Err(ChainError::TransactionError(format!(
                    "transaction net usage is too high: {} > {}",
                    inner.trace.net_usage, inner.eager_net_limit
                )));
            }
        }

        Ok(())
    }

    fn validate_cpu_usage_to_bill(
        inner: &TransactionContextInner,
        db: &Database,
        check_minimum: bool,
    ) -> Result<(), ChainError> {
        if check_minimum {
            let min_cpu = db.chain_config()?.min_transaction_cpu_usage;

            if inner.trace.receipt.cpu_usage_us < min_cpu {
                return Err(ChainError::TransactionError(format!(
                    "cannot bill CPU time less than the minimum of {}",
                    min_cpu
                )));
            }
        }

        Self::validate_account_cpu_usage(inner)
    }

    fn update_billed_cpu_time(
        inner: &mut TransactionContextInner,
        db: &Database,
    ) -> Result<(), ChainError> {
        if inner.explicit_billed_cpu_time {
            inner.trace.receipt.cpu_usage_us = inner.explicit_cpu_us;
            return Ok(());
        }

        let min_cpu = db.chain_config()?.min_transaction_cpu_usage;

        inner.trace.receipt.cpu_usage_us = std::cmp::max(inner.trace.receipt.cpu_usage_us, min_cpu);

        Ok(())
    }

    fn validate_account_cpu_usage(inner: &TransactionContextInner) -> Result<(), ChainError> {
        if inner.explicit_billed_cpu_time {
            return Ok(());
        }
        if inner.trace.receipt.cpu_usage_us > inner.cpu_limit as u32 {
            if inner.cpu_limit_due_to_block {
                return Err(ChainError::TransactionError(format!(
                    "not enough CPU left in block: {} > {}",
                    inner.trace.receipt.cpu_usage_us, inner.cpu_limit
                )));
            } else if inner.cpu_limit_due_to_greylist {
                return Err(ChainError::TransactionError(format!(
                    "greylisted transaction CPU usage is too high: {} > {}",
                    inner.trace.receipt.cpu_usage_us, inner.cpu_limit
                )));
            } else {
                return Err(ChainError::TransactionError(format!(
                    "transaction CPU usage is too high: {} > {}",
                    inner.trace.receipt.cpu_usage_us, inner.cpu_limit
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod deadline_tests {
    use pulsevm_database::{
        Microseconds,
        TimePoint,
    };
    use pulsevm_error::ChainError;

    use super::TransactionContext;

    fn tp(microseconds: i64) -> TimePoint {
        TimePoint::new(Microseconds::new(microseconds))
    }

    #[test]
    fn disabled_subjective_deadline_is_exempt() {
        assert!(
            TransactionContext::deadline_check(
                false,
                tp(1_000_000),
                Microseconds::new(1),
                tp(9_999_999),
            )
            .is_ok()
        );
    }

    #[test]
    fn explicit_billing_is_exempt_from_objective_execution_cpu_limit() {
        assert_eq!(TransactionContext::execution_cpu_limit(true, 150_000), -1);
        assert_eq!(
            TransactionContext::execution_cpu_limit(false, 150_000),
            150_000
        );
    }

    #[test]
    fn deadline_passes_under_limit_and_trips_over_it() {
        assert!(
            TransactionContext::deadline_check(
                true,
                tp(1_000_000),
                Microseconds::new(1_000),
                tp(1_000_500),
            )
            .is_ok()
        );
        assert!(matches!(
            TransactionContext::deadline_check(
                true,
                tp(1_000_000),
                Microseconds::new(1_000),
                tp(1_002_000),
            ),
            Err(ChainError::DeadlineError(_))
        ));
    }

    #[test]
    fn deadline_counts_paused_native_wall_clock() {
        assert!(matches!(
            TransactionContext::deadline_check(true, tp(0), Microseconds::new(1_000), tp(5_000),),
            Err(ChainError::DeadlineError(_))
        ));
    }
}

#[cfg(test)]
mod billing_tests {
    use std::str::FromStr;

    use pulsevm_database::PermissionLevel;

    use super::{
        Action,
        Name,
        Transaction,
        billed_accounts_for_transaction,
    };

    fn account(value: &str) -> Name {
        Name::from_str(value).unwrap()
    }

    #[test]
    fn only_bill_first_authorizer_feature_selects_first_authorizer() {
        let alice = account("alice");
        let bob = account("bob");
        let active = account("active");
        let mut transaction = Transaction::default();
        transaction.actions.push(Action::new(
            account("contract"),
            account("transfer"),
            Vec::new(),
            vec![
                PermissionLevel::new(alice.into(), active.into()),
                PermissionLevel::new(bob.into(), active.into()),
            ],
        ));

        let billed = billed_accounts_for_transaction(&transaction, alice, true);
        assert_eq!(billed.into_iter().collect::<Vec<_>>(), vec![alice]);
    }

    #[test]
    fn pre_only_bill_first_authorizer_feature_bills_all_action_authorizers() {
        let alice = account("alice");
        let bob = account("bob");
        let active = account("active");
        let mut transaction = Transaction::default();
        transaction.actions.push(Action::new(
            account("contract"),
            account("transfer"),
            Vec::new(),
            vec![
                PermissionLevel::new(alice.into(), active.into()),
                PermissionLevel::new(bob.into(), active.into()),
            ],
        ));

        let billed = billed_accounts_for_transaction(&transaction, alice, false);
        assert_eq!(billed.into_iter().collect::<Vec<_>>(), vec![alice, bob]);
    }
}

#[cfg(test)]
mod xpr_mechanics_tests {
    use pulsevm_database::PermissionLevel;

    use super::{
        Action,
        BENCHMARK,
        EOSIO_NULL,
        NONCE,
        Name,
        Transaction,
        is_xpr_mechanics_benchmark_transaction,
    };

    fn benchmark_transaction() -> Transaction {
        let mut transaction = Transaction::default();
        transaction.context_free_actions.push(Action::new(
            Name::new(EOSIO_NULL),
            Name::new(NONCE),
            vec![0; 8],
            Vec::new(),
        ));
        transaction.actions.push(Action::new(
            Name::new(super::super::xpr_native_replay::MECHANICS),
            Name::new(super::super::xpr_native_replay::CPU),
            Vec::new(),
            vec![PermissionLevel::new(
                super::super::xpr_native_replay::MECHANICS,
                BENCHMARK,
            )],
        ));
        transaction
    }

    #[test]
    fn recognizes_only_the_audited_mechanics_transaction_shape() {
        let transaction = benchmark_transaction();
        assert!(is_xpr_mechanics_benchmark_transaction(&transaction));

        let mut wrong_nonce_size = transaction.clone();
        wrong_nonce_size.context_free_actions[0].data = vec![0; 7].into();
        assert!(!is_xpr_mechanics_benchmark_transaction(&wrong_nonce_size));

        let mut wrong_permission = transaction.clone();
        wrong_permission.actions[0].authorization[0].permission = 0;
        assert!(!is_xpr_mechanics_benchmark_transaction(&wrong_permission));

        let mut stateful_payload = transaction;
        stateful_payload.actions[0].data = vec![1].into();
        assert!(!is_xpr_mechanics_benchmark_transaction(&stateful_payload));
    }
}
