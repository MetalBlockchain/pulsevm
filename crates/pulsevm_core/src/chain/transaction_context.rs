use std::{
    cmp::min,
    collections::{
        BTreeMap,
        BTreeSet,
        VecDeque,
    },
    sync::{
        Arc,
        RwLock,
    },
};

use pulsevm_constants::MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER;
use pulsevm_crypto::Digest;
use pulsevm_database::{
    BlockTimestamp,
    Database,
    Microseconds,
    TimePoint,
    seconds,
};
use pulsevm_error::ChainError;
use pulsevm_serialization::VarUint32;

use crate::{
    authorization_manager::AuthorizationManager,
    block::BlockStatus,
    chain::{
        apply_context::ApplyContext,
        id::Id,
        name::Name,
        producer_schedule::ProducerKey,
        resource_limits::ResourceLimitsManager,
        transaction::{
            Action,
            ActionTrace,
            Transaction,
            TransactionStatus,
            TransactionTrace,
        },
        utils::pulse_assert,
        wasm_runtime::WasmRuntime,
    },
    transaction::PackedTransaction,
};

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
}

struct TransactionContextInner {
    initialized: bool,
    trace: TransactionTrace,
    bill_to_account: Option<Name>,
    validate_ram_usage: BTreeSet<Name>,
    explicit_billed_cpu_time: bool,
    // On light/replay validation these carry the block-recorded cpu (µs) and net
    // (words) so the receipt and billing use the recorded values instead of
    // re-measuring, and the objective limit checks are skipped.
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
    pending_block_timestamp: BlockTimestamp,
    cpu_limit: i64,
    cpu_limit_due_to_greylist: bool,
    cpu_limit_due_to_block: bool,
    executed_action_receipt_digests: VecDeque<Digest>,
    is_input: bool,
    proposed_schedule: Option<Vec<ProducerKey>>,
    active_producers: Vec<ProducerKey>,
    active_schedule_version: u32,
}

#[derive(Clone)]
pub struct TransactionContext {
    db: Database,
    wasm_runtime: WasmRuntime,
    block_status: BlockStatus,
    packed_transaction: PackedTransaction,
    inner: Arc<RwLock<TransactionContextInner>>,
}

impl TransactionContext {
    pub fn new(
        db: Database,
        wasm_runtime: WasmRuntime,
        block_num: u32,
        pending_block_timestamp: BlockTimestamp,
        transaction_id: &Id,
        block_status: BlockStatus,
        packed_transaction: PackedTransaction,
        max_transaction_time_ms: u32,
    ) -> Self {
        let mut trace = TransactionTrace::default();
        trace.id = *transaction_id;
        trace.block_num = block_num;
        trace.block_time = pending_block_timestamp.clone();

        Self {
            db,
            wasm_runtime,
            block_status,
            inner: Arc::new(RwLock::new(TransactionContextInner {
                initialized: false,
                trace,
                bill_to_account: None,
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
                pending_block_timestamp,
                cpu_limit: 0,
                cpu_limit_due_to_greylist: false,
                cpu_limit_due_to_block: true,
                executed_action_receipt_digests: VecDeque::with_capacity(6),
                is_input: false,
                proposed_schedule: None,
                active_producers: Vec::new(),
                active_schedule_version: 0,
            })),
            packed_transaction,
        }
    }

    pub fn set_active_schedule(
        &self,
        producers: Vec<ProducerKey>,
        version: u32,
    ) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;
        inner.active_producers = producers;
        inner.active_schedule_version = version;
        Ok(())
    }

    pub fn active_producers(&self) -> Result<Vec<ProducerKey>, ChainError> {
        Ok(self.inner.read()?.active_producers.clone())
    }

    pub fn active_schedule_version(&self) -> Result<u32, ChainError> {
        Ok(self.inner.read()?.active_schedule_version)
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
        inner.bill_to_account = Some(first_authorizer_name.clone());

        // Update usage values of accounts to reflect new time
        ResourceLimitsManager::update_account_usage(
            &mut self.db,
            &first_authorizer_name,
            inner.pending_block_timestamp.slot(),
        )?;

        // Calculate the highest network usage and CPU time that all of the billed accounts can
        // afford to be billed
        let (account_net_limit, account_cpu_limit, greylisted_net, greylisted_cpu) =
            self.max_bandwidth_billed_account_can_pay(&first_authorizer_name)?;

        inner.net_limit_due_to_greylist = greylisted_net;
        inner.cpu_limit_due_to_greylist = greylisted_cpu;
        inner.eager_net_limit = inner.net_limit;

        let new_eager_net_limit = min(
            inner.eager_net_limit,
            (account_net_limit + net_usage_leeway as i64) as u64,
        );

        // Possibly lower eager_net_limit to what the billed account can pay plus some (objective)
        // leeway
        if new_eager_net_limit < inner.eager_net_limit {
            inner.eager_net_limit = new_eager_net_limit;
        }

        inner.cpu_limit = min(inner.cpu_limit, account_cpu_limit);
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
            BTreeMap::new(),
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
            BTreeMap::new(),
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

        // Finalize the apply context
        for (account, ram_delta) in apply_context.account_ram_deltas()?.iter() {
            self.add_ram_usage(account, *ram_delta)?;
        }

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

    /// Bill the block-recorded cpu (µs) and net (words) for this transaction
    /// rather than the re-measured amounts, and skip the objective limit checks —
    /// the Antelope light/replay validation path for an already-accepted block.
    pub fn set_explicit_billed(&self, cpu_us: u32, net_words: u32) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;
        inner.explicit_billed_cpu_time = true;
        inner.explicit_cpu_us = cpu_us;
        inner.explicit_net_words = net_words;
        Ok(())
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

        let first_authorizer_name = inner.bill_to_account.clone().ok_or_else(|| {
            ChainError::TransactionError("bill to account is not set".to_string())
        })?;
        let (account_net_limit, account_cpu_limit, greylisted_net, greylisted_cpu) =
            self.max_bandwidth_billed_account_can_pay(&first_authorizer_name)?;
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
            ResourceLimitsManager::add_transaction_usage(
                &mut self.db,
                &first_authorizer_name,
                inner.trace.receipt.cpu_usage_us as u64,
                inner.trace.net_usage as u64,
                inner.pending_block_timestamp.slot(),
                true,
            )?;
        }

        Ok(TransactionResult {
            trace: inner.trace.clone(),
            billed_cpu_time_us: inner.trace.receipt.cpu_usage_us,
            action_receipt_digests: inner.executed_action_receipt_digests.clone(),
            proposed_schedule: inner.proposed_schedule.clone(),
        })
    }

    // Record a producer schedule proposed by `set_proposed_producers` during this
    // transaction. Surfaced in the TransactionResult; the controller activates it
    // when the block is accepted.
    pub fn set_proposed_producers(&self, producers: Vec<ProducerKey>) -> Result<(), ChainError> {
        self.inner.write()?.proposed_schedule = Some(producers);
        Ok(())
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

    /// Enforce the node-local wall-clock ceiling. Explicitly billed execution
    /// (accepted-block replay/validation) is exempt because this check is
    /// subjective and must never affect consensus validation.
    pub fn checktime(&self) -> Result<(), ChainError> {
        let inner = self.inner.read()?;
        Self::deadline_check(
            inner.explicit_billed_cpu_time,
            inner.start_time,
            inner.max_transaction_time,
            TimePoint::now(),
        )
    }

    fn deadline_check(
        explicit_billed: bool,
        start_time: TimePoint,
        max_transaction_time: Microseconds,
        now: TimePoint,
    ) -> Result<(), ChainError> {
        if explicit_billed {
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

    pub fn get_cpu_limit(&self) -> Result<i64, ChainError> {
        let inner = self.inner.read()?;
        Ok(inner.cpu_limit)
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

                if AuthorizationManager::find_permission(&self.db.read()?, auth)?.is_none() {
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

    fn max_bandwidth_billed_account_can_pay(
        &self,
        account: &Name,
    ) -> Result<(i64, i64, bool, bool), ChainError> {
        let large_number_no_overflow = i64::MAX / 2;
        let mut account_net_limit = large_number_no_overflow;
        let mut account_cpu_limit = large_number_no_overflow;

        let (net_limit, net_was_greylisted) = ResourceLimitsManager::get_account_net_limit(
            &self.db,
            account,
            Some(MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER),
        )?;

        if net_limit >= 0 {
            account_net_limit = min(account_net_limit, net_limit);
        }

        let (cpu_limit, cpu_was_greylisted) = ResourceLimitsManager::get_account_cpu_limit(
            &self.db,
            account,
            Some(MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER),
        )?;

        if cpu_limit >= 0 {
            account_cpu_limit = min(account_cpu_limit, cpu_limit);
        }

        Ok((
            account_net_limit,
            account_cpu_limit,
            net_was_greylisted,
            cpu_was_greylisted,
        ))
    }

    pub fn check_net_usage(&self) -> Result<(), ChainError> {
        let inner = self.inner.read()?;
        Self::check_net_usage_locked(&inner)
    }

    /// The check body, callable while already holding the `inner` guard —
    /// calling `check_net_usage` there would deadlock on the re-lock.
    fn check_net_usage_locked(inner: &TransactionContextInner) -> Result<(), ChainError> {
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
    fn explicit_billing_is_exempt_from_subjective_deadline() {
        assert!(
            TransactionContext::deadline_check(
                true,
                tp(1_000_000),
                Microseconds::new(1),
                tp(9_999_999),
            )
            .is_ok()
        );
    }

    #[test]
    fn deadline_passes_under_limit_and_trips_over_it() {
        assert!(
            TransactionContext::deadline_check(
                false,
                tp(1_000_000),
                Microseconds::new(1_000),
                tp(1_000_500),
            )
            .is_ok()
        );
        assert!(matches!(
            TransactionContext::deadline_check(
                false,
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
            TransactionContext::deadline_check(false, tp(0), Microseconds::new(1_000), tp(5_000),),
            Err(ChainError::DeadlineError(_))
        ));
    }
}
