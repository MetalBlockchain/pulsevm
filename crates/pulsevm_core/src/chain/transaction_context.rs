use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock, atomic::AtomicI64},
};

use pulsevm_error::ChainError;
use pulsevm_ffi::Database;
use pulsevm_serialization::VarUint32;
use pulsevm_time::{Microseconds, TimePoint};
use spdlog::debug;

use crate::{
    block::BlockStatus,
    chain::{
        apply_context::ApplyContext,
        block::BlockTimestamp,
        id::Id,
        name::Name,
        resource_limits::ResourceLimitsManager,
        transaction::{
            Action, ActionTrace, Transaction, TransactionReceiptHeader, TransactionStatus,
            TransactionTrace,
        },
        utils::pulse_assert,
        wasm_runtime::WasmRuntime,
    },
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
}

struct TransactionContextInner {
    initialized: bool,
    trace: TransactionTrace,
    billed_cpu_time_us: AtomicI64,
    bill_to_accounts: HashSet<Name>,
    validate_ram_usage: HashSet<Name>,
    explicit_billed_cpu_time: bool,
    billing: Billing,
    pending_block_timestamp: BlockTimestamp,
}

#[derive(Clone)]
pub struct TransactionContext {
    db: Database,
    wasm_runtime: WasmRuntime,
    block_status: BlockStatus,
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
                billed_cpu_time_us: AtomicI64::new(0),
                bill_to_accounts: HashSet::new(),
                validate_ram_usage: HashSet::new(),
                explicit_billed_cpu_time: false,
                billing: Billing {
                    paused_time: TimePoint::default(),
                    pseudo_start: TimePoint::now(),
                    billed_time: Microseconds::default(),
                },
                pending_block_timestamp,
            })),
        }
    }

    pub fn init(&mut self, initial_net_usage: u64) -> Result<(), ChainError> {
        {
            let mut inner = self.inner.write()?;

            pulse_assert(
                inner.initialized == false,
                ChainError::TransactionError("cannot initialize twice".into()),
            )?;
            inner.initialized = true;
        }

        if initial_net_usage > 0 {
            self.add_net_usage(initial_net_usage)?;
        }

        Ok(())
    }

    pub fn init_for_input_trx(
        &mut self,
        transaction: &Transaction,
        packed_trx_unprunable_size: u64,
        packed_trx_prunable_size: u64,
    ) -> Result<(), ChainError> {
        pulse_assert(
            transaction.header.delay_sec.0 == 0,
            ChainError::TransactionError("transaction cannot be delayed".into()),
        )?;
        pulse_assert(
            transaction.transaction_extensions.len() == 0,
            ChainError::TransactionError(
                "no transaction extensions supported yet for input transactions".into(),
            ),
        )?;

        let mut discounted_size_for_pruned_data = packed_trx_prunable_size;
        let global_properties = unsafe { &*self.db.get_global_properties()? };
        let chain_config = global_properties.get_chain_config();
        if chain_config.get_context_free_discount_net_usage_den() > 0
            && chain_config.get_context_free_discount_net_usage_num()
                < chain_config.get_context_free_discount_net_usage_den()
        {
            discounted_size_for_pruned_data *=
                chain_config.get_context_free_discount_net_usage_num() as u64;
            discounted_size_for_pruned_data = (discounted_size_for_pruned_data
                + chain_config.get_context_free_discount_net_usage_den() as u64
                - 1)
                / chain_config.get_context_free_discount_net_usage_den() as u64; // rounds up
        }

        let initial_net_usage: u64 = (chain_config.get_base_per_transaction_net_usage() as u64)
            + packed_trx_unprunable_size
            + discounted_size_for_pruned_data;

        self.init(initial_net_usage)?;
        Ok(())
    }

    pub fn exec(&mut self, transaction: &Transaction) -> Result<(), ChainError> {
        // Reserve actions array
        {
            let mut inner = self.inner.write()?;
            inner.trace.action_traces.reserve(transaction.actions.len());
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
            HashMap::new(),
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
            HashMap::new(),
        ));

        Ok(new_action_ordinal)
    }

    pub fn execute_action(
        &mut self,
        action_ordinal: u32,
        recurse_depth: u32,
    ) -> Result<(), ChainError> {
        let (action, receiver) = self.with_action_trace(action_ordinal, |t| {
            (t.action().clone(), t.receiver().clone())
        })?;

        let mut apply_context = ApplyContext::new(
            self.db.clone(),
            self.wasm_runtime.clone(),
            self.clone(),
            action,
            receiver.clone(),
            action_ordinal,
            recurse_depth,
        )?;

        // Initialize the apply context with the action trace.
        apply_context.exec(self)?;
        //self.billed_cpu_time_us
        //    .fetch_add(cpu_used as i64, std::sync::atomic::Ordering::Relaxed);

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

    pub fn finalize(&mut self) -> Result<TransactionResult, ChainError> {
        let now = TimePoint::now();
        let billed_cpu_time_us = self.get_billed_cpu_time(now)?;

        let mut inner = self.inner.write()?;
        inner.trace.net_usage = ((inner.trace.net_usage + 7) / 8) * 8; // Round up to nearest multiple of word size (8 bytes)
        inner.trace.receipt = TransactionReceiptHeader::new(
            TransactionStatus::Executed,
            billed_cpu_time_us as u32,
            VarUint32((inner.trace.net_usage / 8) as u32),
        );

        for account in inner.validate_ram_usage.iter() {
            ResourceLimitsManager::verify_account_ram_usage(&mut self.db, account)?;
        }

        debug!("Transaction took {} micros", billed_cpu_time_us);

        if self.block_status != BlockStatus::Benchmarking {
            ResourceLimitsManager::add_transaction_usage(
                &mut self.db,
                &inner.bill_to_accounts,
                billed_cpu_time_us as u64,
                inner.trace.net_usage as u64,
                inner.pending_block_timestamp.slot(),
            )?;
        }

        Ok(TransactionResult {
            trace: inner.trace.clone(),
            billed_cpu_time_us,
        })
    }

    pub fn add_net_usage(&self, net_usage: u64) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;
        inner.trace.net_usage += net_usage;
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

    pub fn get_billed_cpu_time(&self, now: TimePoint) -> Result<u32, ChainError> {
        let inner = self.inner.read()?;
        let billed = (now - inner.billing.pseudo_start).count();
        Ok(billed as u32)
    }
}
