use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
    sync::{Arc, RwLock, atomic::AtomicI64},
};

use pulsevm_chainbase::UndoSession;
use pulsevm_crypto::Digest;
use pulsevm_serialization::VarUint32;
use pulsevm_time::{Microseconds, TimePoint};

use crate::chain::{
    ActionReceipt, BlockTimestamp, PackedTransaction, TransactionReceiptHeader, TransactionStatus,
    TransactionTrace, config, genesis::ChainConfig, pulse_assert,
    resource_limits::ResourceLimitsManager, wasm_runtime::WasmRuntime,
};

use super::{
    Action, ActionTrace, Name, Transaction, apply_context::ApplyContext, error::ChainError,
};

pub struct TransactionResult {
    pub trace: TransactionTrace,
    pub billed_cpu_time_us: u32,
}

#[derive(Clone)]
pub struct TransactionContext {
    initialized: bool,
    packed_trx: PackedTransaction,
    session: UndoSession,
    wasm_runtime: Arc<RwLock<WasmRuntime>>,
    pending_block_timestamp: BlockTimestamp,
    config: ChainConfig,

    trace: Rc<RefCell<TransactionTrace>>,
    billed_cpu_time_us: Rc<AtomicI64>,
    bill_to_accounts: Rc<RefCell<HashSet<Name>>>,
    validate_ram_usage: Rc<RefCell<HashSet<Name>>>,
    explicit_billed_cpu_time: bool,
    paused_time: Rc<RefCell<TimePoint>>,
    pseudo_start: Rc<RefCell<TimePoint>>,
    billed_time: Rc<RefCell<Microseconds>>,
}

impl TransactionContext {
    pub fn new(
        session: UndoSession,
        config: ChainConfig,
        wasm_runtime: Arc<RwLock<WasmRuntime>>,
        block_num: u32,
        pending_block_timestamp: BlockTimestamp,
        transaction: &PackedTransaction,
    ) -> Self {
        let mut trace = TransactionTrace::default();
        trace.id = transaction.id().clone();
        trace.block_num = block_num;
        trace.block_time = pending_block_timestamp;

        Self {
            initialized: false,
            packed_trx: transaction.clone(),
            session,
            wasm_runtime,
            pending_block_timestamp,
            config,

            trace: Rc::new(RefCell::new(trace)),
            billed_cpu_time_us: Rc::new(AtomicI64::new(0)),
            bill_to_accounts: Rc::new(RefCell::new(HashSet::new())),
            validate_ram_usage: Rc::new(RefCell::new(HashSet::new())),
            explicit_billed_cpu_time: false,
            paused_time: Rc::new(RefCell::new(TimePoint::default())),
            pseudo_start: Rc::new(RefCell::new(TimePoint::now())),
            billed_time: Rc::new(RefCell::new(Microseconds::default())),
        }
    }

    pub fn init(&mut self, initial_net_usage: u64) -> Result<(), ChainError> {
        pulse_assert(
            self.initialized == false,
            ChainError::TransactionError("cannot initialize twice".into()),
        )?;
        self.initialized = true;

        if initial_net_usage > 0 {
            self.add_net_usage(initial_net_usage);
        }

        Ok(())
    }

    pub fn init_for_input_trx(
        &mut self,
        packed_trx_unprunable_size: u64,
        packed_trx_prunable_size: u64,
    ) -> Result<(), ChainError> {
        let trx = self.packed_trx.get_transaction();

        pulse_assert(
            trx.header.delay_sec.0 == 0,
            ChainError::TransactionError("transaction cannot be delayed".into()),
        )?;
        pulse_assert(
            trx.transaction_extensions.len() == 0,
            ChainError::TransactionError(
                "no transaction extensions supported yet for input transactions".into(),
            ),
        )?;

        let mut discounted_size_for_pruned_data = packed_trx_prunable_size.clone();
        if self.config.context_free_discount_net_usage_den > 0
            && self.config.context_free_discount_net_usage_num
                < self.config.context_free_discount_net_usage_den
        {
            discounted_size_for_pruned_data *=
                self.config.context_free_discount_net_usage_num as u64;
            discounted_size_for_pruned_data = (discounted_size_for_pruned_data
                + self.config.context_free_discount_net_usage_den as u64
                - 1)
                / self.config.context_free_discount_net_usage_den as u64; // rounds up
        }

        let initial_net_usage: u64 = (self.config.base_per_transaction_net_usage as u64)
            + packed_trx_unprunable_size
            + discounted_size_for_pruned_data;

        self.init(initial_net_usage)?;
        Ok(())
    }

    pub fn exec(&mut self, transaction: &Transaction) -> Result<(), ChainError> {
        for action in transaction.actions.iter() {
            self.schedule_action(action, &action.account(), false, 0, 0);
        }

        let num_original_actions_to_execute = { self.trace.borrow().action_traces.len() };
        for i in 1..=num_original_actions_to_execute {
            self.execute_action(i as u32, 0)?;
        }

        Ok(())
    }

    pub fn schedule_action(
        &mut self,
        act: &Action,
        receiver: &Name,
        context_free: bool,
        creator_action_ordinal: u32,
        closest_unnotified_ancestor_action_ordinal: u32,
    ) -> u32 {
        let (trx_id, block_num, block_time) = {
            let trace = self.trace.borrow();
            (trace.id, trace.block_num, trace.block_time)
        };
        let mut trace = self.trace.borrow_mut();
        let new_action_ordinal = trace.action_traces.len() as u32 + 1;

        trace.action_traces.push(ActionTrace::new(
            trx_id,
            block_num,
            block_time,
            act,
            *receiver,
            context_free,
            new_action_ordinal,
            creator_action_ordinal,
            closest_unnotified_ancestor_action_ordinal,
            HashMap::new(),
        ));

        new_action_ordinal
    }

    pub fn schedule_action_from_ordinal(
        &mut self,
        action_ordinal: u32,
        receiver: &Name,
        context_free: bool,
        creator_action_ordinal: u32,
        closest_unnotified_ancestor_action_ordinal: u32,
    ) -> Result<u32, ChainError> {
        let (trx_id, block_num, block_time) = {
            let trace = self.trace.borrow();
            (trace.id, trace.block_num, trace.block_time)
        };
        let provided_action = self.get_action_trace(action_ordinal)?.act;
        let mut trace = self.trace.borrow_mut();
        let new_action_ordinal = trace.action_traces.len() as u32 + 1;

        trace.action_traces.push(ActionTrace::new(
            trx_id,
            block_num,
            block_time,
            &provided_action,
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
        let trace = self.get_action_trace(action_ordinal)?;
        let action = trace.action();
        let receiver = trace.receiver();
        let mut apply_context = ApplyContext::new(
            self.session.clone(),
            self.wasm_runtime.clone(),
            self.clone(),
            action,
            receiver,
            action_ordinal,
            recurse_depth,
        )?;

        // Initialize the apply context with the action trace.
        let cpu_used = apply_context.exec(self)?;
        self.billed_cpu_time_us.fetch_add(cpu_used as i64, std::sync::atomic::Ordering::Relaxed);

        // Finalize the apply context
        for (account, ram_delta) in apply_context.account_ram_deltas().iter() {
            self.add_ram_usage(account, *ram_delta)?;
        }

        Ok(())
    }

    pub fn get_action_trace(&self, action_ordinal: u32) -> Result<ActionTrace, ChainError> {
        let trace = self.trace.borrow();
        let trace = trace.action_traces.get((action_ordinal as usize) - 1);

        if let Some(trace) = trace {
            return Ok(trace.clone());
        }

        Err(ChainError::TransactionError(format!(
            "failed to get action trace by ordinal {}",
            action_ordinal
        )))
    }

    pub fn modify_action_trace<F>(&self, action_ordinal: u32, modify: F) -> Result<(), ChainError>
    where
        F: FnOnce(&mut ActionTrace) -> ActionTrace,
    {
        let mut trace = self.trace.borrow_mut();
        let trace = trace.action_traces.get_mut((action_ordinal as usize) - 1);

        if let Some(trace) = trace {
            *trace = modify(trace);
            Ok(())
        } else {
            Err(ChainError::TransactionError(format!(
                "failed to update action trace by ordinal {}",
                action_ordinal
            )))
        }
    }

    pub fn pending_block_timestamp(&self) -> BlockTimestamp {
        self.pending_block_timestamp
    }

    pub fn finalize(&mut self) -> Result<TransactionResult, ChainError> {
        let mut trace = self.trace.borrow_mut();
        let now = TimePoint::now();
        let billed_cpu_time_us = self.get_billed_cpu_time(now);

        trace.net_usage = ((trace.net_usage + 7) / 8) * 8; // Round up to nearest multiple of word size (8 bytes)
        trace.receipt = TransactionReceiptHeader::new(
            TransactionStatus::Executed,
            billed_cpu_time_us as u32,
            VarUint32((trace.net_usage / 8) as u32),
        );

        let mut session = self.session.clone();
        let validate_ram_usage = self.validate_ram_usage.borrow();
        for account in validate_ram_usage.iter() {
            ResourceLimitsManager::verify_account_ram_usage(&mut session, account)?;
        }

        ResourceLimitsManager::add_transaction_usage(
            &mut session,
            &self.bill_to_accounts.borrow(),
            billed_cpu_time_us as u64,
            trace.net_usage as u64,
            self.pending_block_timestamp().slot,
        )?;

        Ok(TransactionResult {
            trace: trace.clone(),
            billed_cpu_time_us,
        })
    }

    pub fn add_net_usage(&self, net_usage: u64) {
        let mut trace = self.trace.borrow_mut();
        trace.net_usage += net_usage;
    }

    pub fn add_ram_usage(&self, account: &Name, ram_delta: i64) -> Result<(), ChainError> {
        let mut session = self.session.clone();

        // Update the RAM usage in the resource limits manager.
        ResourceLimitsManager::add_pending_ram_usage(&mut session, account, ram_delta)?;

        if ram_delta > 0 {
            self.validate_ram_usage.borrow_mut().insert(account.clone());
        }

        Ok(())
    }

    pub fn pause_billing_timer(&self) {
        let mut pseudo_start = self.pseudo_start.borrow_mut();
        let mut paused_time = self.paused_time.borrow_mut();
        let mut billed_time = self.billed_time.borrow_mut();

        if self.explicit_billed_cpu_time || *pseudo_start == TimePoint::default() {
            return;
        }

        *paused_time = TimePoint::now();
        *billed_time = *paused_time - *pseudo_start;
        *pseudo_start = TimePoint::default();
    }

    pub fn resume_billing_timer(&self) {
        let mut pseudo_start = self.pseudo_start.borrow_mut();
        let paused_time = self.paused_time.borrow_mut();
        let billed_time = self.billed_time.borrow_mut();

        if self.explicit_billed_cpu_time || *pseudo_start != TimePoint::default() {
            return;
        }

        let now = TimePoint::now();
        let paused = now - *paused_time;

        *pseudo_start = now - *billed_time;
    }

    pub fn get_billed_cpu_time(&self, now: TimePoint) -> u32 {
        let pseudo_start = self.pseudo_start.borrow();
        let billed = (now - *pseudo_start).count();
        billed as u32
    }
}
