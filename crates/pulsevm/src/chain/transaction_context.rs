use std::{
    cell::RefCell,
    rc::Rc,
    sync::{Arc, RwLock, atomic::AtomicI64},
};

use pulsevm_chainbase::UndoSession;

use crate::chain::{BlockTimestamp, TransactionTrace, wasm_runtime::WasmRuntime};

use super::{
    Action, ActionTrace, Name, Transaction, apply_context::ApplyContext, error::ChainError,
};

pub struct TransactionResult {
    pub trace: TransactionTrace,
    pub billed_cpu_time_us: i64,
}

#[derive(Clone)]
pub struct TransactionContext {
    session: UndoSession,
    wasm_runtime: Arc<RwLock<WasmRuntime>>,
    pending_block_timestamp: BlockTimestamp,

    trace: Rc<RefCell<TransactionTrace>>,
    billed_cpu_time_us: Rc<AtomicI64>,
}

impl TransactionContext {
    pub fn new(
        session: UndoSession,
        wasm_runtime: Arc<RwLock<WasmRuntime>>,
        pending_block_timestamp: BlockTimestamp,
    ) -> Self {
        Self {
            session,
            wasm_runtime,
            pending_block_timestamp,

            trace: Rc::new(RefCell::new(TransactionTrace::default())),
            billed_cpu_time_us: Rc::new(AtomicI64::new(0)),
        }
    }

    pub fn exec(&mut self, transaction: &Transaction) -> Result<TransactionResult, ChainError> {
        for action in transaction.actions.iter() {
            self.schedule_action(action, &action.account(), false, 0, 0);
        }

        let num_original_actions_to_execute = { self.trace.borrow().action_traces.len() };
        for i in 1..=num_original_actions_to_execute {
            self.execute_action(i as u32, 0)?;
        }

        let trace = { self.trace.borrow().clone() };
        let billed_cpu_time_us = self
            .billed_cpu_time_us
            .load(std::sync::atomic::Ordering::Relaxed);
        Ok(TransactionResult {
            trace,
            billed_cpu_time_us,
        })
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
            *receiver,
            context_free,
            new_action_ordinal,
            creator_action_ordinal,
            closest_unnotified_ancestor_action_ordinal,
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
        apply_context.exec(self)?;

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

    pub fn pending_block_timestamp(&self) -> BlockTimestamp {
        self.pending_block_timestamp
    }
}
