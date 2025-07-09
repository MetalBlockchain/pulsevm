use std::{
    cell::{Ref, RefCell},
    rc::Rc,
    sync::{Arc, RwLock},
};

use pulsevm_chainbase::UndoSession;

use crate::chain::{
    controller,
    wasm_runtime::{self, WasmContext, WasmRuntime},
};

use super::{
    Action, ActionTrace, Name, Transaction, apply_context::ApplyContext, error::ChainError,
};

pub struct TransactionContext {
    session: Rc<RefCell<UndoSession>>,
    wasm_runtime: Arc<RwLock<WasmRuntime>>,

    action_traces: Vec<ActionTrace>,
}

impl TransactionContext {
    pub fn new(
        session: Rc<RefCell<UndoSession>>,
        wasm_runtime: Arc<RwLock<WasmRuntime>>,
    ) -> Self {
        Self {
            session,
            wasm_runtime,

            action_traces: Vec::new(),
        }
    }

    pub fn exec(&mut self, transaction: &Transaction) -> Result<(), ChainError> {
        for action in transaction.unsigned_tx.actions.iter() {
            self.schedule_action(action, &action.account(), 0);
        }

        let num_original_actions_to_execute = self.action_traces.len();
        for i in 1..=num_original_actions_to_execute {
            self.execute_action(i as u32, 0)?;
        }

        Ok(())
    }

    pub fn schedule_action(
        &mut self,
        action: &Action,
        receiver: &Name,
        creator_action_ordinal: u32,
    ) -> u32 {
        let new_action_ordinal = (self.action_traces.len() as u32) + 1;
        let action_trace = ActionTrace::new(
            new_action_ordinal,
            creator_action_ordinal,
            receiver.clone(),
            action.clone(),
        );
        self.action_traces.push(action_trace);
        new_action_ordinal
    }

    pub fn schedule_action_from_ordinal(
        &mut self,
        action_ordinal: u32,
        receiver: Name,
        creator_action_ordinal: u32,
    ) -> Result<u32, ChainError> {
        let new_action_ordinal = (self.action_traces.len() as u32) + 1;
        let provided_action = self
            .get_action_trace(action_ordinal)
            .ok_or(ChainError::TransactionError(format!("action not found")))?;
        let action_trace = ActionTrace::new(
            new_action_ordinal,
            creator_action_ordinal,
            receiver.clone(),
            provided_action.action().clone(),
        );
        self.action_traces.push(action_trace);
        Ok(new_action_ordinal)
    }

    pub fn execute_action(
        &self,
        action_ordinal: u32,
        recurse_depth: u32,
    ) -> Result<(), ChainError> {
        let trace = self
            .get_action_trace(action_ordinal)
            .ok_or(ChainError::TransactionError(format!("action not found")))?;
        let action = trace.action();
        let receiver = trace.receiver();
        let mut apply_context = ApplyContext::new(
            self.session.clone(),
            action,
            receiver,
            action_ordinal,
            recurse_depth,
        )?;

        // Initialize the apply context with the action trace.
        apply_context.exec(self.wasm_runtime.clone())?;

        Ok(())
    }

    pub fn get_action_trace(&self, action_ordinal: u32) -> Option<&ActionTrace> {
        self.action_traces.get((action_ordinal as usize) - 1)
    }
}
