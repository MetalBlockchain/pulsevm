use pulsevm_chainbase::UndoSession;

use super::{
    Action, ActionTrace, Name, Transaction,
    apply_context::{self, ApplyContext, ApplyContextError},
};

pub struct TransactionContext<'a> {
    transaction: &'a Transaction,
    undo_session: &'a UndoSession<'a>,
    action_traces: Vec<ActionTrace>,
}

impl<'a> TransactionContext<'a> {
    pub fn new(transaction: &'a Transaction, undo_session: &'a UndoSession) -> Self {
        Self {
            transaction,
            undo_session,
            action_traces: Vec::new(),
        }
    }

    pub fn exec(&mut self) -> Result<(), ApplyContextError> {
        for action in &self.transaction.unsigned_tx.actions {
            self.schedule_action(action, action.account(), 0);
        }

        let num_original_actions_to_execute = self.action_traces.len();
        for i in 1..num_original_actions_to_execute {
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

    pub fn execute_action(
        &mut self,
        action_ordinal: u32,
        recurse_depth: u32,
    ) -> Result<(), ApplyContextError> {
        // Execute the action
        let mut apply_context = ApplyContext::new(self, action_ordinal, recurse_depth);
        apply_context.exec()?;

        // Action is executed
        Ok(())
    }

    pub fn get_action_trace(&self, action_ordinal: u32) -> Option<&ActionTrace> {
        self.action_traces.get((action_ordinal as usize) - 1)
    }
}
