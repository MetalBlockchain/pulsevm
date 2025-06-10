use pulsevm_chainbase::UndoSession;

use super::{
    Action, ActionTrace, Controller, Name, Transaction, apply_context::ApplyContext,
    error::ChainError,
};

pub struct TransactionContext<'a, 'b> {
    controller: &'a Controller<'a, 'a>,
    undo_session: &'b mut UndoSession<'b>,
    action_traces: Vec<ActionTrace>,
}

impl<'a, 'b> TransactionContext<'a, 'b>
where
    'a: 'b,
{
    pub fn new(controller: &'a Controller<'a, 'a>, undo_session: &'b mut UndoSession<'b>) -> Self {
        Self {
            controller,
            undo_session,
            action_traces: Vec::new(),
        }
    }

    pub async fn exec(&mut self, transaction: &Transaction) -> Result<(), ChainError> {
        for action in transaction.unsigned_tx.actions.iter() {
            self.schedule_action(action, &action.account(), 0);
        }

        let num_original_actions_to_execute = self.action_traces.len();
        for i in 1..=num_original_actions_to_execute {
            self.execute_action(i as u32, 0).await?;
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

    pub async fn execute_action(
        &mut self,
        action_ordinal: u32,
        recurse_depth: u32,
    ) -> Result<(), ChainError> {
        // Execute the action
        let trace = self
            .get_action_trace(action_ordinal)
            .ok_or(ChainError::TransactionError(format!("action not found")))?;

        let mut apply_context = ApplyContext::new(
            self.controller,
            self.undo_session,
            self,
            action_ordinal,
            trace,
            recurse_depth,
        );
        return apply_context.exec().await;
    }

    pub fn get_action_trace(&self, action_ordinal: u32) -> Option<&ActionTrace> {
        self.action_traces.get((action_ordinal as usize) - 1)
    }
}
