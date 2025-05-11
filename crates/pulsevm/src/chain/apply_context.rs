use std::collections::VecDeque;

use super::{Action, Controller, Name, TransactionContext, error::ChainError};

pub struct ApplyContext<'a, 'b> {
    action: Action,     // The action being applied
    receiver: Name,     // The account that is receiving the action
    recurse_depth: u32, // The current recursion depth
    first_receiver_action_ordinal: u32,
    action_ordinal: u32,
    priviliged: bool,
    controller: &'a Controller,
    transaction_context: &'a mut TransactionContext<'b>,

    notified: VecDeque<(Name, u32)>, // List of notified accounts
    inline_actions: Vec<u32>,        // List of inline actions
}

impl<'a, 'b> ApplyContext<'a, 'b> {
    pub fn new(
        controller: &'a Controller,
        transaction_context: &'a mut TransactionContext<'b>,
        action_ordinal: u32,
        depth: u32,
    ) -> Self {
        let trace = transaction_context
            .get_action_trace(action_ordinal)
            .unwrap();
        let action = trace.action();
        let receiver = trace.receiver();

        ApplyContext {
            action,
            receiver,
            recurse_depth: depth,
            first_receiver_action_ordinal: 0,
            action_ordinal,
            priviliged: false,
            controller,
            transaction_context,
            notified: VecDeque::new(),
            inline_actions: Vec::new(),
        }
    }

    pub fn exec(&mut self) -> Result<(), ChainError> {
        self.notified
            .push_back((self.receiver.clone(), self.action_ordinal));
        self.exec_one()?;
        for i in 1..self.notified.len() {
            let (receiver, action_ordinal) = self.notified[i];
            self.receiver = receiver;
            self.action_ordinal = action_ordinal;
            self.exec_one()?;
        }

        if self.inline_actions.len() > 0 && self.recurse_depth >= 1024 {
            return Err(ChainError::TransactionError(
                "recursion depth exceeded".to_string(),
            ));
        }

        for ordinal in self.inline_actions.iter() {
            self.transaction_context
                .execute_action(*ordinal, self.recurse_depth + 1)?;
        }

        Ok(())
    }

    pub fn exec_one(&mut self) -> Result<(), ChainError> {
        let native = self.controller.find_apply_handler(
            self.receiver,
            self.action.account(),
            self.action.name(),
        );
        if let Some(native) = native {
            native(self)?;
        }
        Ok(())
    }
}
