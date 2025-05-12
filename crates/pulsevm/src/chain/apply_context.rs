use std::collections::{HashMap, VecDeque};

use pulsevm_chainbase::UndoSession;

use super::{Action, Controller, Name, TransactionContext, error::ChainError};

pub struct ApplyContext<'a, 'b> {
    action: Action,     // The action being applied
    receiver: Name,     // The account that is receiving the action
    recurse_depth: u32, // The current recursion depth
    first_receiver_action_ordinal: u32,
    action_ordinal: u32,
    priviliged: bool,
    pub controller: &'a Controller,
    transaction_context: &'a mut TransactionContext<'b>,

    notified: VecDeque<(Name, u32)>, // List of notified accounts
    inline_actions: Vec<u32>,        // List of inline actions
    account_ram_deltas: HashMap<Name, i64>, // RAM usage deltas for accounts
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
            account_ram_deltas: HashMap::new(),
        }
    }

    pub fn exec(&mut self, session: &mut UndoSession) -> Result<(), ChainError> {
        self.notified
            .push_back((self.receiver.clone(), self.action_ordinal));
        self.exec_one(session)?;
        for i in 1..self.notified.len() {
            let (receiver, action_ordinal) = self.notified[i];
            self.receiver = receiver;
            self.action_ordinal = action_ordinal;
            self.exec_one(session)?;
        }

        if self.inline_actions.len() > 0 && self.recurse_depth >= 1024 {
            return Err(ChainError::TransactionError(
                "recursion depth exceeded".to_string(),
            ));
        }

        for ordinal in self.inline_actions.iter() {
            self.transaction_context
                .execute_action(session, *ordinal, self.recurse_depth + 1)?;
        }

        Ok(())
    }

    pub fn exec_one(&mut self, session: &mut UndoSession) -> Result<(), ChainError> {
        let native = self.controller.find_apply_handler(
            self.receiver,
            self.action.account(),
            self.action.name(),
        );
        if let Some(native) = native {
            native(self, session)?;
        }
        Ok(())
    }

    pub fn get_action(&self) -> &Action {
        &self.action
    }

    pub fn require_authorization(&self, account: Name) -> Result<(), ChainError> {
        for auth in self.action.authorization() {
            if auth.actor() == account {
                return Ok(());
            }
        }

        return Err(ChainError::TransactionError(format!(
            "missing authority of {}",
            account
        )));
    }

    pub fn add_ram_usage(&mut self, account: Name, ram_delta: i64) {
        self.account_ram_deltas
            .entry(account)
            .and_modify(|d| *d += ram_delta)
            .or_insert(ram_delta);
    }
}
