use std::{collections::VecDeque, fmt};

use super::{Action, Name, TransactionContext, transaction, transaction_context};

pub enum ApplyContextError {
    AuthenticationError(String),
    RecurseDepthExceeded,
}

impl fmt::Display for ApplyContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplyContextError::AuthenticationError(msg) => {
                write!(f, "Authentication error: {}", msg)
            }
            ApplyContextError::RecurseDepthExceeded => write!(f, "Recurse depth exceeded"),
        }
    }
}

pub struct ApplyContext<'a, 'b> {
    action: Action,     // The action being applied
    receiver: Name,     // The account that is receiving the action
    recurse_depth: u32, // The current recursion depth
    first_receiver_action_ordinal: u32,
    action_ordinal: u32,
    priviliged: bool,
    transaction_context: &'a mut TransactionContext<'b>,

    notified: VecDeque<(Name, u32)>, // List of notified accounts
    inline_actions: Vec<u32>,        // List of inline actions
}

impl<'a, 'b> ApplyContext<'a, 'b> {
    pub fn new(
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
            transaction_context,
            notified: VecDeque::new(),
            inline_actions: Vec::new(),
        }
    }

    pub fn exec(&mut self) -> Result<(), ApplyContextError> {
        self.notified
            .push_back((self.receiver.clone(), self.action_ordinal));
        self.exec_one()?;
        for i in 1..self.notified.len() - 1 {
            let (receiver, action_ordinal) = self.notified[i];
            self.receiver = receiver;
            self.action_ordinal = action_ordinal;
            self.exec_one()?;
        }

        if self.inline_actions.len() > 0 && self.recurse_depth >= 1024 {
            return Err(ApplyContextError::RecurseDepthExceeded);
        }

        for ordinal in self.inline_actions.iter() {
            self.transaction_context
                .execute_action(*ordinal, self.recurse_depth + 1)?;
        }

        Ok(())
    }

    pub fn exec_one(&mut self) -> Result<(), ApplyContextError> {
        Ok(())
    }
}
