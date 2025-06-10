use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use pulsevm_chainbase::UndoSession;
use tokio::sync::RwLock;

use crate::chain::{ActionTrace, wasm_runtime::WasmRuntime};

use super::{
    Account, AccountMetadata, Action, Controller, Id, Name, TransactionContext, error::ChainError,
};

pub struct ApplyContext<'a, 'b, 'c>
where
    'a: 'b,
{
    controller: &'a Controller<'a, 'a>,
    undo_session: &'b mut UndoSession<'b>,
    transaction_context: &'c mut TransactionContext<'a, 'b>,

    action: Action,     // The action being applied
    receiver: Name,     // The account that is receiving the action
    recurse_depth: u32, // The current recursion depth
    first_receiver_action_ordinal: u32,
    action_ordinal: u32,
    privileged: bool,

    notified: VecDeque<(Name, u32)>, // List of notified accounts
    inline_actions: Vec<u32>,        // List of inline actions
    account_ram_deltas: HashMap<Name, i64>, // RAM usage deltas for accounts
}

impl<'a, 'b, 'c> ApplyContext<'a, 'b, 'c> {
    pub fn new(
        controller: &'a Controller<'a, 'a>,
        undo_session: &'b mut UndoSession<'b>,
        transaction_context: &'c mut TransactionContext<'a, 'b>,
        action_ordinal: u32,
        trace: &ActionTrace,
        depth: u32,
    ) -> Self {
        let action = trace.action();
        let receiver = trace.receiver();

        ApplyContext {
            controller,
            undo_session,
            transaction_context,

            action,
            receiver,
            recurse_depth: depth,
            first_receiver_action_ordinal: 0,
            action_ordinal,
            privileged: false,

            notified: VecDeque::new(),
            inline_actions: Vec::new(),
            account_ram_deltas: HashMap::new(),
        }
    }

    pub async fn exec(&mut self) -> Result<(), ChainError> {
        self.notified
            .push_back((self.receiver.clone(), self.action_ordinal));
        self.exec_one().await?;
        for i in 1..self.notified.len() {
            let (receiver, action_ordinal) = self.notified[i];
            self.receiver = receiver;
            self.action_ordinal = action_ordinal;
            self.exec_one().await?;
        }

        if self.inline_actions.len() > 0 && self.recurse_depth >= 1024 {
            return Err(ChainError::TransactionError(
                "recursion depth exceeded".to_string(),
            ));
        }

        for ordinal in self.inline_actions.iter() {
            self.transaction_context
                .execute_action(*ordinal, self.recurse_depth + 1)
                .await?;
        }

        Ok(())
    }

    pub async fn exec_one(&mut self) -> Result<(), ChainError> {
        let mut code_hash = Id::zero();

        {
            let receiver_account = self
                .undo_session
                .get::<AccountMetadata>(self.receiver.clone())
                .map_err(|e| {
                    ChainError::TransactionError(format!("failed to get receiver account: {}", e))
                })?;
            self.privileged = receiver_account.privileged;
            let native = self.controller.find_apply_handler(
                self.receiver,
                self.action.account(),
                self.action.name(),
            );
            if let Some(native) = native {
                native(self.controller, self, self.undo_session)?;
            }
        }
        // Does the receiver account have a contract deployed?
        if code_hash != Id::zero() {
            let runtime = self.controller.get_wasm_runtime();
            runtime.run(self.undo_session, self, code_hash).await?;
        }
        Ok(())
    }

    pub fn schedule_action_from_ordinal(
        &mut self,
        ordinal_of_action_to_schedule: u32,
        receiver: Name,
    ) -> Result<u32, ChainError> {
        let scheduled_action_ordinal = self.transaction_context.schedule_action_from_ordinal(
            ordinal_of_action_to_schedule,
            receiver,
            self.action_ordinal,
        )?;
        Ok(scheduled_action_ordinal)
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

    pub fn require_authorization_with_permission(
        &self,
        account: Name,
        permission: Name,
    ) -> Result<(), ChainError> {
        for auth in self.action.authorization() {
            if auth.actor() == account && auth.permission() == permission {
                return Ok(());
            }
        }

        return Err(ChainError::TransactionError(format!(
            "missing authority of {}/{}",
            account, permission
        )));
    }

    pub fn has_recipient(&self, recipient: Name) -> bool {
        self.notified.iter().any(|(r, _)| *r == recipient)
    }

    pub fn require_recipient(&mut self, recipient: Name) -> Result<(), ChainError> {
        if !self.has_recipient(recipient) {
            let scheduled_ordinal =
                self.schedule_action_from_ordinal(self.action_ordinal, recipient)?;
            self.notified.push_back((recipient, scheduled_ordinal));
        }

        Ok(())
    }

    pub fn has_authorization(&self, account: Name) -> bool {
        for auth in self.action.authorization() {
            if auth.actor() == account {
                return true;
            }
        }

        return false;
    }

    pub fn add_ram_usage(&mut self, account: Name, ram_delta: i64) {
        self.account_ram_deltas
            .entry(account)
            .and_modify(|d| *d += ram_delta)
            .or_insert(ram_delta);
    }

    pub fn is_account(&self, session: &UndoSession, account: Name) -> Result<bool, ChainError> {
        let exists = session
            .find::<Account>(account)
            .map(|account| account.is_some())
            .map_err(|e| ChainError::TransactionError(format!("failed to find account: {}", e)))?;
        Ok(exists)
    }

    pub fn get_receiver(&self) -> Name {
        self.receiver
    }
}
