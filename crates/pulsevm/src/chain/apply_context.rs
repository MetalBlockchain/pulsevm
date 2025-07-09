use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    rc::Rc,
    sync::{Arc, RwLock},
};

use pulsevm_chainbase::UndoSession;
use wasmtime::Ref;

use crate::chain::{
    ActionTrace, controller,
    wasm_runtime::{self, WasmContext, WasmRuntime},
};

use super::{
    Account, AccountMetadata, Action, Controller, Id, Name, TransactionContext, error::ChainError,
};

pub struct ApplyContext {
    pub session: Rc<RefCell<UndoSession>>, // The undo session for this context

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

impl ApplyContext {
    pub fn new(
        session: Rc<RefCell<UndoSession>>,
        action: Action,
        receiver: Name,
        action_ordinal: u32,
        depth: u32,
    ) -> Result<Self, ChainError> {
        Ok(ApplyContext {
            session,

            action,
            receiver,
            recurse_depth: depth,
            first_receiver_action_ordinal: 0,
            action_ordinal,
            privileged: false,

            notified: VecDeque::new(),
            inline_actions: Vec::new(),
            account_ram_deltas: HashMap::new(),
        })
    }

    pub fn exec(&mut self, wasm_runtime: Arc<RwLock<WasmRuntime>>) -> Result<(), ChainError> {
        self.notified
            .push_back((self.receiver.clone(), self.action_ordinal));
        self.exec_one(wasm_runtime.clone())?;
        for i in 1..self.notified.len() {
            let (receiver, action_ordinal) = self.notified[i];
            self.receiver = receiver;
            self.action_ordinal = action_ordinal;
            self.exec_one(wasm_runtime.clone())?;
        }

        // TODO: Handle inline actions

        Ok(())
    }

    pub fn exec_one(
        &mut self,
        wasm_runtime: Arc<RwLock<WasmRuntime>>,
    ) -> Result<(), ChainError> {
        let mut code_hash = Id::zero();

        let receiver_account = self
            .session
            .borrow()
            .get::<AccountMetadata>(self.receiver.clone())
            .map_err(|e| {
                ChainError::TransactionError(format!("failed to get receiver account: {}", e))
            })?;
        self.privileged = receiver_account.privileged;
        let native = Controller::find_apply_handler(
            self.receiver,
            self.action.account(),
            self.action.name(),
        );
        if let Some(native) = native {
            native(self)?;
        }

        // Does the receiver account have a contract deployed?
        if code_hash != Id::zero() {
            let mut runtime = wasm_runtime.write().map_err(|e| {
                ChainError::TransactionError(format!("failed to get mutable wasm runtime: {}", e))
            })?;
            //let wasm_context = WasmContext::new(self);
            runtime.run(Rc::new(RefCell::new(self)), code_hash)?;
        }
        Ok(())
    }

    pub fn schedule_action_from_ordinal(
        &mut self,
        ordinal_of_action_to_schedule: u32,
        receiver: Name,
    ) -> Result<u32, ChainError> {
        // TODO: Implement scheduling logic
        Ok(0)
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

    pub fn is_account(&self, account: Name) -> Result<bool, ChainError> {
        let exists = self.session
            .borrow_mut()
            .find::<Account>(account)
            .map(|account| account.is_some())
            .map_err(|e| ChainError::TransactionError(format!("failed to find account: {}", e)))?;
        Ok(exists)
    }

    pub fn get_receiver(&self) -> Name {
        self.receiver
    }
}
