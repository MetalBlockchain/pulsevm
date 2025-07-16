use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
    rc::Rc,
    sync::{Arc, RwLock},
};

use pulsevm_chainbase::UndoSession;

use crate::chain::{
    AuthorizationManager, CODE_NAME,
    authority::{Permission, PermissionLevel},
    pulse_assert,
    wasm_runtime::WasmRuntime,
};

use super::{
    Account, AccountMetadata, Action, Controller, Id, Name, TransactionContext, error::ChainError,
};

#[derive(Clone)]
pub struct ApplyContext {
    session: Rc<RefCell<UndoSession>>, // The undo session for this context
    wasm_runtime: Arc<RwLock<WasmRuntime>>, // Context for the Wasm runtime
    trx_context: TransactionContext,   // The transaction context

    action: Action,     // The action being applied
    receiver: Name,     // The account that is receiving the action
    recurse_depth: u32, // The current recursion depth
    first_receiver_action_ordinal: u32,
    action_ordinal: u32,
    privileged: bool,

    notified: Rc<RefCell<VecDeque<(Name, u32)>>>, // List of notified accounts
    inline_actions: Rc<RefCell<Vec<u32>>>,        // List of inline actions
    account_ram_deltas: Rc<RefCell<HashMap<Name, i64>>>, // RAM usage deltas for accounts
}

impl ApplyContext {
    pub fn new(
        session: Rc<RefCell<UndoSession>>,
        wasm_runtime: Arc<RwLock<WasmRuntime>>,
        trx_context: TransactionContext,
        action: Action,
        receiver: Name,
        action_ordinal: u32,
        depth: u32,
    ) -> Result<Self, ChainError> {
        Ok(ApplyContext {
            session,
            wasm_runtime,
            trx_context,

            action,
            receiver,
            recurse_depth: depth,
            first_receiver_action_ordinal: 0,
            action_ordinal,
            privileged: false,

            notified: Rc::new(RefCell::new(VecDeque::new())),
            inline_actions: Rc::new(RefCell::new(Vec::new())),
            account_ram_deltas: Rc::new(RefCell::new(HashMap::new())),
        })
    }

    pub fn exec(&mut self, trx_context: &mut TransactionContext) -> Result<(), ChainError> {
        {
            self.notified
                .borrow_mut()
                .push_back((self.receiver.clone(), self.action_ordinal));
        }

        self.exec_one()?;

        let notified_pairs: Vec<(Name, u32)> = {
            let notified = self.notified.borrow();
            notified.iter().skip(1).cloned().collect()
        };

        for (receiver, action_ordinal) in notified_pairs {
            self.receiver = receiver;
            self.action_ordinal = action_ordinal;
            self.exec_one()?;
        }

        let inline_actions: Vec<u32> = {
            let inline_actions = self.inline_actions.borrow();
            inline_actions.clone()
        };

        if inline_actions.len() > 0 {
            pulse_assert(
                self.recurse_depth < 1024, // TODO: Make this configurable
                ChainError::TransactionError(
                    "max inline action depth per transaction reached".to_string(),
                ),
            )?;
        }

        for action_ordinal in inline_actions {
            trx_context.execute_action(action_ordinal, self.recurse_depth + 1)?;
        }

        Ok(())
    }

    pub fn exec_one(&mut self) -> Result<(), ChainError> {
        let code_hash = Id::zero();
        let receiver_account = self
            .session
            .borrow_mut()
            .get::<AccountMetadata>(self.receiver.clone())
            .map_err(|e| {
                ChainError::TransactionError(format!(
                    "failed to get receiver account: {}",
                    self.receiver.clone()
                ))
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
            let mut runtime = self.wasm_runtime.write().map_err(|e| {
                ChainError::TransactionError(format!("failed to get immutable wasm runtime: {}", e))
            })?;
            runtime.run(self.receiver, self.action.clone(), self.clone(), code_hash)?;
        }

        Ok(())
    }

    pub fn get_action(&self) -> &Action {
        &self.action
    }

    pub fn require_authorization(
        &self,
        account: Name,
        permission: Option<Name>,
    ) -> Result<(), ChainError> {
        for auth in self.action.authorization() {
            if let Some(perm) = permission {
                if auth.actor() == account && auth.permission() == perm {
                    return Ok(());
                }

                return Err(ChainError::TransactionError(format!(
                    "missing authority of {}/{}",
                    account, perm
                )));
            } else if auth.actor() == account {
                return Ok(());
            }
        }

        return Err(ChainError::TransactionError(format!(
            "missing authority of {}",
            account
        )));
    }

    pub fn has_recipient(&self, recipient: Name) -> bool {
        self.notified.borrow().iter().any(|(r, _)| *r == recipient)
    }

    pub fn require_recipient(&mut self, recipient: Name) -> Result<(), ChainError> {
        if !self.has_recipient(recipient) {
            let scheduled_ordinal =
                self.schedule_action_from_ordinal(self.action_ordinal, &recipient, false)?;
            self.notified
                .borrow_mut()
                .push_back((recipient, scheduled_ordinal));
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
            .borrow_mut()
            .entry(account)
            .and_modify(|d| *d += ram_delta)
            .or_insert(ram_delta);
    }

    pub fn is_account(&mut self, account: Name) -> Result<bool, ChainError> {
        let exists = self
            .session
            .borrow_mut()
            .find::<Account>(account)
            .map(|account| account.is_some())
            .map_err(|e| ChainError::TransactionError(format!("failed to find account: {}", e)))?;
        Ok(exists)
    }

    pub fn get_receiver(&self) -> Name {
        self.receiver
    }

    pub fn undo_session(&self) -> Rc<RefCell<UndoSession>> {
        self.session.clone()
    }

    pub fn execute_inline(&mut self, a: &Action) -> Result<(), ChainError> {
        {
            let mut session = self.session.borrow_mut();
            let code = session.find::<Account>(a.account())?;
            pulse_assert(
                code.is_some(),
                ChainError::TransactionError(format!(
                    "inline action's code account {} does not exist",
                    a.account()
                )),
            )?;

            for auth in a.authorization() {
                let actor = session.find::<Account>(auth.actor())?;
                pulse_assert(
                    actor.is_some(),
                    ChainError::TransactionError(format!(
                        "inline action's authorizing actor {} does not exist",
                        auth.actor()
                    )),
                )?;
                pulse_assert(
                    AuthorizationManager::find_permission(&mut session, auth)?.is_some(),
                    ChainError::TransactionError(format!(
                        "inline action's authorizations include a non-existent permission: {}",
                        auth
                    )),
                )?;
            }

            let mut provided_permissions = HashSet::new();
            provided_permissions.insert(PermissionLevel::new(self.receiver.clone(), CODE_NAME));

            AuthorizationManager::check_authorization(
                &mut session,
                &vec![a.clone()],
                &HashSet::new(),       // No provided keys
                &provided_permissions, // Default permission level
                &HashSet::new(),
            )?;
        }

        let inline_receiver = a.account();
        let scheduled_ordinal = self.schedule_action_from_action(a, &inline_receiver, false)?;
        self.inline_actions.borrow_mut().push(scheduled_ordinal);

        Ok(())
    }

    pub fn schedule_action_from_ordinal(
        &mut self,
        ordinal_of_action_to_schedule: u32,
        receiver: &Name,
        context_free: bool,
    ) -> Result<u32, ChainError> {
        let scheduled_action_ordinal = self.trx_context.schedule_action_from_ordinal(
            ordinal_of_action_to_schedule,
            receiver,
            context_free,
            self.action_ordinal,
            self.first_receiver_action_ordinal,
        )?;

        self.action = self.trx_context.get_action_trace(self.action_ordinal)?.act;

        Ok(scheduled_action_ordinal)
    }

    pub fn schedule_action_from_action(
        &mut self,
        act_to_schedule: &Action,
        receiver: &Name,
        context_free: bool,
    ) -> Result<u32, ChainError> {
        let scheduled_action_ordinal = self.trx_context.schedule_action(
            act_to_schedule,
            receiver,
            context_free,
            self.action_ordinal,
            self.first_receiver_action_ordinal,
        );

        self.action = self.trx_context.get_action_trace(self.action_ordinal)?.act;

        Ok(scheduled_action_ordinal)
    }
}
