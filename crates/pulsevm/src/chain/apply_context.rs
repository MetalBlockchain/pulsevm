use std::{
    cell::RefCell,
    cmp::min,
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
    rc::Rc,
    sync::{Arc, RwLock},
};

use jsonrpsee::tracing::field::Iter;
use pulsevm_chainbase::UndoSession;

use crate::chain::{
    AuthorizationManager, CODE_NAME, IteratorCache, KeyValue, KeyValueByScopePrimaryIndex, Table,
    TableByCodeScopeTableIndex,
    authority::{Permission, PermissionLevel},
    pulse_assert, table,
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
    keyval_cache: Rc<RefCell<IteratorCache<KeyValue>>>, // Cache for iterators
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
            keyval_cache: Rc::new(RefCell::new(IteratorCache::new())),
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
        let receiver_account = self.get_account_metadata(self.receiver)?;

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
        if receiver_account.code_hash != Id::zero() {
            let mut runtime = self.wasm_runtime.write().map_err(|e| {
                ChainError::TransactionError(format!("failed to get immutable wasm runtime: {}", e))
            })?;
            runtime.run(
                self.receiver,
                self.action.clone(),
                self.clone(),
                receiver_account.code_hash,
            )?;
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

    pub fn db_find_i64(
        &self,
        code: Name,
        scope: Name,
        table: Name,
        id: u64,
    ) -> Result<i32, ChainError> {
        let table = self.find_table(code, scope, table)?;

        if table.is_none() {
            return Ok(-1);
        }

        let table = table.unwrap();
        let mut keyval_cache = self.keyval_cache.borrow_mut();
        let table_end_itr = keyval_cache.cache_table(&table);
        let obj = self
            .session
            .borrow_mut()
            .find_by_secondary::<KeyValue, KeyValueByScopePrimaryIndex>((table.id, id))
            .map_err(|e| ChainError::TransactionError(format!("failed to find keyval: {}", e)))?;

        match obj {
            Some(keyval) => Ok(keyval_cache.add(&keyval)),
            None => Ok(table_end_itr),
        }
    }

    pub fn db_store_i64(
        &mut self,
        scope: Name,
        table: Name,
        payer: Name,
        primary_key: u64,
        data: &Vec<u8>,
    ) -> Result<i32, ChainError> {
        let mut table = self.find_or_create_table(self.receiver, scope, table, payer)?;
        pulse_assert(
            !payer.empty(),
            ChainError::TransactionError(format!(
                "must specify a valid account to pay for new record"
            )),
        )?;
        let mut session = self.session.borrow_mut();
        let id = session.generate_id::<KeyValue>()?;
        let key_value = KeyValue::new(id, table.id, primary_key, payer, data.clone());
        session
            .insert(&key_value)
            .map_err(|e| ChainError::TransactionError(format!("failed to insert keyval: {}", e)))?;
        session.modify(&mut table, |t| {
            t.count += 1;
        })?;
        // TODO: Update payer's RAM usage

        let mut keyval_cache = self.keyval_cache.borrow_mut();
        keyval_cache.cache_table(&table);
        return Ok(keyval_cache.add(&key_value));
    }

    pub fn find_table(
        &self,
        code: Name,
        scope: Name,
        table: Name,
    ) -> Result<Option<Table>, ChainError> {
        let mut session = self.session.borrow_mut();
        let table = session
            .find_by_secondary::<Table, TableByCodeScopeTableIndex>((code, scope, table))
            .map_err(|e| ChainError::TransactionError(format!("failed to find table: {}", e)))?;
        Ok(table)
    }

    pub fn db_get_i64(
        &self,
        iterator: i32,
        buffer: &mut Vec<u8>,
        buffer_size: usize,
    ) -> Result<i32, ChainError> {
        let keyval_cache = self.keyval_cache.borrow();
        let obj = keyval_cache.get(iterator)?;
        let s = obj.value.len();

        if buffer_size == 0 {
            return Ok(s as i32);
        }

        let copy_size = min(buffer_size, s);
        buffer.copy_from_slice(&obj.value[..copy_size]);
        return Ok(copy_size as i32);
    }

    pub fn db_update_i64(
        &mut self,
        iterator: i32,
        payer: Name,
        data: &Vec<u8>,
    ) -> Result<(), ChainError> {
        let keyval_cache = self.keyval_cache.borrow();
        let obj = keyval_cache.get(iterator)?;

        let table_obj = keyval_cache.get_table(obj.table_id)?;
        pulse_assert(
            table_obj.code == self.receiver,
            ChainError::TransactionError(format!("db access violation",)),
        )?;

        let payer = if payer.empty() {
            obj.payer.clone()
        } else {
            payer
        };

        // TODO: Update payer's RAM usage

        let mut session = self.session.borrow_mut();
        session.modify(&mut obj.clone(), |kv| {
            kv.payer = payer;
            kv.value = data.clone();
        })?;
        Ok(())
    }

    pub fn db_remove_i64(&mut self, iterator: i32) -> Result<(), ChainError> {
        let mut keyval_cache = self.keyval_cache.borrow_mut();
        let obj = keyval_cache.get(iterator)?;

        let table_obj = keyval_cache.get_table(obj.table_id)?;
        pulse_assert(
            table_obj.code == self.receiver,
            ChainError::TransactionError(format!("db access violation",)),
        )?;

        // TODO: Update payer's RAM usage

        let mut session = self.session.borrow_mut();
        session.remove(obj.clone())?;
        session.modify(&mut table_obj.clone(), |t| {
            t.count -= 1;
        })?;

        if table_obj.count == 0 {
            // If the table is empty, we can remove it
            session.remove(table_obj.clone())?;
        }

        keyval_cache.remove(iterator)?;

        Ok(())
    }

    pub fn find_or_create_table(
        &mut self,
        code: Name,
        scope: Name,
        table: Name,
        payer: Name,
    ) -> Result<Table, ChainError> {
        let mut session = self.session.borrow_mut();
        let existing_tid = session
            .find_by_secondary::<Table, TableByCodeScopeTableIndex>((code, scope, table))
            .map_err(|e| ChainError::TransactionError(format!("failed to find table: {}", e)))?;
        if let Some(existing_table) = existing_tid {
            return Ok(existing_table);
        }
        // TODO: Update payer's RAM usage
        let id = session.generate_id::<Table>()?;
        let table = Table::new(
            id, code, scope, table, payer, 0, // Initial count is 0
        );
        session
            .insert(&table)
            .map_err(|e| ChainError::TransactionError(format!("failed to insert table: {}", e)))?;
        Ok(table)
    }

    pub fn get_account_metadata(
        &self,
        account: Name,
    ) -> Result<AccountMetadata, ChainError> {
        let mut session = self.session.borrow_mut();
        session
            .get::<AccountMetadata>(account)
            .map_err(|e| ChainError::TransactionError(format!("failed to get account metadata: {}", e)))
    }
}
