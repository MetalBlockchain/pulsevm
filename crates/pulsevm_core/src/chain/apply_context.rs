use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, RwLock},
    u64,
};

use chrono::Utc;
use pulsevm_chainbase::UndoSession;
use pulsevm_crypto::Bytes;
use spdlog::info;

use crate::{
    CODE_NAME,
    chain::{
        account::{Account, AccountMetadata},
        authority::PermissionLevel,
        authorization_manager::AuthorizationManager,
        block::BlockTimestamp,
        config::{DynamicGlobalPropertyObject, billable_size_v},
        controller::Controller,
        error::ChainError,
        genesis::ChainConfig,
        id::Id,
        iterator_cache::IteratorCache,
        name::Name,
        table::{KeyValue, KeyValueByScopePrimaryIndex, Table, TableByCodeScopeTableIndex},
        transaction::{Action, ActionReceipt, generate_action_digest},
        transaction_context::TransactionContext,
        utils::pulse_assert,
        wasm_runtime::WasmRuntime,
    },
};

struct ApplyContextInner {
    keyval_cache: IteratorCache<KeyValue>, // Cache for iterators
    action_return_value: Option<Vec<u8>>,  // Return value of the action
    start: i64,                            // Start time in microseconds
    privileged: bool,
    account_ram_deltas: HashMap<Name, i64>, // RAM usage deltas for accounts
    notified: VecDeque<(Name, u32)>,        // List of notified accounts
    inline_actions: Vec<u32>,               // List of inline actions
    recurse_depth: u32, // The current recursion depth
}

#[derive(Clone)]
pub struct ApplyContext {
    pub chain_config: Arc<ChainConfig>,
    session: UndoSession,            // The undo session for this context
    wasm_runtime: WasmRuntime,       // Context for the Wasm runtime
    trx_context: TransactionContext, // The transaction context

    action: Action,     // The action being applied
    receiver: Name,     // The account that is receiving the action
    first_receiver_action_ordinal: u32,
    action_ordinal: u32,
    pending_block_timestamp: BlockTimestamp, // Timestamp for the pending block

    inner: Arc<RwLock<ApplyContextInner>>,
}

impl ApplyContext {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        session: UndoSession,
        wasm_runtime: WasmRuntime,
        trx_context: TransactionContext,
        action: Action,
        receiver: Name,
        action_ordinal: u32,
        depth: u32,
    ) -> Result<Self, ChainError> {
        let pending_block_timestamp = trx_context.pending_block_timestamp()?;

        Ok(ApplyContext {
            chain_config,
            session,
            wasm_runtime,
            trx_context,

            action,
            receiver,
            first_receiver_action_ordinal: 0,
            action_ordinal,
            pending_block_timestamp,

            inner: Arc::new(RwLock::new(ApplyContextInner {
                keyval_cache: IteratorCache::new(),
                action_return_value: None,
                start: Utc::now().timestamp_micros(),
                privileged: false,
                account_ram_deltas: HashMap::new(),
                notified: VecDeque::new(),
                inline_actions: Vec::new(),
                recurse_depth: depth,
            })),
        })
    }

    pub fn exec(&mut self, trx_context: &mut TransactionContext) -> Result<u64, ChainError> {
        let mut cpu_used = 0;

        {
            let mut inner = self.inner.write()?;
            inner
                .notified
                .push_back((self.receiver, self.action_ordinal));
        }

        cpu_used += self.exec_one()?;

        let notified_pairs: Vec<(Name, u32)> = {
            let inner = self.inner.read()?;
            inner.notified.iter().skip(1).cloned().collect()
        };

        for (receiver, action_ordinal) in notified_pairs {
            self.receiver = receiver;
            self.action_ordinal = action_ordinal;
            cpu_used += self.exec_one()?;
        }

        {
            let inner = self.inner.read()?;

            if inner.inline_actions.len() > 0 {
                pulse_assert(
                    inner.recurse_depth < 1024, // TODO: Make this configurable
                    ChainError::TransactionError(
                        "max inline action depth per transaction reached".to_string(),
                    ),
                )?;
            }

            for action_ordinal in inner.inline_actions.iter() {
                trx_context.execute_action(*action_ordinal, inner.recurse_depth + 1)?;
            }
        }

        Ok(cpu_used)
    }

    pub fn exec_one(&mut self) -> Result<u64, ChainError> {
        let mut receiver_account = self.get_account_metadata(self.receiver)?;
        let cpu_used = 100; // Base usage is always 100 instructions

        {
            let mut inner = self.inner.write()?;
            inner.privileged = receiver_account.privileged;
        }

        let native = Controller::find_apply_handler(
            self.receiver,
            self.action.account(),
            self.action.name(),
        );
        if let Some(native) = native {
            native(self)?;
        }

        // Refresh the receiver account metadata
        receiver_account = self.get_account_metadata(self.receiver)?;

        // Does the receiver account have a contract deployed?
        if receiver_account.code_hash != Id::zero() {
            self.wasm_runtime.run(
                self.receiver,
                self.action.clone(),
                self.clone(),
                receiver_account.code_hash,
            )?;
        }

        let act_digest = {
            let inner = self.inner.read()?;
            generate_action_digest(&self.action, inner.action_return_value.clone())
        };
        let first_receiver_account = if self.action.account() == self.receiver {
            receiver_account.clone()
        } else {
            self.get_account_metadata(self.action.account())?
        };
        let mut receipt = ActionReceipt::new(
            self.receiver,
            act_digest,
            self.next_global_sequence()?,
            self.next_recv_sequence(&mut receiver_account)?,
            HashMap::new(),
            first_receiver_account.code_sequence,
            first_receiver_account.abi_sequence,
        );

        for auth in self.action.clone().authorization().iter() {
            let auth_sequence = self.next_auth_sequence(&mut auth.actor.clone())?;
            receipt.add_auth_sequence(auth.actor, auth_sequence);
        }

        self.finalize_trace(receipt)?;

        Ok(cpu_used)
    }

    pub fn finalize_trace(&self, receipt: ActionReceipt) -> Result<(), ChainError> {
        let inner = self.inner.read()?;

        info!(
            "took {} us to execute action {}@{}",
            Utc::now().timestamp_micros() - inner.start,
            self.action.account(),
            self.action.name()
        );

        self.trx_context
            .modify_action_trace(self.action_ordinal, |trace| {
                trace.receipt = Some(receipt);
                trace.set_elapsed((Utc::now().timestamp_micros() - inner.start) as u32);
                trace.account_ram_deltas = inner.account_ram_deltas.clone();
            })?;
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
                if auth.actor == account && auth.permission == perm {
                    return Ok(());
                }

                return Err(ChainError::MissingAuthError(format!(
                    "missing authority of {}/{}",
                    account, perm
                )));
            } else if auth.actor == account {
                return Ok(());
            }
        }

        return Err(ChainError::MissingAuthError(format!(
            "missing authority of {}",
            account
        )));
    }

    pub fn has_recipient(&self, recipient: Name) -> Result<bool, ChainError> {
        let inner = self.inner.read()?;
        Ok(inner.notified.iter().any(|(r, _)| *r == recipient))
    }

    pub fn require_recipient(&mut self, recipient: Name) -> Result<(), ChainError> {
        if !self.has_recipient(recipient)? {
            let scheduled_ordinal =
                self.schedule_action_from_ordinal(self.action_ordinal, &recipient, false)?;
            let mut inner = self.inner.write()?;
            inner.notified.push_back((recipient, scheduled_ordinal));
        }

        Ok(())
    }

    pub fn has_authorization(&self, account: Name) -> bool {
        for auth in self.action.authorization() {
            if auth.actor == account {
                return true;
            }
        }

        return false;
    }

    pub fn add_ram_usage(&self, account: Name, ram_delta: i64) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;
        inner
            .account_ram_deltas
            .entry(account)
            .and_modify(|d| *d += ram_delta)
            .or_insert(ram_delta);
        Ok(())
    }

    pub fn is_account(&mut self, account: Name) -> Result<bool, ChainError> {
        let exists = self
            .session
            .find::<Account>(account)
            .map(|account| account.is_some())
            .map_err(|e| ChainError::TransactionError(format!("failed to find account: {}", e)))?;
        Ok(exists)
    }

    pub fn undo_session(&self) -> UndoSession {
        self.session.clone()
    }

    pub fn execute_inline(&mut self, a: &Action) -> Result<(), ChainError> {
        let send_to_self = a.account() == self.receiver;
        let inherit_parent_authorizations = send_to_self && self.receiver == self.action.account();

        {
            let code = self.session.find::<Account>(a.account())?;
            pulse_assert(
                code.is_some(),
                ChainError::TransactionError(format!(
                    "inline action's code account {} does not exist",
                    a.account()
                )),
            )?;

            let mut inherited_authorizations: HashSet<PermissionLevel> = HashSet::new();

            for auth in a.authorization() {
                let actor = self.session.find::<Account>(auth.actor)?;
                pulse_assert(
                    actor.is_some(),
                    ChainError::TransactionError(format!(
                        "inline action's authorizing actor {} does not exist",
                        auth.actor
                    )),
                )?;
                pulse_assert(
                    AuthorizationManager::find_permission(&mut self.session, auth)?.is_some(),
                    ChainError::TransactionError(format!(
                        "inline action's authorizations include a non-existent permission: {}",
                        auth
                    )),
                )?;

                if inherit_parent_authorizations
                    && self.action.authorization().iter().any(|pl| pl == auth)
                {
                    inherited_authorizations.insert(auth.clone());
                }
            }

            let mut provided_permissions = HashSet::new();
            provided_permissions.insert(PermissionLevel::new(self.receiver, CODE_NAME));
            let inner = self.inner.read()?;

            if !inner.privileged {
                AuthorizationManager::check_authorization(
                    &self.chain_config,
                    &mut self.session,
                    &vec![a.clone()],
                    &HashSet::new(),       // No provided keys
                    &provided_permissions, // Default permission level
                    &inherited_authorizations,
                )?;
            }
        }

        let inline_receiver = a.account();
        let scheduled_ordinal =
            self.schedule_action_from_action(a.clone(), &inline_receiver, false)?;
        let mut inner = self.inner.write()?;
        inner.inline_actions.push(scheduled_ordinal);

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
        act_to_schedule: Action,
        receiver: &Name,
        context_free: bool,
    ) -> Result<u32, ChainError> {
        let scheduled_action_ordinal = self.trx_context.schedule_action(
            act_to_schedule,
            receiver,
            context_free,
            self.action_ordinal,
            self.first_receiver_action_ordinal,
        )?;

        self.action = self.trx_context.get_action_trace(self.action_ordinal)?.act;

        Ok(scheduled_action_ordinal)
    }

    pub fn db_find_i64(
        &mut self,
        code: Name,
        scope: Name,
        table: Name,
        id: u64,
    ) -> Result<i32, ChainError> {
        let table = self.find_table(code, scope, table)?;

        match table {
            Some(table) => {
                let mut inner = self.inner.write()?;
                let table_end_itr = inner.keyval_cache.cache_table(&table);
                let obj = self
                    .session
                    .find_by_secondary::<KeyValue, KeyValueByScopePrimaryIndex>((table.id, id))
                    .map_err(|e| {
                        ChainError::TransactionError(format!("failed to find keyval: {}", e))
                    })?;

                match obj {
                    Some(keyval) => Ok(inner.keyval_cache.add(&keyval)),
                    None => Ok(table_end_itr),
                }
            }
            None => Ok(-1),
        }
    }

    pub fn db_store_i64(
        &mut self,
        scope: Name,
        table: Name,
        payer: Name,
        primary_key: u64,
        data: Bytes,
    ) -> Result<i32, ChainError> {
        let mut table = self.find_or_create_table(self.receiver, scope, table, payer)?;
        pulse_assert(
            !payer.empty(),
            ChainError::TransactionError(format!(
                "must specify a valid account to pay for new record"
            )),
        )?;

        let id = self.session.generate_id::<KeyValue>()?;
        let len = data.len();
        let key_value = KeyValue::new(id, table.id, primary_key, payer, data);
        self.session
            .insert(&key_value)
            .map_err(|e| ChainError::TransactionError(format!("failed to insert keyval: {}", e)))?;
        self.session.modify(&mut table, |t| {
            t.count += 1;
            Ok(())
        })?;

        let billable_size = len as i64 + billable_size_v::<KeyValue>() as i64;
        self.update_db_usage(payer, billable_size)?;

        let mut inner = self.inner.write()?;
        inner.keyval_cache.cache_table(&table);
        return Ok(inner.keyval_cache.add(&key_value));
    }

    pub fn db_get_i64(
        &self,
        iterator: i32,
        buffer: &mut Vec<u8>,
        buffer_size: usize,
    ) -> Result<i32, ChainError> {
        let inner = self.inner.read()?;
        let obj = inner.keyval_cache.get(iterator)?;
        let s = obj.value.len();
        if buffer_size == 0 {
            return Ok(s as i32);
        }
        let copy_size = core::cmp::min(buffer_size, s);
        if buffer.len() < copy_size {
            buffer.resize(copy_size, 0);
        }
        buffer[..copy_size].copy_from_slice(&obj.value.as_slice()[..copy_size]);
        Ok(copy_size as i32)
    }

    pub fn db_update_i64(
        &mut self,
        iterator: i32,
        payer: Name,
        data: impl AsRef<[u8]>,
    ) -> Result<(), ChainError> {
        let inner = self.inner.read()?;
        let obj = inner.keyval_cache.get(iterator)?;
        let table_obj = inner.keyval_cache.get_table(obj.table_id)?;
        pulse_assert(
            table_obj.code == self.receiver,
            ChainError::TransactionError(format!("db access violation",)),
        )?;

        let overhead = billable_size_v::<KeyValue>() as i64;
        let old_size = obj.value.len() as i64 + overhead;
        let new_size = data.as_ref().len() as i64 + overhead;

        let payer = if payer.empty() { obj.payer } else { payer };

        if obj.payer != payer {
            self.update_db_usage(obj.payer, -old_size)?;
            self.update_db_usage(payer, new_size)?;
        } else if old_size != new_size {
            self.update_db_usage(obj.payer, new_size - old_size)?;
        }

        self.session.modify(&mut obj.clone(), |kv| {
            kv.payer = payer;
            kv.value = Bytes::from(data.as_ref().to_vec());
            Ok(())
        })?;
        Ok(())
    }

    pub fn db_remove_i64(&mut self, iterator: i32) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;
        let obj = inner.keyval_cache.get(iterator)?;
        let table_obj = inner.keyval_cache.get_table(obj.table_id)?;
        pulse_assert(
            table_obj.code == self.receiver,
            ChainError::TransactionError(format!("db access violation",)),
        )?;

        self.update_db_usage(
            obj.payer,
            -(obj.value.len() as i64 + billable_size_v::<KeyValue>() as i64),
        )?;

        self.session.remove(obj.clone())?;
        self.session.modify(&mut table_obj.clone(), |t| {
            t.count -= 1;
            Ok(())
        })?;

        if table_obj.count == 0 {
            // If the table is empty, we can remove it
            self.session.remove(table_obj.clone())?;
        }

        inner.keyval_cache.remove(iterator)?;

        Ok(())
    }

    pub fn db_next_i64(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        if iterator < -1 {
            return Ok(-1); // Cannot increment past end iterator of table
        }

        let mut inner = self.inner.write()?;
        let obj = inner.keyval_cache.get(iterator)?;
        let mut idx = self
            .session
            .get_index::<KeyValue, KeyValueByScopePrimaryIndex>();

        let mut itr = idx.iterator_to(obj)?;
        let next_object = itr.next()?;

        match next_object {
            Some(next_object) => {
                if next_object.table_id != obj.table_id {
                    // If the primary key is the same, we are at the end of the table
                    return Ok(inner
                        .keyval_cache
                        .get_end_iterator_by_table_id(obj.table_id)?);
                }

                *primary = next_object.primary_key;

                return Ok(inner.keyval_cache.add(&next_object));
            }
            None => {
                // No more objects in this table
                return Ok(inner
                    .keyval_cache
                    .get_end_iterator_by_table_id(obj.table_id)?);
            }
        }
    }

    pub fn db_previous_i64(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let mut idx = self
            .session
            .get_index::<KeyValue, KeyValueByScopePrimaryIndex>();

        if iterator < -1 {
            // is end iterator
            let tab = inner
                .keyval_cache
                .find_table_by_end_iterator(iterator)?
                .ok_or(ChainError::TransactionError(format!(
                    "invalid end iterator"
                )))?;

            let mut itr = idx.upper_bound(
                (tab.id, u64::MIN), // Use u64::MIN to get the last element
            )?;
            let prev_object = itr.previous()?;

            match prev_object {
                Some(prev_object) => {
                    if prev_object.table_id != tab.id {
                        return Ok(-1); // Empty table
                    }

                    *primary = prev_object.primary_key;

                    return Ok(inner.keyval_cache.add(&prev_object));
                }
                None => {
                    // No more objects in this table
                    return Ok(-1);
                }
            }
        }

        let obj = inner.keyval_cache.get(iterator)?;
        let mut itr = idx.iterator_to(obj)?;
        let prev_object = itr.previous()?;

        match prev_object {
            Some(prev_object) => {
                if prev_object.table_id != obj.table_id {
                    return Ok(-1); // Empty table
                }

                *primary = prev_object.primary_key;

                return Ok(inner.keyval_cache.add(&prev_object));
            }
            None => {
                // No more objects in this table
                return Ok(-1);
            }
        }
    }

    pub fn db_end_i64(&mut self, code: Name, scope: Name, table: Name) -> Result<i32, ChainError> {
        let tab = self.find_table(code, scope, table)?;

        match tab {
            Some(table) => {
                let mut inner = self.inner.write()?;
                let end_itr = inner.keyval_cache.cache_table(&table);
                Ok(end_itr)
            }
            None => Ok(-1), // No table found, return end iterator
        }
    }

    pub fn db_lowerbound_i64(
        &mut self,
        code: Name,
        scope: Name,
        table: Name,
        primary: u64,
    ) -> Result<i32, ChainError> {
        let tab = self.find_table(code, scope, table)?;

        match tab {
            Some(table) => {
                let mut inner = self.inner.write()?;
                let end_itr = inner.keyval_cache.cache_table(&table);
                let mut idx = self
                    .session
                    .get_index::<KeyValue, KeyValueByScopePrimaryIndex>();
                let mut itr = idx.lower_bound((table.id, primary))?;
                let obj = itr.next()?;

                match obj {
                    Some(obj) => {
                        if obj.table_id != table.id {
                            return Ok(end_itr);
                        }

                        return Ok(inner.keyval_cache.add(&obj));
                    }
                    None => {
                        return Ok(end_itr);
                    }
                }
            }
            None => return Ok(-1), // No table found, return end iterator
        }
    }

    pub fn db_upperbound_i64(
        &mut self,
        code: Name,
        scope: Name,
        table: Name,
        primary: u64,
    ) -> Result<i32, ChainError> {
        let tab = self.find_table(code, scope, table)?;

        match tab {
            Some(table) => {
                let mut inner = self.inner.write()?;
                let end_itr = inner.keyval_cache.cache_table(&table);
                let mut idx = self
                    .session
                    .get_index::<KeyValue, KeyValueByScopePrimaryIndex>();
                let mut itr = idx.upper_bound((table.id, primary))?;
                let obj = itr.next()?;

                match obj {
                    Some(obj) => {
                        if obj.table_id != table.id {
                            return Ok(end_itr);
                        }

                        return Ok(inner.keyval_cache.add(&obj));
                    }
                    None => {
                        return Ok(end_itr);
                    }
                }
            }
            None => return Ok(-1), // No table found, return end iterator
        }
    }

    pub fn find_table(
        &mut self,
        code: Name,
        scope: Name,
        table: Name,
    ) -> Result<Option<Table>, ChainError> {
        let table = self
            .session
            .find_by_secondary::<Table, TableByCodeScopeTableIndex>((code, scope, table))
            .map_err(|e| ChainError::TransactionError(format!("failed to find table: {}", e)))?;
        Ok(table)
    }

    pub fn find_or_create_table(
        &mut self,
        code: Name,
        scope: Name,
        table: Name,
        payer: Name,
    ) -> Result<Table, ChainError> {
        let existing_tid = self
            .session
            .find_by_secondary::<Table, TableByCodeScopeTableIndex>((code, scope, table))
            .map_err(|e| ChainError::TransactionError(format!("failed to find table: {}", e)))?;
        if let Some(existing_table) = existing_tid {
            return Ok(existing_table);
        }
        // TODO: Update payer's RAM usage
        let id = self.session.generate_id::<Table>()?;
        let table = Table::new(
            id, code, scope, table, payer, 0, // Initial count is 0
        );
        self.session
            .insert(&table)
            .map_err(|e| ChainError::TransactionError(format!("failed to insert table: {}", e)))?;
        Ok(table)
    }

    pub fn get_account_metadata(&mut self, account: Name) -> Result<AccountMetadata, ChainError> {
        self.session.get::<AccountMetadata>(account).map_err(|e| {
            ChainError::TransactionError(format!("failed to get account metadata: {}", e))
        })
    }

    pub fn update_db_usage(&self, payer: Name, delta: i64) -> Result<(), ChainError> {
        if delta > 0 {
            // Do not allow charging RAM to other accounts during notify
            let inner = self.inner.read()?;
            if !(inner.privileged || payer == self.receiver) {
                self.require_authorization(payer, None).map_err(|_| {
                    ChainError::TransactionError(format!(
                        "cannot charge RAM to other accounts during notify"
                    ))
                })?;
            }
        }

        self.add_ram_usage(payer, delta)?;

        return Ok(());
    }

    pub fn set_action_return_value(&self, value: Vec<u8>) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;
        inner.action_return_value = Some(value);
        Ok(())
    }

    pub fn next_recv_sequence(
        &mut self,
        receiver_account: &mut AccountMetadata,
    ) -> Result<u64, ChainError> {
        let next_sequence = receiver_account.recv_sequence + 1;
        self.session.modify(receiver_account, |am| {
            am.recv_sequence = next_sequence;
            Ok(())
        })?;

        Ok(next_sequence)
    }

    pub fn next_auth_sequence(&mut self, actor: &Name) -> Result<u64, ChainError> {
        let mut amo = self.session.get::<AccountMetadata>(*actor)?;
        let next_sequence = amo.auth_sequence + 1;
        self.session.modify(&mut amo, |amo| {
            amo.auth_sequence = next_sequence;
            Ok(())
        })?;

        Ok(next_sequence)
    }

    pub fn next_global_sequence(&mut self) -> Result<u64, ChainError> {
        let dgpo = self.session.find::<DynamicGlobalPropertyObject>(0)?;

        if let Some(mut dgpo) = dgpo {
            let next_sequence = dgpo.global_action_sequence + 1;
            self.session.modify(&mut dgpo, |dgpo| {
                dgpo.global_action_sequence = next_sequence;
                Ok(())
            })?;
            return Ok(next_sequence);
        } else {
            self.session.insert(&DynamicGlobalPropertyObject::new(1))?;
            return Ok(1);
        }
    }

    pub fn is_privileged(&self) -> Result<bool, ChainError> {
        let inner = self.inner.read()?;
        Ok(inner.privileged)
    }

    pub fn set_privileged(&mut self, account: Name, is_privileged: bool) -> Result<(), ChainError> {
        let mut account = self.session.get::<AccountMetadata>(account.into())?;
        self.session.modify(&mut account, |acc| {
            acc.set_privileged(is_privileged);
            Ok(())
        })?;

        Ok(())
    }

    pub fn pending_block_timestamp(&self) -> BlockTimestamp {
        self.pending_block_timestamp
    }

    pub fn account_ram_deltas(&self) -> Result<HashMap<Name, i64>, ChainError> {
        let inner = self.inner.read()?;
        Ok(inner.account_ram_deltas.clone())
    }

    pub fn pause_billing_timer(&self) -> Result<(), ChainError> {
        self.trx_context.pause_billing_timer()?;
        Ok(())
    }

    pub fn resume_billing_timer(&self) -> Result<(), ChainError> {
        self.trx_context.resume_billing_timer()?;
        Ok(())
    }
}