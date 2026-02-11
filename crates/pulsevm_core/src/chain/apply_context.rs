use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, RwLock},
    u64,
};

use chrono::Utc;
use pulsevm_billable_size::billable_size_v;
use pulsevm_crypto::Bytes;
use pulsevm_error::ChainError;
use pulsevm_ffi::{
    AccountMetadataObject, Database, KeyValueIteratorCache, KeyValueObject, TableObject,
};
use spdlog::debug;

use crate::{
    CODE_NAME,
    chain::{
        authority::PermissionLevel,
        authorization_manager::AuthorizationManager,
        block::BlockTimestamp,
        controller::Controller,
        transaction::{Action, ActionReceipt, generate_action_digest},
        transaction_context::TransactionContext,
        utils::pulse_assert,
        wasm_runtime::WasmRuntime,
    },
    name::Name,
};

struct ApplyContextInner {
    action: Action,                       // The action being applied
    action_return_value: Option<Vec<u8>>, // Return value of the action
    start: i64,                           // Start time in microseconds
    privileged: bool,
    account_ram_deltas: HashMap<Name, i64>, // RAM usage deltas for accounts
    notified: VecDeque<(Name, u32)>,        // List of notified accounts
    inline_actions: Vec<u32>,               // List of inline actions
    recurse_depth: u32,                     // The current recursion depth
    keyval_cache: KeyValueIteratorCache,    // Cache for key-value iterators
}

#[derive(Clone)]
pub struct ApplyContext {
    wasm_runtime: WasmRuntime,       // Context for the Wasm runtime
    trx_context: TransactionContext, // The transaction context
    db: Database,                    // The database being used

    receiver: Name, // The account that is receiving the action
    first_receiver_action_ordinal: u32,
    action_ordinal: u32,
    pending_block_timestamp: BlockTimestamp, // Timestamp for the pending block

    inner: Arc<RwLock<ApplyContextInner>>,
}

impl ApplyContext {
    pub fn new(
        db: Database,
        wasm_runtime: WasmRuntime,
        trx_context: TransactionContext,
        action: Action,
        receiver: Name,
        action_ordinal: u32,
        depth: u32,
    ) -> Result<Self, ChainError> {
        let pending_block_timestamp = trx_context.pending_block_timestamp()?;

        Ok(ApplyContext {
            wasm_runtime,
            trx_context,
            db,

            receiver,
            first_receiver_action_ordinal: 0,
            action_ordinal,
            pending_block_timestamp,

            inner: Arc::new(RwLock::new(ApplyContextInner {
                action,
                action_return_value: None,
                start: Utc::now().timestamp_micros(),
                privileged: false,
                account_ram_deltas: HashMap::new(),
                notified: VecDeque::new(),
                inline_actions: Vec::new(),
                recurse_depth: depth,
                keyval_cache: KeyValueIteratorCache::new(),
            })),
        })
    }

    pub fn exec(&mut self, trx_context: &mut TransactionContext) -> Result<u64, ChainError> {
        let mut cpu_used = 0;

        {
            let mut inner = self.inner.write()?;
            inner
                .notified
                .push_back((self.receiver.clone(), self.action_ordinal));
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
        let receiver_account = self.db.get_account_metadata(self.receiver.as_u64())?;
        let cpu_used = 100; // Base usage is always 100 instructions
        let action = {
            let mut inner = self.inner.write()?;
            inner.privileged = receiver_account.is_privileged();
            inner.action.clone()
        };

        let native =
            Controller::find_apply_handler(&self.receiver, action.account(), action.name());
        if let Some(native) = native {
            native(self, &mut self.db.clone(), &action)?;
        }

        // Refresh the receiver account metadata
        let receiver_account = self.db.get_account_metadata(self.receiver.as_u64())?;

        // Does the receiver account have a contract deployed?
        if !receiver_account.get_code_hash().empty() {
            self.wasm_runtime.run(
                self.receiver.clone(),
                action.clone(),
                self.clone(),
                self.db.clone(),
                receiver_account.get_code_hash(),
            )?;
        }

        let act_digest = {
            let inner = self.inner.read()?;
            generate_action_digest(&action, inner.action_return_value.clone())
        };
        let first_receiver_account = if action.account() == &self.receiver {
            receiver_account
        } else {
            self.db.get_account_metadata(action.account().as_u64())?
        };
        let mut receipt = ActionReceipt::new(
            self.receiver.clone(),
            act_digest,
            self.next_global_sequence()?,
            self.next_recv_sequence(&receiver_account)?,
            HashMap::new(),
            first_receiver_account.get_code_sequence() as u32,
            first_receiver_account.get_abi_sequence() as u32,
        );

        for auth in action.clone().authorization().iter() {
            let auth_sequence = self.next_auth_sequence(auth.actor)?;
            receipt.add_auth_sequence(auth.actor.clone(), auth_sequence);
        }

        self.finalize_trace(receipt)?;

        Ok(cpu_used)
    }

    pub fn finalize_trace(&self, receipt: ActionReceipt) -> Result<(), ChainError> {
        let inner = self.inner.read()?;

        debug!(
            "took {} us to execute action {}@{}",
            Utc::now().timestamp_micros() - inner.start,
            inner.action.account(),
            inner.action.name()
        );

        self.trx_context
            .modify_action_trace(self.action_ordinal, |trace| {
                trace.receipt = Some(receipt);
                trace.set_elapsed((Utc::now().timestamp_micros() - inner.start) as u32);
                trace.account_ram_deltas = inner.account_ram_deltas.clone();
            })?;
        Ok(())
    }

    pub fn require_authorization(
        &self,
        account: &Name,
        permission: Option<Name>,
    ) -> Result<(), ChainError> {
        let inner = self.inner.read()?;

        for auth in inner.action.authorization() {
            if let Some(perm) = permission {
                if auth.actor == *account && auth.permission == perm {
                    return Ok(());
                }

                return Err(ChainError::MissingAuthError(format!(
                    "missing authority of {}/{}",
                    account, perm
                )));
            } else if auth.actor == account.as_u64() {
                return Ok(());
            }
        }

        return Err(ChainError::MissingAuthError(format!(
            "missing authority of {}",
            account
        )));
    }

    pub fn has_recipient(&self, recipient: &Name) -> Result<bool, ChainError> {
        let inner = self.inner.read()?;
        Ok(inner.notified.iter().any(|(r, _)| r == recipient))
    }

    pub fn require_recipient(&mut self, recipient: &Name) -> Result<(), ChainError> {
        if !self.has_recipient(recipient)? {
            let scheduled_ordinal =
                self.schedule_action_from_ordinal(self.action_ordinal, &recipient, false)?;
            let mut inner = self.inner.write()?;
            inner
                .notified
                .push_back((recipient.clone(), scheduled_ordinal));
        }

        Ok(())
    }

    pub fn has_authorization(&self, account: &Name) -> Result<bool, ChainError> {
        let inner = self.inner.read()?;

        for auth in inner.action.authorization() {
            if auth.actor == *account {
                return Ok(true);
            }
        }

        return Ok(false);
    }

    pub fn add_ram_usage(&mut self, account: &Name, ram_delta: i64) -> Result<(), ChainError> {
        let mut inner = self.inner.write()?;
        inner
            .account_ram_deltas
            .entry(account.clone())
            .and_modify(|d| *d += ram_delta)
            .or_insert(ram_delta);
        Ok(())
    }

    pub fn is_account(&self, account: &Name) -> Result<bool, ChainError> {
        self.db.is_account(account.as_u64())
    }

    pub fn execute_inline(&mut self, a: &Action) -> Result<(), ChainError> {
        let action = {
            let inner = self.inner.read()?;
            inner.action.clone()
        };
        let send_to_self = a.account() == &self.receiver;
        let inherit_parent_authorizations = send_to_self && &self.receiver == action.account();

        {
            let code = self.db.find_account(a.account().as_u64())?;
            pulse_assert(
                !code.is_null(),
                ChainError::TransactionError(format!(
                    "inline action's code account {} does not exist",
                    a.account()
                )),
            )?;

            let mut inherited_authorizations: HashSet<PermissionLevel> = HashSet::new();

            for auth in a.authorization() {
                let actor = self.db.find_account(auth.actor)?;
                pulse_assert(
                    !actor.is_null(),
                    ChainError::TransactionError(format!(
                        "inline action's authorizing actor {} does not exist",
                        auth.actor
                    )),
                )?;
                pulse_assert(
                    AuthorizationManager::find_permission(&mut self.db, auth)?.is_some(),
                    ChainError::TransactionError(format!(
                        "inline action's authorizations include a non-existent permission: {}",
                        auth
                    )),
                )?;

                if inherit_parent_authorizations
                    && action.authorization().iter().any(|pl| pl == auth)
                {
                    inherited_authorizations.insert(auth.clone());
                }
            }

            let mut provided_permissions = HashSet::new();
            provided_permissions.insert(PermissionLevel::new(*self.receiver, CODE_NAME.into()));
            let inner = self.inner.read()?;

            if !inner.privileged {
                AuthorizationManager::check_authorization(
                    &mut self.db,
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

        {
            let mut inner = self.inner.write()?;
            inner.action = self.trx_context.get_action_trace(self.action_ordinal)?.act;
        }

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

        {
            let mut inner = self.inner.write()?;
            inner.action = self.trx_context.get_action_trace(self.action_ordinal)?.act;
        }

        Ok(scheduled_action_ordinal)
    }

    pub fn db_find_i64(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        id: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;

        match self
            .db
            .db_find_i64(code, scope, table, id, &mut inner.keyval_cache)
        {
            Ok(itr) => Ok(itr),
            Err(e) => Err(ChainError::DatabaseError(format!(
                "failed to find i64 in db: {}",
                e
            ))),
        }
    }

    pub fn db_store_i64(
        &mut self,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        data: Bytes,
    ) -> Result<i32, ChainError> {
        let table = self.find_or_create_table(*self.receiver, scope, table, payer)?;
        let table = unsafe { &*table };
        pulse_assert(
            payer != 0,
            ChainError::TransactionError(format!(
                "must specify a valid account to pay for new record"
            )),
        )?;

        let res = {
            let mut inner = self.inner.write()?;
            let obj =
                self.db
                    .create_key_value_object(table, payer, primary_key, &data.0.as_slice())?;
            let obj = unsafe { &*obj };
            inner.keyval_cache.cache_table(&table)?;
            inner.keyval_cache.add(obj)?
        };

        let billable_size = data.len() as i64 + billable_size_v::<KeyValueObject>() as i64;
        self.update_db_usage(&payer.into(), billable_size)?;

        Ok(res)
    }

    pub fn db_update_i64(
        &mut self,
        iterator: i32,
        payer: &Name,
        data: impl AsRef<[u8]>,
    ) -> Result<(), ChainError> {
        let payer = payer.as_u64();
        let new_size = data.as_ref().len() as i64;
        let (old_size, old_payer, new_payer) = {
            let inner = self.inner.read()?;
            let obj = inner.keyval_cache.get(iterator)?;
            let table_obj = inner.keyval_cache.get_table(obj.get_table_id())?;
            pulse_assert(
                table_obj.get_code().to_uint64_t() == self.receiver.as_u64(),
                ChainError::TransactionError(format!("db access violation",)),
            )?;
            let old_payer = obj.get_payer().to_uint64_t();
            let new_payer = if payer == 0 {
                obj.get_payer().to_uint64_t()
            } else {
                payer
            };
            let old_size = obj.get_value().size() as i64;
            self.db
                .update_key_value_object(obj, new_payer, data.as_ref())?;
            (old_size, old_payer, new_payer)
        };

        let overhead = billable_size_v::<KeyValueObject>() as i64;
        let old_size = old_size + overhead;
        let new_size = new_size + overhead;

        if old_payer != new_payer {
            self.update_db_usage(&Name::new(old_payer), -old_size)?;
            self.update_db_usage(&Name::new(new_payer), new_size)?;
        } else if old_size != new_size {
            self.update_db_usage(&Name::new(new_payer), new_size - old_size)?;
        }

        Ok(())
    }

    pub fn db_get_i64(
        &self,
        iterator: i32,
        buffer: &mut Vec<u8>,
        buffer_size: usize,
    ) -> Result<i32, ChainError> {
        let inner = self.inner.read()?;
        let obj = inner.keyval_cache.get(iterator)?;
        let s = obj.get_value().size();
        if buffer_size == 0 {
            return Ok(s as i32);
        }
        let copy_size = core::cmp::min(buffer_size, s);
        if buffer.len() < copy_size {
            buffer.resize(copy_size, 0);
        }
        buffer[..copy_size].copy_from_slice(&obj.get_value().as_slice()[..copy_size]);
        Ok(copy_size as i32)
    }

    pub fn db_remove_i64(&mut self, iterator: i32) -> Result<(), ChainError> {
        let delta = {
            let mut inner = self.inner.write()?;
            let delta =
                self.db
                    .db_remove_i64(&mut inner.keyval_cache, iterator, self.receiver.as_u64())?;
            delta
        };

        self.update_db_usage(&Name::new(self.receiver.as_u64()), -delta)?;

        Ok(())
    }

    pub fn db_next_i64(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        self.db
            .db_next_i64(&mut inner.keyval_cache, iterator, primary)
    }

    pub fn db_previous_i64(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        self.db
            .db_previous_i64(&mut inner.keyval_cache, iterator, primary)
    }

    pub fn db_end_i64(&mut self, code: u64, scope: u64, table: u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        self.db
            .db_end_i64(&mut inner.keyval_cache, code, scope, table)
    }

    pub fn db_lowerbound_i64(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        self.db
            .db_lowerbound_i64(&mut inner.keyval_cache, code, scope, table, primary)
    }

    pub fn db_upperbound_i64(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        self.db
            .db_upperbound_i64(&mut inner.keyval_cache, code, scope, table, primary)
    }

    pub fn find_table(
        &self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<*const TableObject, ChainError> {
        self.db.find_table(code, scope, table)
    }

    pub fn find_or_create_table(
        &mut self,
        code: u64,
        scope: u64,
        table_name: u64,
        payer: u64,
    ) -> Result<*const TableObject, ChainError> {
        let table = self.find_table(code, scope, table_name)?;

        if table.is_null() {
            self.update_db_usage(&payer.into(), billable_size_v::<TableObject>() as i64)?;

            return self.db.create_table(code, scope, table_name, payer);
        } else {
            Ok(table)
        }
    }

    pub fn remove_table(&mut self, table: &TableObject) -> Result<(), ChainError> {
        self.update_db_usage(
            &table.get_payer().to_uint64_t().into(),
            -(billable_size_v::<TableObject>() as i64),
        )?;
        self.db.remove_table(table)?;
        Ok(())
    }

    pub fn update_db_usage(&mut self, payer: &Name, delta: i64) -> Result<(), ChainError> {
        if delta > 0 {
            // Do not allow charging RAM to other accounts during notify
            let inner = self.inner.read()?;
            if !(inner.privileged || *payer == self.receiver.as_u64()) {
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
        receiver_account: &AccountMetadataObject,
    ) -> Result<u64, ChainError> {
        self.db.next_recv_sequence(receiver_account)
    }

    pub fn next_auth_sequence(&mut self, actor: u64) -> Result<u64, ChainError> {
        self.db.next_auth_sequence(actor)
    }

    pub fn next_global_sequence(&mut self) -> Result<u64, ChainError> {
        self.db.next_global_sequence()
    }

    pub fn is_privileged(&self) -> Result<bool, ChainError> {
        let inner = self.inner.read()?;
        Ok(inner.privileged)
    }

    pub fn set_privileged(&mut self, account: u64, is_privileged: bool) -> Result<(), ChainError> {
        self.db.set_privileged(account, is_privileged)?;
        Ok(())
    }

    pub fn pending_block_timestamp(&self) -> &BlockTimestamp {
        &self.pending_block_timestamp
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

    pub fn get_head_block_num(&self) -> u32 {
        0 // TODO: Fix
    }

    pub fn get_pending_block_time(&self) -> &BlockTimestamp {
        &self.pending_block_timestamp
    }
}
