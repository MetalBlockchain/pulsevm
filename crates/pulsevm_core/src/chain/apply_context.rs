use std::{
    collections::{
        BTreeMap,
        BTreeSet,
        VecDeque,
    },
    sync::{
        Arc,
        RwLock,
    },
    u64,
};

use chrono::Utc;
use pulsevm_billable_size::billable_size_v;
use pulsevm_crypto::Bytes;
use pulsevm_database::{
    BlockTimestamp,
    ChainConfigV0,
    Database,
    Float128,
    Index64Object,
    Index128Object,
    Index256Object,
    IndexDoubleObject,
    IndexLongDoubleObject,
    KeyValueObject,
    Microseconds,
    TableObject,
    U256,
};
use pulsevm_error::ChainError;
use pulsevm_serialization::Write;

use crate::{
    CODE_NAME,
    chain::{
        authority::PermissionLevel,
        authorization_manager::AuthorizationManager,
        controller::Controller,
        producer_schedule::ProducerKey,
        transaction::{
            Action,
            ActionReceipt,
            generate_action_digest,
        },
        transaction_context::TransactionContext,
        utils::pulse_assert,
        wasm_runtime::WasmRuntime,
    },
    name::Name,
    transaction::PackedTransaction,
};

struct ApplyContextInner {
    action: Action,                       // The action being applied
    action_return_value: Option<Vec<u8>>, // Return value of the action
    start: i64,                           // Start time in microseconds
    privileged: bool,
    account_ram_deltas: BTreeMap<Name, i64>, // RAM usage deltas for accounts
    notified: VecDeque<(Name, u32)>,         // List of notified accounts
    inline_actions: Vec<u32>,                // List of inline actions
    context_free_inline_actions: Vec<u32>,   // List of context-free inline actions
    recurse_depth: u32,                      // The current recursion depth
    // The arena mints the key-value iterator handles a contract sees.
    arena_keyval_cache: ArenaIteratorCache,
    // The arena keeps a separate iterator cache per secondary-index type, mirroring
    // each independently.
    arena_index64_cache: ArenaIteratorCache,
    arena_index128_cache: ArenaIteratorCache,
    arena_index256_cache: ArenaIteratorCache,
    arena_index_double_cache: ArenaIteratorCache,
    arena_index_long_double_cache: ArenaIteratorCache,
    cpu_limit: i64, // CPU limit for the current action
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
    context_free: bool,

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
        cpu_limit: i64,
        context_free: bool,
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
            context_free,

            inner: Arc::new(RwLock::new(ApplyContextInner {
                action,
                action_return_value: None,
                start: Utc::now().timestamp_micros(),
                privileged: false,
                account_ram_deltas: BTreeMap::new(),
                notified: VecDeque::new(),
                inline_actions: Vec::new(),
                context_free_inline_actions: Vec::new(),
                recurse_depth: depth,
                arena_keyval_cache: ArenaIteratorCache::default(),
                arena_index64_cache: ArenaIteratorCache::default(),
                arena_index128_cache: ArenaIteratorCache::default(),
                arena_index256_cache: ArenaIteratorCache::default(),
                arena_index_double_cache: ArenaIteratorCache::default(),
                arena_index_long_double_cache: ArenaIteratorCache::default(),
                cpu_limit,
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

        let (recurse_depth, inline_actions, context_free_inline_actions) = {
            let inner = self.inner.read()?;
            (
                inner.recurse_depth,
                inner.inline_actions.clone(),
                inner.context_free_inline_actions.clone(),
            )
        };

        if inline_actions.len() > 0 || context_free_inline_actions.len() > 0 {
            let max_inline_action_depth = self.db.chain_config()?.max_inline_action_depth;

            pulse_assert(
                recurse_depth < max_inline_action_depth as u32,
                ChainError::TransactionError(
                    "max inline action depth per transaction reached".to_string(),
                ),
            )?;
        }

        for action_ordinal in context_free_inline_actions.iter() {
            trx_context.execute_action(*action_ordinal, recurse_depth + 1)?;
        }

        for action_ordinal in inline_actions.iter() {
            trx_context.execute_action(*action_ordinal, recurse_depth + 1)?;
        }

        Ok(cpu_used)
    }

    pub fn exec_one(&mut self) -> Result<u64, ChainError> {
        let privileged = self.db.is_account_privileged(self.receiver.as_u64())?;
        let mut cpu_used = 100; // Base usage is always 100 instructions
        let action = {
            let mut inner = self.inner.write()?;
            inner.privileged = privileged;
            inner.action.clone()
        };

        let native =
            Controller::find_apply_handler(&self.receiver, action.account(), action.name());
        if let Some(native) = native {
            native(self, &mut self.db.clone(), &action)?;
            // Native handlers are outside deterministic Wasm metering, so give
            // the subjective watchdog a cooperative boundary after they return.
            self.trx_context.checktime()?;
        }

        // Does the receiver account have a contract deployed? Read the deployed
        // code hash from the Rust database. An all-zero hash means no contract.
        let (code_hash, _vm_type, _vm_version) =
            self.db.account_code_hash_vm(self.receiver.as_u64())?;
        if code_hash != [0u8; 32] {
            // Separate context here because we need to release the lock on inner before executing
            // the Wasm code, which may call back into the context and cause deadlock if we hold the
            // lock.
            let cpu_limit = {
                let inner = self.inner.read()?;
                inner.cpu_limit
            };

            cpu_used += self.wasm_runtime.run(
                self.receiver.clone(),
                action.clone(),
                self.clone(),
                self.db.clone(),
                &code_hash,
                cpu_limit,
            )?;
        }

        let act_digest = {
            let inner = self.inner.read()?;
            generate_action_digest(&action, inner.action_return_value.clone())
        };
        let (code_sequence, abi_sequence) = self
            .db
            .account_metadata_code_abi_sequence(action.account().as_u64())?;
        let mut receipt = ActionReceipt::new(
            self.receiver.clone(),
            act_digest,
            self.next_global_sequence()?,
            self.next_recv_sequence(self.receiver.as_u64())?,
            BTreeMap::new(),
            code_sequence as u32,
            abi_sequence as u32,
        );

        for auth in action.clone().authorization().iter() {
            let auth_sequence = self.next_auth_sequence(auth.actor)?;
            receipt.add_auth_sequence(auth.actor.clone(), auth_sequence);
        }

        // Calculate action digest
        self.trx_context
            .add_executed_action_receipt_digest(receipt.digest()?)?;
        self.finalize_trace(receipt)?;

        Ok(cpu_used)
    }

    pub fn finalize_trace(&self, receipt: ActionReceipt) -> Result<(), ChainError> {
        let inner = self.inner.read()?;

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
                if auth.actor == account.as_u64() && auth.permission == perm.as_u64() {
                    return Ok(());
                }
            } else if permission == None && auth.actor == account.as_u64() {
                return Ok(());
            }
        }

        if let Some(perm) = permission {
            return Err(ChainError::MissingAuthError(format!(
                "missing authority of {}/{}",
                account, perm
            )));
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
        let entry = inner.account_ram_deltas.entry(account.clone()).or_insert(0);
        *entry = entry.checked_add(ram_delta).ok_or_else(|| {
            ChainError::ActionValidationError(format!("RAM usage overflow for account {}", account))
        })?;
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
            pulse_assert(
                self.db.is_account(a.account().as_u64())?,
                ChainError::TransactionError(format!(
                    "inline action's code account {} does not exist",
                    a.account()
                )),
            )?;

            let mut inherited_authorizations: BTreeSet<PermissionLevel> = BTreeSet::new();

            for auth in a.authorization() {
                pulse_assert(
                    self.db.is_account(auth.actor)?,
                    ChainError::TransactionError(format!(
                        "inline action's authorizing actor {} does not exist",
                        auth.actor
                    )),
                )?;
                pulse_assert(
                    AuthorizationManager::find_permission(&self.db.read()?, auth)?.is_some(),
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

            let mut provided_permissions = BTreeSet::new();
            provided_permissions.insert(PermissionLevel::new(*self.receiver, CODE_NAME.into()));
            let inner = self.inner.read()?;

            if !inner.privileged {
                AuthorizationManager::check_authorization(
                    &mut self.db,
                    &vec![a.clone()],
                    &BTreeSet::new(),      // No provided keys
                    &provided_permissions, // Default permission level
                    Microseconds::new(0),  // No delay
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

    pub fn execute_context_free_inline(&mut self, a: &Action) -> Result<(), ChainError> {
        pulse_assert(
            self.db.is_account(a.account().as_u64())?,
            ChainError::TransactionError(format!(
                "inline action's code account {} does not exist",
                a.account()
            )),
        )?;
        pulse_assert(
            a.authorization().len() == 0,
            ChainError::TransactionError(format!(
                "context-free actions cannot have authorizations",
            )),
        )?;

        let inline_receiver = a.account();
        let scheduled_ordinal =
            self.schedule_action_from_action(a.clone(), &inline_receiver, true)?;
        let mut inner = self.inner.write()?;
        inner.context_free_inline_actions.push(scheduled_ordinal);

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

    pub fn get_context_free_data(
        &self,
        index: u32,
        buffer: &mut [u8],
        buffer_size: usize,
    ) -> Result<i32, ChainError> {
        let trx = self
            .trx_context
            .get_packed_transaction()
            .get_signed_transaction();
        let cfd = trx.context_free_data();

        let segment = match cfd.get(index as usize) {
            Some(seg) => seg,
            None => return Ok(-1),
        };

        let s = segment.len();
        if buffer_size == 0 {
            return Ok(s as i32);
        }

        let copy_size = buffer_size.min(buffer.len()).min(s);
        buffer[..copy_size].copy_from_slice(&segment.as_slice()[..copy_size]);
        Ok(copy_size as i32)
    }

    pub fn db_find_i64(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        id: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;

        // Resolve the lookup against the arena only. A present row takes its
        // handle; a missing row in a present table takes the table's end iterator;
        // a missing table is -1 — matching chainbase's db_find_i64 (which caches
        // the table's end iterator before the lookup).
        let h = if !self.db.arena_kv_table_exists(code, scope, table) {
            -1
        } else if self.db.arena_kv_get(code, scope, table, id).is_some() {
            inner.arena_keyval_cache.add((code, scope, table, id))
        } else {
            inner.arena_keyval_cache.cache_table((code, scope, table))
        };
        Ok(h)
    }

    pub fn db_store_i64(
        &mut self,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        data: Bytes,
    ) -> Result<i32, ChainError> {
        pulse_assert(
            payer != 0,
            ChainError::TransactionError(format!(
                "must specify a valid account to pay for new record"
            )),
        )?;

        // Table existence, creation, the row insert and the RAM billing all
        // resolve against the arena. The contract receives the arena's iterator
        // handle. This is the find_or_create_table + create_key_value_object path
        // with no chainbase TableObject pointer in the middle.
        let code = self.receiver.as_u64();
        // find_or_create_table: bill the new table before the row, only when the
        // table did not already exist.
        if !self.db.arena_table_exists(code, scope, table) {
            self.update_db_usage(&payer.into(), billable_size_v::<TableObject>() as i64)?;
        }
        self.db.create_key_value_object_standalone(
            code,
            scope,
            table,
            payer,
            primary_key,
            data.0.as_slice(),
        )?;
        let res = {
            let mut inner = self.inner.write()?;
            inner.arena_keyval_cache.cache_table((code, scope, table));
            inner
                .arena_keyval_cache
                .add((code, scope, table, primary_key))
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

        // The handle is the arena's; resolve the row's key and old (payer, value)
        // from the arena and rewrite it there alone. The RAM delta is authored
        // entirely from arena state.
        let (old_size, old_payer, new_payer) = {
            let inner = self.inner.read()?;
            let (code, scope, table, primary) = inner
                .arena_keyval_cache
                .row_of(iterator)
                .ok_or_else(|| ChainError::InternalError(format!("invalid iterator {iterator}")))?;
            pulse_assert(
                code == self.receiver.as_u64(),
                ChainError::TransactionError(format!("db access violation")),
            )?;
            let (row_payer, value) = self
                .db
                .arena_kv_row(code, scope, table, primary)
                .ok_or_else(|| {
                    ChainError::InternalError(format!("arena has no row for iterator {iterator}"))
                })?;
            let new_payer = if payer == 0 { row_payer } else { payer };
            let old_size = value.len() as i64;
            self.db.update_key_value_object_standalone(
                code,
                scope,
                table,
                primary,
                new_payer,
                data.as_ref(),
            )?;
            (old_size, row_payer, new_payer)
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

        // Resolve the value entirely from the arena. The arena mints the same
        // iterator handles chainbase did, so the contract's handle resolves
        // directly against the arena cache.
        let (code, scope, table, primary) = inner
            .arena_keyval_cache
            .row_of(iterator)
            .ok_or_else(|| ChainError::InternalError(format!("invalid iterator {iterator}")))?;
        let value = self
            .db
            .arena_kv_get(code, scope, table, primary)
            .ok_or_else(|| {
                ChainError::InternalError(format!("arena has no row for iterator {iterator}"))
            })?;
        let s = value.len();
        if buffer_size == 0 {
            return Ok(s as i32);
        }
        let copy_size = core::cmp::min(buffer_size, s);
        if buffer.len() < copy_size {
            buffer.resize(copy_size, 0);
        }
        buffer[..copy_size].copy_from_slice(&value[..copy_size]);
        Ok(copy_size as i32)
    }

    /// Refund the table_id_object overhead to the table's payer when a remove has
    /// just emptied the table, matching chainbase's `remove_table`. `table_payer`
    /// is sampled before the remove, since emptying deletes the table_id row. A
    /// no-op while the table still has children — the `count` a table tracks spans
    /// its primary and every secondary row, so any of the six remove paths can be
    /// the one that empties it.
    fn refund_table_if_emptied(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        table_payer: u64,
    ) -> Result<(), ChainError> {
        if !self.db.arena_table_exists(code, scope, table) {
            self.update_db_usage(
                &Name::new(table_payer),
                -(billable_size_v::<TableObject>() as i64),
            )?;
        }
        Ok(())
    }

    pub fn db_remove_i64(&mut self, iterator: i32) -> Result<(), ChainError> {
        // Resolve the row's key and value from the arena, remove it there alone
        // (which auto-removes the table when it empties, as chainbase did), and
        // reclaim the same RAM. The delta matches the C++ db_remove_i64:
        // -(value + key_value_object overhead).
        let (delta, payer, code, scope, table, table_payer) = {
            let mut inner = self.inner.write()?;
            let (code, scope, table, primary) = inner
                .arena_keyval_cache
                .row_of(iterator)
                .ok_or_else(|| ChainError::InternalError(format!("invalid iterator {iterator}")))?;
            pulse_assert(
                code == self.receiver.as_u64(),
                ChainError::TransactionError(format!("db access violation")),
            )?;
            let (payer, value) = self
                .db
                .arena_kv_row(code, scope, table, primary)
                .ok_or_else(|| {
                    ChainError::InternalError(format!("arena has no row for iterator {iterator}"))
                })?;
            let table_payer = self
                .db
                .arena_table_payer(code, scope, table)
                .unwrap_or(payer);
            let delta = -(value.len() as i64 + billable_size_v::<KeyValueObject>() as i64);
            self.db
                .remove_key_value_object_standalone(code, scope, table, primary)?;
            inner.arena_keyval_cache.remove(iterator);
            (delta, payer, code, scope, table, table_payer)
        };
        // Refund the row's stored payer (matching EOSIO's db_remove_i64, which
        // credits obj.payer). `delta` is already negative, so pass it straight
        // through — negating it here would bill the payer for freeing the row.
        self.update_db_usage(&Name::new(payer), delta)?;
        self.refund_table_if_emptied(code, scope, table, table_payer)?;
        Ok(())
    }

    pub fn db_next_i64(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;

        // Advance to the successor via the arena's upper_bound of the current key;
        // no successor lands on the table's end iterator.
        if let Some((code, scope, table, cur_pk)) = inner.arena_keyval_cache.row_of(iterator) {
            return Ok(
                match self.db.arena_kv_upper_bound(code, scope, table, cur_pk) {
                    Some(pk) => {
                        *primary = pk;
                        inner.arena_keyval_cache.add((code, scope, table, pk))
                    }
                    None => inner.arena_keyval_cache.cache_table((code, scope, table)),
                },
            );
        }
        // db_next from an end iterator has no successor: stay put.
        Ok(iterator)
    }

    pub fn db_previous_i64(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;

        // From a live row, step to its arena predecessor; from an end iterator, to
        // the table's last row. No predecessor returns -1 (db_previous never lands
        // on an end iterator).
        let landing = match inner.arena_keyval_cache.row_of(iterator) {
            Some((code, scope, table, cur_pk)) => Some((
                code,
                scope,
                table,
                self.db.arena_kv_prev(code, scope, table, cur_pk),
            )),
            None => inner
                .arena_keyval_cache
                .table_of_end(iterator)
                .map(|(code, scope, table)| {
                    (
                        code,
                        scope,
                        table,
                        self.db.arena_kv_last(code, scope, table),
                    )
                }),
        };
        let Some((code, scope, table, prev)) = landing else {
            return Ok(-1);
        };
        Ok(match prev {
            Some(pk) => {
                *primary = pk;
                inner.arena_keyval_cache.add((code, scope, table, pk))
            }
            None => -1,
        })
    }

    pub fn db_end_i64(&mut self, code: u64, scope: u64, table: u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;

        // A present table has an end iterator, an absent one is -1.
        Ok(if self.db.arena_kv_table_exists(code, scope, table) {
            inner.arena_keyval_cache.cache_table((code, scope, table))
        } else {
            -1
        })
    }

    pub fn db_lowerbound_i64(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;

        // Smallest primary >= key from the arena; none lands on the end iterator;
        // an absent table is -1.
        if !self.db.arena_kv_table_exists(code, scope, table) {
            return Ok(-1);
        }
        Ok(
            match self.db.arena_kv_lower_bound(code, scope, table, primary) {
                Some(pk) => inner.arena_keyval_cache.add((code, scope, table, pk)),
                None => inner.arena_keyval_cache.cache_table((code, scope, table)),
            },
        )
    }

    pub fn db_upperbound_i64(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;

        // Smallest primary > key from the arena; none lands on the end iterator;
        // an absent table is -1.
        if !self.db.arena_kv_table_exists(code, scope, table) {
            return Ok(-1);
        }
        Ok(
            match self.db.arena_kv_upper_bound(code, scope, table, primary) {
                Some(pk) => inner.arena_keyval_cache.add((code, scope, table, pk)),
                None => inner.arena_keyval_cache.cache_table((code, scope, table)),
            },
        )
    }

    pub fn db_idx64_store(
        &mut self,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: u64,
    ) -> Result<i32, ChainError> {
        pulse_assert(
            payer != 0,
            ChainError::TransactionError(format!(
                "must specify a valid account to pay for new record"
            )),
        )?;
        // Author the table (billing it if new) and the index row in the arena
        // alone, no chainbase IndexObject pointer.
        let code = self.receiver.as_u64();
        if !self.db.arena_table_exists(code, scope, table) {
            self.update_db_usage(&payer.into(), billable_size_v::<TableObject>() as i64)?;
        }
        self.db.create_index64_object_standalone(
            code,
            scope,
            table,
            payer,
            primary_key,
            secondary_key,
        )?;
        let res = {
            let mut inner = self.inner.write()?;
            inner.arena_index64_cache.cache_table((code, scope, table));
            inner
                .arena_index64_cache
                .add((code, scope, table, primary_key))
        };
        self.update_db_usage(&payer.into(), billable_size_v::<Index64Object>() as i64)?;
        Ok(res)
    }

    pub fn db_idx64_update(
        &mut self,
        iterator: i32,
        payer: &Name,
        secondary: u64,
    ) -> Result<(), ChainError> {
        let payer = payer.as_u64();
        let billing_size = billable_size_v::<Index64Object>() as i64;

        // Resolve the row and old payer from the arena and re-point it there alone.
        let (old_payer, new_payer) = {
            let inner = self.inner.read()?;
            let (code, scope, table, primary) = inner
                .arena_index64_cache
                .row_of(iterator)
                .ok_or_else(|| ChainError::InternalError(format!("invalid iterator {iterator}")))?;
            pulse_assert(
                code == self.receiver.as_u64(),
                ChainError::TransactionError(format!("db access violation")),
            )?;
            let old_payer = self
                .db
                .arena_idx64_payer(code, scope, table, primary)
                .ok_or_else(|| {
                    ChainError::InternalError(format!("arena has no idx64 row for {iterator}"))
                })?;
            let new_payer = if payer == 0 { old_payer } else { payer };
            self.db.update_index64_object_standalone(
                code, scope, table, primary, new_payer, secondary,
            )?;
            (old_payer, new_payer)
        };
        if old_payer != new_payer {
            self.update_db_usage(&Name::new(old_payer), -billing_size)?;
            self.update_db_usage(&Name::new(new_payer), billing_size)?;
        }
        Ok(())
    }

    pub fn db_idx64_remove(&mut self, iterator: i32) -> Result<(), ChainError> {
        // Refund the secondary row's stored payer (matching EOSIO and the
        // idxN_update billing), not self.receiver.
        let (payer, code, scope, table, table_payer) = {
            let mut inner = self.inner.write()?;
            let (code, scope, table, primary) = inner
                .arena_index64_cache
                .row_of(iterator)
                .ok_or_else(|| ChainError::InternalError(format!("invalid iterator {iterator}")))?;
            pulse_assert(
                code == self.receiver.as_u64(),
                ChainError::TransactionError(format!("db access violation")),
            )?;
            let payer = self
                .db
                .arena_idx64_payer(code, scope, table, primary)
                .unwrap_or(self.receiver.as_u64());
            let table_payer = self
                .db
                .arena_table_payer(code, scope, table)
                .unwrap_or(payer);
            self.db
                .remove_index64_object_standalone(code, scope, table, primary)?;
            inner.arena_index64_cache.remove(iterator);
            (payer, code, scope, table, table_payer)
        };
        self.update_db_usage(
            &Name::new(payer),
            -(billable_size_v::<Index64Object>() as i64),
        )?;
        self.refund_table_if_emptied(code, scope, table, table_payer)?;
        Ok(())
    }

    pub fn db_idx64_find_secondary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx64_find_secondary(code, scope, table, secondary);
        let res = match arena {
            Some(p) => {
                *primary = p;
                inner.arena_index64_cache.cache_table((code, scope, table));
                inner.arena_index64_cache.add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => {
                inner.arena_index64_cache.cache_table((code, scope, table))
            }
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx64_find_primary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx64_find_primary(code, scope, table, primary);
        let res = match arena {
            Some(s) => {
                *secondary = s;
                inner.arena_index64_cache.cache_table((code, scope, table));
                inner.arena_index64_cache.add((code, scope, table, primary))
            }
            None if self.db.arena_table_exists(code, scope, table) => {
                inner.arena_index64_cache.cache_table((code, scope, table))
            }
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx64_lowerbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        // `secondary` is the search key on the way in and the landing key on the
        // way out, so capture it before the FFI overwrites it.
        let search = *secondary;
        let mut inner = self.inner.write()?;
        let arena = self.db.arena_idx64_lower_bound(code, scope, table, search);
        let res = match arena {
            Some((p, s)) => {
                *primary = p;
                *secondary = s;
                inner.arena_index64_cache.cache_table((code, scope, table));
                inner.arena_index64_cache.add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => {
                inner.arena_index64_cache.cache_table((code, scope, table))
            }
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx64_upperbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let search = *secondary;
        let mut inner = self.inner.write()?;
        let arena = self.db.arena_idx64_upper_bound(code, scope, table, search);
        let res = match arena {
            Some((p, s)) => {
                *primary = p;
                *secondary = s;
                inner.arena_index64_cache.cache_table((code, scope, table));
                inner.arena_index64_cache.add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => {
                inner.arena_index64_cache.cache_table((code, scope, table))
            }
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx64_end(&mut self, code: u64, scope: u64, table: u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        // The end iterator equals the table's cached end handle, or -1 when the
        // table is absent.
        let res = if self.db.arena_table_exists(code, scope, table) {
            inner.arena_index64_cache.cache_table((code, scope, table))
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx64_next(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        // Advance in secondary order: past-the-end stays -1, a successor in the
        // same table adds its row handle, and falling off the end lands on the
        // table's end iterator.
        let res = if iterator < -1 {
            -1
        } else if let Some((code, scope, table, cur)) = inner.arena_index64_cache.row_of(iterator) {
            match self.db.arena_idx64_next(code, scope, table, cur) {
                Some((np, _)) => {
                    *primary = np;
                    inner.arena_index64_cache.add((code, scope, table, np))
                }
                None => inner.arena_index64_cache.cache_table((code, scope, table)),
            }
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx64_previous(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        // Retreat in secondary order: from an end iterator, land on the table's
        // last row (or -1 if empty); from a live row, land on its predecessor (or
        // -1 at the beginning).
        let res = if let Some((code, scope, table)) =
            inner.arena_index64_cache.table_of_end(iterator)
        {
            match self.db.arena_idx64_last(code, scope, table) {
                Some((lp, _)) => {
                    *primary = lp;
                    inner.arena_index64_cache.add((code, scope, table, lp))
                }
                None => -1,
            }
        } else if let Some((code, scope, table, cur)) = inner.arena_index64_cache.row_of(iterator) {
            match self.db.arena_idx64_previous(code, scope, table, cur) {
                Some((pp, _)) => {
                    *primary = pp;
                    inner.arena_index64_cache.add((code, scope, table, pp))
                }
                None => -1,
            }
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx128_store(
        &mut self,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: u128,
    ) -> Result<i32, ChainError> {
        pulse_assert(
            payer != 0,
            ChainError::TransactionError(format!(
                "must specify a valid account to pay for new record"
            )),
        )?;
        let code = self.receiver.as_u64();
        if !self.db.arena_table_exists(code, scope, table) {
            self.update_db_usage(&payer.into(), billable_size_v::<TableObject>() as i64)?;
        }
        self.db.create_index128_object_standalone(
            code,
            scope,
            table,
            payer,
            primary_key,
            secondary_key,
        )?;
        let res = {
            let mut inner = self.inner.write()?;
            inner.arena_index128_cache.cache_table((code, scope, table));
            inner
                .arena_index128_cache
                .add((code, scope, table, primary_key))
        };
        self.update_db_usage(&payer.into(), billable_size_v::<Index128Object>() as i64)?;
        Ok(res)
    }

    pub fn db_idx128_update(
        &mut self,
        iterator: i32,
        payer: &Name,
        secondary: u128,
    ) -> Result<(), ChainError> {
        let payer = payer.as_u64();
        let billing_size = billable_size_v::<Index128Object>() as i64;

        let (old_payer, new_payer) = {
            let inner = self.inner.read()?;
            let (code, scope, table, primary) = inner
                .arena_index128_cache
                .row_of(iterator)
                .ok_or_else(|| ChainError::InternalError(format!("invalid iterator {iterator}")))?;
            pulse_assert(
                code == self.receiver.as_u64(),
                ChainError::TransactionError(format!("db access violation")),
            )?;
            let old_payer = self
                .db
                .arena_idx128_payer(code, scope, table, primary)
                .ok_or_else(|| {
                    ChainError::InternalError(format!("arena has no idx128 row for {iterator}"))
                })?;
            let new_payer = if payer == 0 { old_payer } else { payer };
            self.db.update_index128_object_standalone(
                code, scope, table, primary, new_payer, secondary,
            )?;
            (old_payer, new_payer)
        };
        if old_payer != new_payer {
            self.update_db_usage(&Name::new(old_payer), -billing_size)?;
            self.update_db_usage(&Name::new(new_payer), billing_size)?;
        }
        Ok(())
    }

    pub fn db_idx128_remove(&mut self, iterator: i32) -> Result<(), ChainError> {
        // Refund the secondary row's stored payer, not self.receiver.
        let (payer, code, scope, table, table_payer) = {
            let mut inner = self.inner.write()?;
            let (code, scope, table, primary) = inner
                .arena_index128_cache
                .row_of(iterator)
                .ok_or_else(|| ChainError::InternalError(format!("invalid iterator {iterator}")))?;
            pulse_assert(
                code == self.receiver.as_u64(),
                ChainError::TransactionError(format!("db access violation")),
            )?;
            let payer = self
                .db
                .arena_idx128_payer(code, scope, table, primary)
                .unwrap_or(self.receiver.as_u64());
            let table_payer = self
                .db
                .arena_table_payer(code, scope, table)
                .unwrap_or(payer);
            self.db
                .remove_index128_object_standalone(code, scope, table, primary)?;
            inner.arena_index128_cache.remove(iterator);
            (payer, code, scope, table, table_payer)
        };
        self.update_db_usage(
            &Name::new(payer),
            -(billable_size_v::<Index128Object>() as i64),
        )?;
        self.refund_table_if_emptied(code, scope, table, table_payer)?;
        Ok(())
    }

    pub fn db_idx128_find_secondary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx128_find_secondary(code, scope, table, secondary);
        let res = match arena {
            Some(p) => {
                *primary = p;
                inner.arena_index128_cache.cache_table((code, scope, table));
                inner.arena_index128_cache.add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => {
                inner.arena_index128_cache.cache_table((code, scope, table))
            }
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx128_find_primary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u128,
        primary: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx128_find_primary(code, scope, table, primary);
        let res = match arena {
            Some(s) => {
                *secondary = s;
                inner.arena_index128_cache.cache_table((code, scope, table));
                inner
                    .arena_index128_cache
                    .add((code, scope, table, primary))
            }
            None if self.db.arena_table_exists(code, scope, table) => {
                inner.arena_index128_cache.cache_table((code, scope, table))
            }
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx128_lowerbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let search = *secondary;
        let mut inner = self.inner.write()?;
        let arena = self.db.arena_idx128_lower_bound(code, scope, table, search);
        let res = match arena {
            Some((p, s)) => {
                *primary = p;
                *secondary = s;
                inner.arena_index128_cache.cache_table((code, scope, table));
                inner.arena_index128_cache.add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => {
                inner.arena_index128_cache.cache_table((code, scope, table))
            }
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx128_upperbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let search = *secondary;
        let mut inner = self.inner.write()?;
        let arena = self.db.arena_idx128_upper_bound(code, scope, table, search);
        let res = match arena {
            Some((p, s)) => {
                *primary = p;
                *secondary = s;
                inner.arena_index128_cache.cache_table((code, scope, table));
                inner.arena_index128_cache.add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => {
                inner.arena_index128_cache.cache_table((code, scope, table))
            }
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx128_end(&mut self, code: u64, scope: u64, table: u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = if self.db.arena_table_exists(code, scope, table) {
            inner.arena_index128_cache.cache_table((code, scope, table))
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx128_next(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = if iterator < -1 {
            -1
        } else if let Some((code, scope, table, cur)) = inner.arena_index128_cache.row_of(iterator)
        {
            match self.db.arena_idx128_next(code, scope, table, cur) {
                Some(np) => {
                    *primary = np;
                    inner.arena_index128_cache.add((code, scope, table, np))
                }
                None => inner.arena_index128_cache.cache_table((code, scope, table)),
            }
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx128_previous(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = if let Some((code, scope, table)) =
            inner.arena_index128_cache.table_of_end(iterator)
        {
            match self.db.arena_idx128_last(code, scope, table) {
                Some(lp) => {
                    *primary = lp;
                    inner.arena_index128_cache.add((code, scope, table, lp))
                }
                None => -1,
            }
        } else if let Some((code, scope, table, cur)) = inner.arena_index128_cache.row_of(iterator)
        {
            match self.db.arena_idx128_previous(code, scope, table, cur) {
                Some(pp) => {
                    *primary = pp;
                    inner.arena_index128_cache.add((code, scope, table, pp))
                }
                None => -1,
            }
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx256_store(
        &mut self,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: U256,
    ) -> Result<i32, ChainError> {
        pulse_assert(
            payer != 0,
            ChainError::TransactionError(format!(
                "must specify a valid account to pay for new record"
            )),
        )?;
        let code = self.receiver.as_u64();
        if !self.db.arena_table_exists(code, scope, table) {
            self.update_db_usage(&payer.into(), billable_size_v::<TableObject>() as i64)?;
        }
        self.db.create_index256_object_standalone(
            code,
            scope,
            table,
            payer,
            primary_key,
            secondary_key,
        )?;
        let res = {
            let mut inner = self.inner.write()?;
            inner.arena_index256_cache.cache_table((code, scope, table));
            inner
                .arena_index256_cache
                .add((code, scope, table, primary_key))
        };
        self.update_db_usage(&payer.into(), billable_size_v::<Index256Object>() as i64)?;
        Ok(res)
    }

    pub fn db_idx256_update(
        &mut self,
        iterator: i32,
        payer: &Name,
        secondary: U256,
    ) -> Result<(), ChainError> {
        let payer = payer.as_u64();
        let billing_size = billable_size_v::<Index256Object>() as i64;

        let (old_payer, new_payer) = {
            let inner = self.inner.read()?;
            let (code, scope, table, primary) = inner
                .arena_index256_cache
                .row_of(iterator)
                .ok_or_else(|| ChainError::InternalError(format!("invalid iterator {iterator}")))?;
            pulse_assert(
                code == self.receiver.as_u64(),
                ChainError::TransactionError(format!("db access violation")),
            )?;
            let old_payer = self
                .db
                .arena_idx256_payer(code, scope, table, primary)
                .ok_or_else(|| {
                    ChainError::InternalError(format!("arena has no idx256 row for {iterator}"))
                })?;
            let new_payer = if payer == 0 { old_payer } else { payer };
            self.db.update_index256_object_standalone(
                code, scope, table, primary, new_payer, secondary,
            )?;
            (old_payer, new_payer)
        };
        if old_payer != new_payer {
            self.update_db_usage(&Name::new(old_payer), -billing_size)?;
            self.update_db_usage(&Name::new(new_payer), billing_size)?;
        }
        Ok(())
    }

    pub fn db_idx256_remove(&mut self, iterator: i32) -> Result<(), ChainError> {
        // Refund the secondary row's stored payer, not self.receiver.
        let (payer, code, scope, table, table_payer) = {
            let mut inner = self.inner.write()?;
            let (code, scope, table, primary) = inner
                .arena_index256_cache
                .row_of(iterator)
                .ok_or_else(|| ChainError::InternalError(format!("invalid iterator {iterator}")))?;
            pulse_assert(
                code == self.receiver.as_u64(),
                ChainError::TransactionError(format!("db access violation")),
            )?;
            let payer = self
                .db
                .arena_idx256_payer(code, scope, table, primary)
                .unwrap_or(self.receiver.as_u64());
            let table_payer = self
                .db
                .arena_table_payer(code, scope, table)
                .unwrap_or(payer);
            self.db
                .remove_index256_object_standalone(code, scope, table, primary)?;
            inner.arena_index256_cache.remove(iterator);
            (payer, code, scope, table, table_payer)
        };
        self.update_db_usage(
            &Name::new(payer),
            -(billable_size_v::<Index256Object>() as i64),
        )?;
        self.refund_table_if_emptied(code, scope, table, table_payer)?;
        Ok(())
    }

    pub fn db_idx256_find_secondary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: U256,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let search = secondary.value;
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx256_find_secondary(code, scope, table, search);
        let res = match arena {
            Some(p) => {
                *primary = p;
                inner.arena_index256_cache.cache_table((code, scope, table));
                inner.arena_index256_cache.add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => {
                inner.arena_index256_cache.cache_table((code, scope, table))
            }
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx256_find_primary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut U256,
        primary: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx256_find_primary(code, scope, table, primary);
        let res = match arena {
            Some(b) => {
                secondary.value = b;
                inner.arena_index256_cache.cache_table((code, scope, table));
                inner
                    .arena_index256_cache
                    .add((code, scope, table, primary))
            }
            None if self.db.arena_table_exists(code, scope, table) => {
                inner.arena_index256_cache.cache_table((code, scope, table))
            }
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx256_lowerbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut U256,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let search = secondary.value;
        let mut inner = self.inner.write()?;
        let arena = self.db.arena_idx256_lower_bound(code, scope, table, search);
        let res = match arena {
            Some((p, b)) => {
                *primary = p;
                secondary.value = b;
                inner.arena_index256_cache.cache_table((code, scope, table));
                inner.arena_index256_cache.add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => {
                inner.arena_index256_cache.cache_table((code, scope, table))
            }
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx256_upperbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut U256,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let search = secondary.value;
        let mut inner = self.inner.write()?;
        let arena = self.db.arena_idx256_upper_bound(code, scope, table, search);
        let res = match arena {
            Some((p, b)) => {
                *primary = p;
                secondary.value = b;
                inner.arena_index256_cache.cache_table((code, scope, table));
                inner.arena_index256_cache.add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => {
                inner.arena_index256_cache.cache_table((code, scope, table))
            }
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx256_end(&mut self, code: u64, scope: u64, table: u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = if self.db.arena_table_exists(code, scope, table) {
            inner.arena_index256_cache.cache_table((code, scope, table))
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx256_next(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = if iterator < -1 {
            -1
        } else if let Some((code, scope, table, cur)) = inner.arena_index256_cache.row_of(iterator)
        {
            match self.db.arena_idx256_next(code, scope, table, cur) {
                Some(np) => {
                    *primary = np;
                    inner.arena_index256_cache.add((code, scope, table, np))
                }
                None => inner.arena_index256_cache.cache_table((code, scope, table)),
            }
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx256_previous(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = if let Some((code, scope, table)) =
            inner.arena_index256_cache.table_of_end(iterator)
        {
            match self.db.arena_idx256_last(code, scope, table) {
                Some(lp) => {
                    *primary = lp;
                    inner.arena_index256_cache.add((code, scope, table, lp))
                }
                None => -1,
            }
        } else if let Some((code, scope, table, cur)) = inner.arena_index256_cache.row_of(iterator)
        {
            match self.db.arena_idx256_previous(code, scope, table, cur) {
                Some(pp) => {
                    *primary = pp;
                    inner.arena_index256_cache.add((code, scope, table, pp))
                }
                None => -1,
            }
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx_double_store(
        &mut self,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: u64,
    ) -> Result<i32, ChainError> {
        pulse_assert(
            payer != 0,
            ChainError::TransactionError(format!(
                "must specify a valid account to pay for new record"
            )),
        )?;
        let code = self.receiver.as_u64();
        if !self.db.arena_table_exists(code, scope, table) {
            self.update_db_usage(&payer.into(), billable_size_v::<TableObject>() as i64)?;
        }
        self.db.create_idx_double_object_standalone(
            code,
            scope,
            table,
            payer,
            primary_key,
            secondary_key,
        )?;
        let res = {
            let mut inner = self.inner.write()?;
            inner
                .arena_index_double_cache
                .cache_table((code, scope, table));
            inner
                .arena_index_double_cache
                .add((code, scope, table, primary_key))
        };
        self.update_db_usage(&payer.into(), billable_size_v::<IndexDoubleObject>() as i64)?;
        Ok(res)
    }

    pub fn db_idx_double_update(
        &mut self,
        iterator: i32,
        payer: &Name,
        secondary: u64,
    ) -> Result<(), ChainError> {
        let payer = payer.as_u64();
        let billing_size = billable_size_v::<IndexDoubleObject>() as i64;

        let (old_payer, new_payer) = {
            let inner = self.inner.read()?;
            let (code, scope, table, primary) = inner
                .arena_index_double_cache
                .row_of(iterator)
                .ok_or_else(|| ChainError::InternalError(format!("invalid iterator {iterator}")))?;
            pulse_assert(
                code == self.receiver.as_u64(),
                ChainError::TransactionError(format!("db access violation")),
            )?;
            let old_payer = self
                .db
                .arena_idx_double_payer(code, scope, table, primary)
                .ok_or_else(|| {
                    ChainError::InternalError(format!("arena has no idx_double row for {iterator}"))
                })?;
            let new_payer = if payer == 0 { old_payer } else { payer };
            self.db.update_idx_double_object_standalone(
                code, scope, table, primary, new_payer, secondary,
            )?;
            (old_payer, new_payer)
        };
        if old_payer != new_payer {
            self.update_db_usage(&Name::new(old_payer), -billing_size)?;
            self.update_db_usage(&Name::new(new_payer), billing_size)?;
        }
        Ok(())
    }

    pub fn db_idx_double_remove(&mut self, iterator: i32) -> Result<(), ChainError> {
        // Refund the secondary row's stored payer, not self.receiver.
        let (payer, code, scope, table, table_payer) = {
            let mut inner = self.inner.write()?;
            let (code, scope, table, primary) = inner
                .arena_index_double_cache
                .row_of(iterator)
                .ok_or_else(|| ChainError::InternalError(format!("invalid iterator {iterator}")))?;
            pulse_assert(
                code == self.receiver.as_u64(),
                ChainError::TransactionError(format!("db access violation")),
            )?;
            let payer = self
                .db
                .arena_idx_double_payer(code, scope, table, primary)
                .unwrap_or(self.receiver.as_u64());
            let table_payer = self
                .db
                .arena_table_payer(code, scope, table)
                .unwrap_or(payer);
            self.db
                .remove_idx_double_object_standalone(code, scope, table, primary)?;
            inner.arena_index_double_cache.remove(iterator);
            (payer, code, scope, table, table_payer)
        };
        self.update_db_usage(
            &Name::new(payer),
            -(billable_size_v::<IndexDoubleObject>() as i64),
        )?;
        self.refund_table_if_emptied(code, scope, table, table_payer)?;
        Ok(())
    }

    pub fn db_idx_double_find_secondary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx_double_find_secondary(code, scope, table, secondary);
        let res = match arena {
            Some(p) => {
                *primary = p;
                inner
                    .arena_index_double_cache
                    .cache_table((code, scope, table));
                inner.arena_index_double_cache.add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => inner
                .arena_index_double_cache
                .cache_table((code, scope, table)),
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx_double_find_primary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx_double_find_primary(code, scope, table, primary);
        let res = match arena {
            Some(s) => {
                *secondary = s;
                inner
                    .arena_index_double_cache
                    .cache_table((code, scope, table));
                inner
                    .arena_index_double_cache
                    .add((code, scope, table, primary))
            }
            None if self.db.arena_table_exists(code, scope, table) => inner
                .arena_index_double_cache
                .cache_table((code, scope, table)),
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx_double_lowerbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let search = *secondary;
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx_double_lower_bound(code, scope, table, search);
        let res = match arena {
            Some((p, s)) => {
                *primary = p;
                *secondary = s;
                inner
                    .arena_index_double_cache
                    .cache_table((code, scope, table));
                inner.arena_index_double_cache.add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => inner
                .arena_index_double_cache
                .cache_table((code, scope, table)),
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx_double_upperbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let search = *secondary;
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx_double_upper_bound(code, scope, table, search);
        let res = match arena {
            Some((p, s)) => {
                *primary = p;
                *secondary = s;
                inner
                    .arena_index_double_cache
                    .cache_table((code, scope, table));
                inner.arena_index_double_cache.add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => inner
                .arena_index_double_cache
                .cache_table((code, scope, table)),
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx_double_end(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = if self.db.arena_table_exists(code, scope, table) {
            inner
                .arena_index_double_cache
                .cache_table((code, scope, table))
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx_double_next(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = if iterator < -1 {
            -1
        } else if let Some((code, scope, table, cur)) =
            inner.arena_index_double_cache.row_of(iterator)
        {
            match self.db.arena_idx_double_next(code, scope, table, cur) {
                Some(np) => {
                    *primary = np;
                    inner.arena_index_double_cache.add((code, scope, table, np))
                }
                None => inner
                    .arena_index_double_cache
                    .cache_table((code, scope, table)),
            }
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx_double_previous(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = if let Some((code, scope, table)) =
            inner.arena_index_double_cache.table_of_end(iterator)
        {
            match self.db.arena_idx_double_last(code, scope, table) {
                Some(lp) => {
                    *primary = lp;
                    inner.arena_index_double_cache.add((code, scope, table, lp))
                }
                None => -1,
            }
        } else if let Some((code, scope, table, cur)) =
            inner.arena_index_double_cache.row_of(iterator)
        {
            match self.db.arena_idx_double_previous(code, scope, table, cur) {
                Some(pp) => {
                    *primary = pp;
                    inner.arena_index_double_cache.add((code, scope, table, pp))
                }
                None => -1,
            }
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx_long_double_store(
        &mut self,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: Float128,
    ) -> Result<i32, ChainError> {
        pulse_assert(
            payer != 0,
            ChainError::TransactionError(format!(
                "must specify a valid account to pay for new record"
            )),
        )?;
        let code = self.receiver.as_u64();
        if !self.db.arena_table_exists(code, scope, table) {
            self.update_db_usage(&payer.into(), billable_size_v::<TableObject>() as i64)?;
        }
        self.db.create_idx_long_double_object_standalone(
            code,
            scope,
            table,
            payer,
            primary_key,
            secondary_key,
        )?;
        let res = {
            let mut inner = self.inner.write()?;
            inner
                .arena_index_long_double_cache
                .cache_table((code, scope, table));
            inner
                .arena_index_long_double_cache
                .add((code, scope, table, primary_key))
        };
        self.update_db_usage(
            &payer.into(),
            billable_size_v::<IndexLongDoubleObject>() as i64,
        )?;
        Ok(res)
    }

    pub fn db_idx_long_double_update(
        &mut self,
        iterator: i32,
        payer: &Name,
        secondary: Float128,
    ) -> Result<(), ChainError> {
        let payer = payer.as_u64();
        let billing_size = billable_size_v::<IndexLongDoubleObject>() as i64;

        let (old_payer, new_payer) = {
            let inner = self.inner.read()?;
            let (code, scope, table, primary) = inner
                .arena_index_long_double_cache
                .row_of(iterator)
                .ok_or_else(|| ChainError::InternalError(format!("invalid iterator {iterator}")))?;
            pulse_assert(
                code == self.receiver.as_u64(),
                ChainError::TransactionError(format!("db access violation")),
            )?;
            let old_payer = self
                .db
                .arena_idx_long_double_payer(code, scope, table, primary)
                .ok_or_else(|| {
                    ChainError::InternalError(format!(
                        "arena has no idx_long_double row for {iterator}"
                    ))
                })?;
            let new_payer = if payer == 0 { old_payer } else { payer };
            self.db.update_idx_long_double_object_standalone(
                code, scope, table, primary, new_payer, secondary,
            )?;
            (old_payer, new_payer)
        };
        if old_payer != new_payer {
            self.update_db_usage(&Name::new(old_payer), -billing_size)?;
            self.update_db_usage(&Name::new(new_payer), billing_size)?;
        }
        Ok(())
    }

    pub fn db_idx_long_double_remove(&mut self, iterator: i32) -> Result<(), ChainError> {
        // Refund the secondary row's stored payer, not self.receiver.
        let (payer, code, scope, table, table_payer) = {
            let mut inner = self.inner.write()?;
            let (code, scope, table, primary) = inner
                .arena_index_long_double_cache
                .row_of(iterator)
                .ok_or_else(|| ChainError::InternalError(format!("invalid iterator {iterator}")))?;
            pulse_assert(
                code == self.receiver.as_u64(),
                ChainError::TransactionError(format!("db access violation")),
            )?;
            let payer = self
                .db
                .arena_idx_long_double_payer(code, scope, table, primary)
                .unwrap_or(self.receiver.as_u64());
            let table_payer = self
                .db
                .arena_table_payer(code, scope, table)
                .unwrap_or(payer);
            self.db
                .remove_idx_long_double_object_standalone(code, scope, table, primary)?;
            inner.arena_index_long_double_cache.remove(iterator);
            (payer, code, scope, table, table_payer)
        };
        self.update_db_usage(
            &Name::new(payer),
            -(billable_size_v::<IndexLongDoubleObject>() as i64),
        )?;
        self.refund_table_if_emptied(code, scope, table, table_payer)?;
        Ok(())
    }

    pub fn db_idx_long_double_find_secondary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: Float128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let search = (secondary.lo, secondary.hi);
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx_long_double_find_secondary(code, scope, table, search);
        let res = match arena {
            Some(p) => {
                *primary = p;
                inner
                    .arena_index_long_double_cache
                    .cache_table((code, scope, table));
                inner
                    .arena_index_long_double_cache
                    .add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => inner
                .arena_index_long_double_cache
                .cache_table((code, scope, table)),
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx_long_double_find_primary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut Float128,
        primary: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx_long_double_find_primary(code, scope, table, primary);
        let res = match arena {
            Some((lo, hi)) => {
                secondary.lo = lo;
                secondary.hi = hi;
                inner
                    .arena_index_long_double_cache
                    .cache_table((code, scope, table));
                inner
                    .arena_index_long_double_cache
                    .add((code, scope, table, primary))
            }
            None if self.db.arena_table_exists(code, scope, table) => inner
                .arena_index_long_double_cache
                .cache_table((code, scope, table)),
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx_long_double_lowerbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut Float128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let search = (secondary.lo, secondary.hi);
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx_long_double_lower_bound(code, scope, table, search);
        let res = match arena {
            Some((p, (lo, hi))) => {
                *primary = p;
                secondary.lo = lo;
                secondary.hi = hi;
                inner
                    .arena_index_long_double_cache
                    .cache_table((code, scope, table));
                inner
                    .arena_index_long_double_cache
                    .add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => inner
                .arena_index_long_double_cache
                .cache_table((code, scope, table)),
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx_long_double_upperbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut Float128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let search = (secondary.lo, secondary.hi);
        let mut inner = self.inner.write()?;
        let arena = self
            .db
            .arena_idx_long_double_upper_bound(code, scope, table, search);
        let res = match arena {
            Some((p, (lo, hi))) => {
                *primary = p;
                secondary.lo = lo;
                secondary.hi = hi;
                inner
                    .arena_index_long_double_cache
                    .cache_table((code, scope, table));
                inner
                    .arena_index_long_double_cache
                    .add((code, scope, table, p))
            }
            None if self.db.arena_table_exists(code, scope, table) => inner
                .arena_index_long_double_cache
                .cache_table((code, scope, table)),
            None => -1,
        };
        Ok(res)
    }

    pub fn db_idx_long_double_end(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = if self.db.arena_table_exists(code, scope, table) {
            inner
                .arena_index_long_double_cache
                .cache_table((code, scope, table))
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx_long_double_next(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = if iterator < -1 {
            -1
        } else if let Some((code, scope, table, cur)) =
            inner.arena_index_long_double_cache.row_of(iterator)
        {
            match self.db.arena_idx_long_double_next(code, scope, table, cur) {
                Some(np) => {
                    *primary = np;
                    inner
                        .arena_index_long_double_cache
                        .add((code, scope, table, np))
                }
                None => inner
                    .arena_index_long_double_cache
                    .cache_table((code, scope, table)),
            }
        } else {
            -1
        };
        Ok(res)
    }

    pub fn db_idx_long_double_previous(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = if let Some((code, scope, table)) =
            inner.arena_index_long_double_cache.table_of_end(iterator)
        {
            match self.db.arena_idx_long_double_last(code, scope, table) {
                Some(lp) => {
                    *primary = lp;
                    inner
                        .arena_index_long_double_cache
                        .add((code, scope, table, lp))
                }
                None => -1,
            }
        } else if let Some((code, scope, table, cur)) =
            inner.arena_index_long_double_cache.row_of(iterator)
        {
            match self
                .db
                .arena_idx_long_double_previous(code, scope, table, cur)
            {
                Some(pp) => {
                    *primary = pp;
                    inner
                        .arena_index_long_double_cache
                        .add((code, scope, table, pp))
                }
                None => -1,
            }
        } else {
            -1
        };
        Ok(res)
    }

    pub fn update_db_usage(&mut self, payer: &Name, delta: i64) -> Result<(), ChainError> {
        if delta > 0 {
            // Do not allow charging RAM to other accounts during notify
            let privileged = {
                let inner = self.inner.read()?;
                inner.privileged
            };

            if !(privileged || *payer == self.receiver.as_u64()) {
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

    pub fn set_trace_return_value(&self, value: Vec<u8>) -> Result<(), ChainError> {
        self.trx_context
            .modify_action_trace(self.action_ordinal, |trace| {
                trace.return_value = value;
            })
    }

    pub fn next_recv_sequence(&mut self, receiver: u64) -> Result<u64, ChainError> {
        self.db.next_recv_sequence(receiver)
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

    pub fn account_ram_deltas(&self) -> Result<BTreeMap<Name, i64>, ChainError> {
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

    pub fn checktime(&self) -> Result<(), ChainError> {
        self.trx_context.checktime()
    }

    pub fn get_head_block_num(&self) -> u32 {
        0 // TODO: Fix
    }

    pub fn get_pending_block_time(&self) -> &BlockTimestamp {
        &self.pending_block_timestamp
    }

    pub fn get_packed_transaction(&self) -> &PackedTransaction {
        self.trx_context.get_packed_transaction()
    }

    pub fn get_action(
        &self,
        type_id: u32,
        index: u32,
        buffer: &mut [u8],
        buffer_size: usize,
    ) -> Result<i32, ChainError> {
        let trx = self.trx_context.get_packed_transaction().get_transaction();

        let action: &Action = if type_id == 0 {
            match trx.context_free_actions.get(index as usize) {
                Some(a) => a,
                None => return Ok(-1),
            }
        } else if type_id == 1 {
            match trx.actions.get(index as usize) {
                Some(a) => a,
                None => return Ok(-1),
            }
        } else {
            return Err(ChainError::TransactionError(
                "get_action: invalid action type".to_string(),
            ));
        };

        let data = action.pack()?;
        let ps = data.len();

        // Only copy if the whole thing fits — matches EOSIO's `ps <= buffer_size`.
        // Clamp against the real slice length too, so the copy can never panic.
        let limit = buffer_size.min(buffer.len());
        if ps <= limit {
            buffer[..ps].copy_from_slice(&data);
        }

        Ok(ps as i32)
    }

    pub fn is_context_free(&self) -> bool {
        self.context_free
    }

    pub fn set_global_properties(&mut self, cfg: &ChainConfigV0) -> Result<(), ChainError> {
        self.db.set_global_properties(cfg)?;
        Ok(())
    }

    pub fn set_proposed_producers(
        &mut self,
        producers: Vec<ProducerKey>,
    ) -> Result<(), ChainError> {
        self.trx_context.set_proposed_producers(producers)
    }

    pub fn active_producers(&self) -> Result<Vec<ProducerKey>, ChainError> {
        self.trx_context.active_producers()
    }

    pub fn active_schedule_version(&self) -> Result<u32, ChainError> {
        self.trx_context.active_schedule_version()
    }

    pub fn validate_ram_usage(&self, account: &Name) -> Result<(), ChainError> {
        self.trx_context.validate_ram_usage(account)
    }
}

/// A pure-Rust twin of the chainbase `iterator_cache`, keyed on the logical row
/// identity `(code, scope, table, primary)` and table identity `(code, scope,
/// table)` instead of chainbase object pointers. Chainbase assigns a handle the
/// first time it sees an object and reuses it thereafter; because a live row has
/// exactly one object at a time, keying on its logical identity yields the same
/// handle assignment — non-negative indices for rows in first-seen order, and
/// `-(index + 2)` end iterators per table, matching
/// `index_to_end_iterator`/`end_iterator_to_index`. Driven in lockstep with the
/// chainbase cache so the arena can mint the identical handle for every
/// contract iterator; cross-checked against chainbase's answer at each mint.
#[derive(Default)]
struct ArenaIteratorCache {
    end_to_table: Vec<(u64, u64, u64)>,
    table_to_end: std::collections::HashMap<(u64, u64, u64), i32>,
    // `None` marks a slot whose row was removed — the index is never reused, so
    // a later re-insert of the same key takes a fresh handle, as in chainbase.
    iter_to_row: Vec<Option<(u64, u64, u64, u64)>>,
    row_to_iter: std::collections::HashMap<(u64, u64, u64, u64), i32>,
}

impl ArenaIteratorCache {
    /// End iterator for a table, minting one on first use.
    fn cache_table(&mut self, t: (u64, u64, u64)) -> i32 {
        if let Some(&ei) = self.table_to_end.get(&t) {
            return ei;
        }
        let ei = -(self.end_to_table.len() as i32 + 2);
        self.end_to_table.push(t);
        self.table_to_end.insert(t, ei);
        ei
    }

    /// Handle for a live row, minting one on first use (dedup on repeat).
    fn add(&mut self, row: (u64, u64, u64, u64)) -> i32 {
        if let Some(&h) = self.row_to_iter.get(&row) {
            return h;
        }
        let h = self.iter_to_row.len() as i32;
        self.iter_to_row.push(Some(row));
        self.row_to_iter.insert(row, h);
        h
    }

    /// The logical row a non-negative handle points at, or `None` for an end or
    /// removed iterator.
    fn row_of(&self, handle: i32) -> Option<(u64, u64, u64, u64)> {
        if handle < 0 {
            return None;
        }
        self.iter_to_row.get(handle as usize).copied().flatten()
    }

    /// The table an end iterator (`-(index + 2)`) belongs to, or `None` if the
    /// handle is not a minted end iterator. Mirrors
    /// `find_table_by_end_iterator`.
    fn table_of_end(&self, handle: i32) -> Option<(u64, u64, u64)> {
        if handle >= -1 {
            return None;
        }
        let idx = (-handle - 2) as usize;
        self.end_to_table.get(idx).copied()
    }

    /// Drop a row's handle (the slot stays as a tombstone so the index is never
    /// reused), matching chainbase's `remove`.
    fn remove(&mut self, handle: i32) {
        if handle < 0 {
            return;
        }
        if let Some(slot) = self.iter_to_row.get_mut(handle as usize)
            && let Some(row) = slot.take()
        {
            self.row_to_iter.remove(&row);
        }
    }
}
