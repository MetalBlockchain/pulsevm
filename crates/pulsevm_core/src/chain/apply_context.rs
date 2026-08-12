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
use pulsevm_error::ChainError;
use pulsevm_ffi::{
    BlockTimestamp,
    ChainConfigV0,
    CxxDigest,
    Database,
    Float128,
    Index64IteratorCache,
    Index64Object,
    Index128IteratorCache,
    Index128Object,
    Index256IteratorCache,
    Index256Object,
    IndexDoubleIteratorCache,
    IndexDoubleObject,
    IndexLongDoubleIteratorCache,
    IndexLongDoubleObject,
    KeyValueIteratorCache,
    KeyValueObject,
    Microseconds,
    TableObject,
    U256,
};
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
    keyval_cache: KeyValueIteratorCache,     // Cache for key-value iterators
    index64_cache: Index64IteratorCache,     // Cache for index64 iterators
    index128_cache: Index128IteratorCache,   // Cache for index128 iterators
    index256_cache: Index256IteratorCache,   // Cache for index256 iterators
    index_double_cache: IndexDoubleIteratorCache, // Cache for index double iterators
    index_long_double_cache: IndexLongDoubleIteratorCache, // Cache for index long double iterators
    // Arena twin of keyval_cache, driven in lockstep so the arena mints the same
    // key-value iterator handles chainbase does.
    #[cfg(feature = "arena-shadow")]
    arena_keyval_cache: ArenaIteratorCache,
    // Arena twin of index64_cache — chainbase keeps a separate iterator cache per
    // secondary-index type, so the arena mirrors each independently.
    #[cfg(feature = "arena-shadow")]
    arena_index64_cache: ArenaIteratorCache,
    #[cfg(feature = "arena-shadow")]
    arena_index128_cache: ArenaIteratorCache,
    #[cfg(feature = "arena-shadow")]
    arena_index256_cache: ArenaIteratorCache,
    #[cfg(feature = "arena-shadow")]
    arena_index_double_cache: ArenaIteratorCache,
    #[cfg(feature = "arena-shadow")]
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
                keyval_cache: KeyValueIteratorCache::new(),
                index64_cache: Index64IteratorCache::new(),
                index128_cache: Index128IteratorCache::new(),
                index256_cache: Index256IteratorCache::new(),
                index_double_cache: IndexDoubleIteratorCache::new(),
                index_long_double_cache: IndexLongDoubleIteratorCache::new(),
                #[cfg(feature = "arena-shadow")]
                arena_keyval_cache: ArenaIteratorCache::default(),
                #[cfg(feature = "arena-shadow")]
                arena_index64_cache: ArenaIteratorCache::default(),
                #[cfg(feature = "arena-shadow")]
                arena_index128_cache: ArenaIteratorCache::default(),
                #[cfg(feature = "arena-shadow")]
                arena_index256_cache: ArenaIteratorCache::default(),
                #[cfg(feature = "arena-shadow")]
                arena_index_double_cache: ArenaIteratorCache::default(),
                #[cfg(feature = "arena-shadow")]
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
            let r = self.db.read()?;
            let gpo = r.get_global_properties()?;

            pulse_assert(
                recurse_depth < gpo.get_chain_config().get_max_inline_action_depth() as u32,
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
            // The native handler runs unmetered Rust, so re-check the deadline now
            // that it's done. Only needed when one actually ran — with no native
            // handler, execute_action's entry check a few microseconds ago already
            // covers this action.
            self.trx_context.checktime()?;
        }

        // Copy the (possibly just-updated) code hash out as an owned value: the wasm
        // run re-locks the database, so no read guard or chainbase reference may be
        // held across it. Read after the native handler so a self-setcode is seen,
        // matching the previous live-reference behaviour.
        let code_hash = {
            let r = self.db.read()?;
            let meta = r.get_account_metadata(self.receiver.as_u64())?;
            CxxDigest::new_from_existing_hash(meta.get_code_hash().as_slice())?
        };

        // Does the receiver account have a contract deployed?
        if !code_hash.as_ref().map_or(true, |d| d.empty()) {
            let cpu_limit = {
                let inner = self.inner.read()?;
                inner.cpu_limit
            };

            cpu_used += self.wasm_runtime.run(
                self.receiver.clone(),
                action.clone(),
                self.clone(),
                self.db.clone(),
                code_hash.as_ref().unwrap(),
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

    /// Tally an arena iterator-handle cross-check (arena handle == chainbase's),
    /// logging the operation and table on a mismatch when `PULSEVM_DBG_ITER` is set.
    #[cfg(feature = "arena-shadow")]
    fn note_iter_handle(
        &self,
        op: &str,
        code: u64,
        scope: u64,
        table: u64,
        arena_h: i32,
        res: i32,
    ) {
        if arena_h != res && std::env::var("PULSEVM_DBG_ITER").is_ok() {
            eprintln!(
                "ITER MISMATCH {op} code={code} scope={scope} table={table} arena={arena_h} chain={res}"
            );
        }
        self.db.arena_note_pos(arena_h == res);
    }

    /// Mint the secondary-index iterator handle for a find/bound result and
    /// cross-check it against chainbase's `res`: `-1` when the table is absent,
    /// the landing row's handle on a hit, otherwise the table's end iterator —
    /// mirroring `cache_table` on every call then `add` on a hit, as the C++
    /// oracle does. `cache` is the arena twin of the chainbase iterator cache for
    /// this secondary-index type.
    #[cfg(feature = "arena-shadow")]
    fn note_secondary_handle(
        &self,
        cache: &mut ArenaIteratorCache,
        op: &str,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        res: i32,
    ) {
        let arena_h = if res == -1 {
            -1
        } else {
            let end = cache.cache_table((code, scope, table));
            if res >= 0 {
                cache.add((code, scope, table, primary))
            } else {
                end
            }
        };
        self.note_iter_handle(op, code, scope, table, arena_h, res);
    }

    pub fn db_find_i64(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        id: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;

        let res = self
            .db
            .db_find_i64(code, scope, table, id, &mut inner.keyval_cache)
            .map_err(|e| ChainError::DatabaseError(format!("failed to find i64 in db: {}", e)))?;

        // Mirror the handle into the arena cache: a found row adds its logical
        // key, a missing row (but present table) takes the table's end iterator,
        // and a missing table is -1 on both. The row/table existence itself is
        // cross-checked by the value reads; here we confirm the handle index.
        #[cfg(feature = "arena-shadow")]
        {
            // Chainbase caches the table (minting its end iterator) on every call
            // before looking up the row, so mirror that unconditionally, then add
            // the row on a hit.
            let arena_h = if res == -1 {
                -1
            } else {
                let end = inner.arena_keyval_cache.cache_table((code, scope, table));
                if res >= 0 {
                    inner.arena_keyval_cache.add((code, scope, table, id))
                } else {
                    end
                }
            };
            self.note_iter_handle("find", code, scope, table, arena_h, res);
        }

        Ok(res)
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
            let handle = inner.keyval_cache.add(obj)?;
            #[cfg(feature = "arena-shadow")]
            {
                let key = (
                    table.get_code().to_uint64_t(),
                    table.get_scope().to_uint64_t(),
                    table.get_table().to_uint64_t(),
                    primary_key,
                );
                inner.arena_keyval_cache.cache_table((key.0, key.1, key.2));
                let arena_handle = inner.arena_keyval_cache.add(key);
                self.note_iter_handle("store", key.0, key.1, key.2, arena_handle, handle);
            }
            handle
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

        // Inline read cross-check: the arena must serve this contract read — the
        // exact bytes at the exact key, at this point mid-execution (speculative,
        // pre-commit) — identically to chainbase. Stronger than the block-boundary
        // root diff, which only sees committed state. When the cutover switch is
        // on, the value the contract receives comes FROM the arena.
        #[cfg(feature = "arena-shadow")]
        let arena_value: Option<Vec<u8>> = {
            let table_obj = inner.keyval_cache.get_table(obj.get_table_id())?;
            let code = table_obj.get_code().to_uint64_t();
            let scope = table_obj.get_scope().to_uint64_t();
            let table = table_obj.get_table().to_uint64_t();
            let primary = obj.get_primary_key();
            self.db
                .arena_crosscheck_kv(code, scope, table, primary, obj.get_value().as_slice());
            if self.db.arena_reads_enabled() {
                self.db.arena_kv_get(code, scope, table, primary)
            } else {
                None
            }
        };

        let cb_value = obj.get_value();
        #[cfg(feature = "arena-shadow")]
        let source: &[u8] = arena_value
            .as_deref()
            .unwrap_or_else(|| cb_value.as_slice());
        #[cfg(not(feature = "arena-shadow"))]
        let source: &[u8] = cb_value.as_slice();

        let s = source.len();
        if buffer_size == 0 {
            return Ok(s as i32);
        }
        let copy_size = core::cmp::min(buffer_size, s);
        if buffer.len() < copy_size {
            buffer.resize(copy_size, 0);
        }
        buffer[..copy_size].copy_from_slice(&source[..copy_size]);
        Ok(copy_size as i32)
    }

    pub fn db_remove_i64(&mut self, iterator: i32) -> Result<(), ChainError> {
        let delta = {
            let mut inner = self.inner.write()?;
            let delta =
                self.db
                    .db_remove_i64(&mut inner.keyval_cache, iterator, self.receiver.as_u64())?;
            #[cfg(feature = "arena-shadow")]
            inner.arena_keyval_cache.remove(iterator);
            delta
        };

        self.update_db_usage(&Name::new(self.receiver.as_u64()), -delta)?;

        Ok(())
    }

    pub fn db_next_i64(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;

        // The cursor's current key, for the arena successor cross-check. `None`
        // if `iterator` is an end iterator (no backing row) — then we leave
        // chainbase's answer untouched.
        #[cfg(feature = "arena-shadow")]
        let cur = current_iter_key(&inner.keyval_cache, iterator);

        let res = self
            .db
            .db_next_i64(&mut inner.keyval_cache, iterator, primary)?;

        // db_next advances to the smallest primary > current: the arena's
        // upper_bound of the current key. res < 0 means chainbase hit the end,
        // so the arena must have no successor. Serve the arena's primary when
        // the cutover switch is on.
        #[cfg(feature = "arena-shadow")]
        if let Some((code, scope, table, cur_pk)) = cur {
            let arena_next = self.db.arena_kv_upper_bound(code, scope, table, cur_pk);
            let ffi_next = if res >= 0 { Some(*primary) } else { None };
            self.db.arena_note_pos(arena_next == ffi_next);

            // The handle db_next lands on: the successor row's, or the table's
            // end iterator when there is none.
            let arena_h = if res >= 0 {
                match arena_next {
                    Some(pk) => inner.arena_keyval_cache.add((code, scope, table, pk)),
                    None => res, // position check already flagged this divergence
                }
            } else {
                inner.arena_keyval_cache.cache_table((code, scope, table))
            };
            self.note_iter_handle("iter", code, scope, table, arena_h, res);

            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some(an) = arena_next
            {
                *primary = an;
            }
        }

        Ok(res)
    }

    pub fn db_previous_i64(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;

        // From a live row: predecessor = arena `prev` of its key. From an end
        // iterator (the db_end -> db_previous backward-iteration entry): the
        // table's last row = arena `kv_last`.
        #[cfg(feature = "arena-shadow")]
        let arena_ctx: Option<((u64, u64, u64), Option<u64>)> =
            match current_iter_key(&inner.keyval_cache, iterator) {
                Some((code, scope, table, cur_pk)) => Some((
                    (code, scope, table),
                    self.db.arena_kv_prev(code, scope, table, cur_pk),
                )),
                None => {
                    end_iter_table(&inner.keyval_cache, iterator).map(|(code, scope, table)| {
                        (
                            (code, scope, table),
                            self.db.arena_kv_last(code, scope, table),
                        )
                    })
                }
            };

        let res = self
            .db
            .db_previous_i64(&mut inner.keyval_cache, iterator, primary)?;

        #[cfg(feature = "arena-shadow")]
        if let Some(((code, scope, table), arena_prev)) = arena_ctx {
            let ffi_prev = if res >= 0 { Some(*primary) } else { None };
            self.db.arena_note_pos(arena_prev == ffi_prev);

            // db_previous lands on the predecessor row, or -1 when there is none
            // (it never returns an end iterator).
            let arena_h = if res >= 0 {
                match arena_prev {
                    Some(pk) => inner.arena_keyval_cache.add((code, scope, table, pk)),
                    None => res, // position check already flagged this divergence
                }
            } else {
                -1
            };
            self.note_iter_handle("iter", code, scope, table, arena_h, res);

            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some(ap) = arena_prev
            {
                *primary = ap;
            }
        }

        Ok(res)
    }

    pub fn db_end_i64(&mut self, code: u64, scope: u64, table: u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self
            .db
            .db_end_i64(&mut inner.keyval_cache, code, scope, table)?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if res == -1 {
                -1
            } else {
                inner.arena_keyval_cache.cache_table((code, scope, table))
            };
            self.note_iter_handle("iter", code, scope, table, arena_h, res);
        }

        Ok(res)
    }

    pub fn db_lowerbound_i64(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res =
            self.db
                .db_lowerbound_i64(&mut inner.keyval_cache, code, scope, table, primary)?;

        // Cross-check both the primary the iterator lands on and the handle
        // index the arena would mint for it.
        #[cfg(feature = "arena-shadow")]
        {
            let ffi_landing = landing_primary(&inner.keyval_cache, res);
            let arena_landing = self.db.arena_kv_lower_bound(code, scope, table, primary);
            self.db.arena_note_pos(ffi_landing == arena_landing);

            let arena_h = if res == -1 {
                -1
            } else {
                let end = inner.arena_keyval_cache.cache_table((code, scope, table));
                if res >= 0 {
                    match arena_landing {
                        Some(pk) => inner.arena_keyval_cache.add((code, scope, table, pk)),
                        None => res,
                    }
                } else {
                    end
                }
            };
            self.note_iter_handle("bound", code, scope, table, arena_h, res);
        }

        Ok(res)
    }

    pub fn db_upperbound_i64(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res =
            self.db
                .db_upperbound_i64(&mut inner.keyval_cache, code, scope, table, primary)?;

        #[cfg(feature = "arena-shadow")]
        {
            let ffi_landing = landing_primary(&inner.keyval_cache, res);
            let arena_landing = self.db.arena_kv_upper_bound(code, scope, table, primary);
            self.db.arena_note_pos(ffi_landing == arena_landing);

            let arena_h = if res == -1 {
                -1
            } else {
                let end = inner.arena_keyval_cache.cache_table((code, scope, table));
                if res >= 0 {
                    match arena_landing {
                        Some(pk) => inner.arena_keyval_cache.add((code, scope, table, pk)),
                        None => res,
                    }
                } else {
                    end
                }
            };
            self.note_iter_handle("bound", code, scope, table, arena_h, res);
        }

        Ok(res)
    }

    pub fn db_idx64_store(
        &mut self,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: u64,
    ) -> Result<i32, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let table_name = table;
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
            let obj = self
                .db
                .create_index64_object(table, payer, primary_key, secondary_key)?;
            let obj = unsafe { &*obj };
            inner.index64_cache.cache_table(&table)?;
            let handle = inner.index64_cache.add(obj)?;

            #[cfg(feature = "arena-shadow")]
            {
                let code = self.receiver.as_u64();
                inner
                    .arena_index64_cache
                    .cache_table((code, scope, table_name));
                let arena_h = inner
                    .arena_index64_cache
                    .add((code, scope, table_name, primary_key));
                self.note_iter_handle("idx64:store", code, scope, table_name, arena_h, handle);
            }

            handle
        };

        let billable_size = billable_size_v::<Index64Object>() as i64;
        self.update_db_usage(&payer.into(), billable_size)?;

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
        let (old_payer, new_payer) = {
            let inner = self.inner.read()?;
            let obj = inner.index64_cache.get(iterator)?;
            let table_obj = inner.index64_cache.get_table(obj.get_table_id())?;
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
            self.db.update_index64_object(obj, new_payer, secondary)?;
            // Re-point the arena row's secondary/payer too; the FFI update only
            // touches chainbase, so an arena-served read would otherwise be stale.
            #[cfg(feature = "arena-shadow")]
            self.db.arena_update_index64(
                table_obj.get_code().to_uint64_t(),
                table_obj.get_scope().to_uint64_t(),
                table_obj.get_table().to_uint64_t(),
                obj.get_primary_key(),
                new_payer,
                secondary,
            );
            (old_payer, new_payer)
        };

        if old_payer != new_payer {
            self.update_db_usage(&Name::new(old_payer), -billing_size)?;
            self.update_db_usage(&Name::new(new_payer), billing_size)?;
        }

        Ok(())
    }

    pub fn db_idx64_remove(&mut self, iterator: i32) -> Result<(), ChainError> {
        {
            let mut inner = self.inner.write()?;
            self.db
                .db_idx64_remove(&mut inner.index64_cache, iterator, self.receiver.as_u64())?;
            #[cfg(feature = "arena-shadow")]
            inner.arena_index64_cache.remove(iterator);
        }

        self.update_db_usage(
            &Name::new(self.receiver.as_u64()),
            -(billable_size_v::<Index64Object>() as i64),
        )?;

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
        let res = self.db.db_idx64_find_secondary(
            &mut inner.index64_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        // Arena answers the same secondary lookup: found -> the same primary,
        // not-found -> both agree there's no match. Serve the primary when the
        // cutover switch is on.
        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx64_find_secondary(code, scope, table, secondary);
            let ffi = if res >= 0 { Some(*primary) } else { None };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some(p) = arena
            {
                *primary = p;
            }
            self.note_secondary_handle(
                &mut inner.arena_index64_cache,
                "idx64:find_sec",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

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
        let res = self.db.db_idx64_find_primary(
            &mut inner.index64_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx64_find_primary(code, scope, table, primary);
            let ffi = if res >= 0 { Some(*secondary) } else { None };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some(s) = arena
            {
                *secondary = s;
            }
            self.note_secondary_handle(
                &mut inner.arena_index64_cache,
                "idx64:find_pri",
                code,
                scope,
                table,
                primary,
                res,
            );
        }

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
        #[cfg(feature = "arena-shadow")]
        let search = *secondary;
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx64_lowerbound(
            &mut inner.index64_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        // lowerbound/upperbound land on a row and write BOTH its secondary and
        // primary; the arena must reproduce the pair (or agree on the end).
        #[cfg(feature = "arena-shadow")]
        {
            let arena = self.db.arena_idx64_lower_bound(code, scope, table, search);
            let ffi = if res >= 0 {
                Some((*primary, *secondary))
            } else {
                None
            };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some((p, s)) = arena
            {
                *primary = p;
                *secondary = s;
            }
            self.note_secondary_handle(
                &mut inner.arena_index64_cache,
                "idx64:lb",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

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
        #[cfg(feature = "arena-shadow")]
        let search = *secondary;
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx64_upperbound(
            &mut inner.index64_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self.db.arena_idx64_upper_bound(code, scope, table, search);
            let ffi = if res >= 0 {
                Some((*primary, *secondary))
            } else {
                None
            };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some((p, s)) = arena
            {
                *primary = p;
                *secondary = s;
            }
            self.note_secondary_handle(
                &mut inner.arena_index64_cache,
                "idx64:ub",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

        Ok(res)
    }

    pub fn db_idx64_end(&mut self, code: u64, scope: u64, table: u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self
            .db
            .db_idx64_end(&mut inner.index64_cache, code, scope, table)?;

        // The end iterator equals the table's cached end handle, or -1 when the
        // table is absent.
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if res == -1 {
                -1
            } else {
                inner.arena_index64_cache.cache_table((code, scope, table))
            };
            self.note_iter_handle("idx64:end", code, scope, table, arena_h, res);
        }

        Ok(res)
    }

    pub fn db_idx64_next(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self
            .db
            .db_idx64_next(&mut inner.index64_cache, iterator, primary)?;

        // Advance the arena twin in secondary order: past-the-end stays -1, a
        // successor in the same table adds its row handle, and falling off the end
        // lands on the table's end iterator. The written primary is cross-checked
        // against the arena's successor too.
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if iterator < -1 {
                -1
            } else if let Some((code, scope, table, cur)) =
                inner.arena_index64_cache.row_of(iterator)
            {
                match self.db.arena_idx64_next(code, scope, table, cur) {
                    Some((np, _)) => {
                        self.db.arena_note_pos(res < 0 || np == *primary);
                        inner.arena_index64_cache.add((code, scope, table, np))
                    }
                    None => inner.arena_index64_cache.cache_table((code, scope, table)),
                }
            } else {
                res
            };
            self.note_iter_handle("idx64:next", 0, 0, 0, arena_h, res);
        }

        Ok(res)
    }

    pub fn db_idx64_previous(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self
            .db
            .db_idx64_previous(&mut inner.index64_cache, iterator, primary)?;

        // Retreat the arena twin: from an end iterator, land on the table's last
        // row (or -1 if empty); from a live row, land on its predecessor (or -1 at
        // the beginning). The written primary is cross-checked on a hit.
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if let Some((code, scope, table)) =
                inner.arena_index64_cache.table_of_end(iterator)
            {
                match self.db.arena_idx64_last(code, scope, table) {
                    Some((lp, _)) => {
                        self.db.arena_note_pos(res < 0 || lp == *primary);
                        inner.arena_index64_cache.add((code, scope, table, lp))
                    }
                    None => -1,
                }
            } else if let Some((code, scope, table, cur)) =
                inner.arena_index64_cache.row_of(iterator)
            {
                match self.db.arena_idx64_previous(code, scope, table, cur) {
                    Some((pp, _)) => {
                        self.db.arena_note_pos(res < 0 || pp == *primary);
                        inner.arena_index64_cache.add((code, scope, table, pp))
                    }
                    None => -1,
                }
            } else {
                res
            };
            self.note_iter_handle("idx64:prev", 0, 0, 0, arena_h, res);
        }

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
        #[cfg(feature = "arena-shadow")]
        let table_name = table;
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
            let obj = self
                .db
                .create_index128_object(table, payer, primary_key, secondary_key)?;
            let obj = unsafe { &*obj };
            inner.index128_cache.cache_table(&table)?;
            let handle = inner.index128_cache.add(obj)?;

            #[cfg(feature = "arena-shadow")]
            {
                let code = self.receiver.as_u64();
                inner
                    .arena_index128_cache
                    .cache_table((code, scope, table_name));
                let arena_h =
                    inner
                        .arena_index128_cache
                        .add((code, scope, table_name, primary_key));
                self.note_iter_handle("idx128:store", code, scope, table_name, arena_h, handle);
            }

            handle
        };

        let billable_size = billable_size_v::<Index128Object>() as i64;
        self.update_db_usage(&payer.into(), billable_size)?;

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
            let obj = inner.index128_cache.get(iterator)?;
            let table_obj = inner.index128_cache.get_table(obj.get_table_id())?;
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
            self.db.update_index128_object(obj, new_payer, secondary)?;
            #[cfg(feature = "arena-shadow")]
            self.db.arena_update_index128(
                table_obj.get_code().to_uint64_t(),
                table_obj.get_scope().to_uint64_t(),
                table_obj.get_table().to_uint64_t(),
                obj.get_primary_key(),
                new_payer,
                secondary,
            );
            (old_payer, new_payer)
        };

        if old_payer != new_payer {
            self.update_db_usage(&Name::new(old_payer), -billing_size)?;
            self.update_db_usage(&Name::new(new_payer), billing_size)?;
        }

        Ok(())
    }

    pub fn db_idx128_remove(&mut self, iterator: i32) -> Result<(), ChainError> {
        {
            let mut inner = self.inner.write()?;
            self.db.db_idx128_remove(
                &mut inner.index128_cache,
                iterator,
                self.receiver.as_u64(),
            )?;
            #[cfg(feature = "arena-shadow")]
            inner.arena_index128_cache.remove(iterator);
        }

        self.update_db_usage(
            &Name::new(self.receiver.as_u64()),
            -(billable_size_v::<Index128Object>() as i64),
        )?;

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
        let res = self.db.db_idx128_find_secondary(
            &mut inner.index128_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx128_find_secondary(code, scope, table, secondary);
            let ffi = if res >= 0 { Some(*primary) } else { None };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some(p) = arena
            {
                *primary = p;
            }
            self.note_secondary_handle(
                &mut inner.arena_index128_cache,
                "idx128:find_sec",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

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
        let res = self.db.db_idx128_find_primary(
            &mut inner.index128_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx128_find_primary(code, scope, table, primary);
            let ffi = if res >= 0 { Some(*secondary) } else { None };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some(s) = arena
            {
                *secondary = s;
            }
            self.note_secondary_handle(
                &mut inner.arena_index128_cache,
                "idx128:find_pri",
                code,
                scope,
                table,
                primary,
                res,
            );
        }

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
        #[cfg(feature = "arena-shadow")]
        let search = *secondary;
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx128_lowerbound(
            &mut inner.index128_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self.db.arena_idx128_lower_bound(code, scope, table, search);
            let ffi = if res >= 0 {
                Some((*primary, *secondary))
            } else {
                None
            };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some((p, s)) = arena
            {
                *primary = p;
                *secondary = s;
            }
            self.note_secondary_handle(
                &mut inner.arena_index128_cache,
                "idx128:lb",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

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
        #[cfg(feature = "arena-shadow")]
        let search = *secondary;
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx128_upperbound(
            &mut inner.index128_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self.db.arena_idx128_upper_bound(code, scope, table, search);
            let ffi = if res >= 0 {
                Some((*primary, *secondary))
            } else {
                None
            };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some((p, s)) = arena
            {
                *primary = p;
                *secondary = s;
            }
            self.note_secondary_handle(
                &mut inner.arena_index128_cache,
                "idx128:ub",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

        Ok(res)
    }

    pub fn db_idx128_end(&mut self, code: u64, scope: u64, table: u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self
            .db
            .db_idx128_end(&mut inner.index128_cache, code, scope, table)?;
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if res == -1 {
                -1
            } else {
                inner.arena_index128_cache.cache_table((code, scope, table))
            };
            self.note_iter_handle("idx128:end", code, scope, table, arena_h, res);
        }
        Ok(res)
    }

    pub fn db_idx128_next(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self
            .db
            .db_idx128_next(&mut inner.index128_cache, iterator, primary)?;
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if iterator < -1 {
                -1
            } else if let Some((code, scope, table, cur)) =
                inner.arena_index128_cache.row_of(iterator)
            {
                match self.db.arena_idx128_next(code, scope, table, cur) {
                    Some(np) => {
                        self.db.arena_note_pos(res < 0 || np == *primary);
                        inner.arena_index128_cache.add((code, scope, table, np))
                    }
                    None => inner.arena_index128_cache.cache_table((code, scope, table)),
                }
            } else {
                res
            };
            self.note_iter_handle("idx128:next", 0, 0, 0, arena_h, res);
        }
        Ok(res)
    }

    pub fn db_idx128_previous(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self
            .db
            .db_idx128_previous(&mut inner.index128_cache, iterator, primary)?;
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if let Some((code, scope, table)) =
                inner.arena_index128_cache.table_of_end(iterator)
            {
                match self.db.arena_idx128_last(code, scope, table) {
                    Some(lp) => {
                        self.db.arena_note_pos(res < 0 || lp == *primary);
                        inner.arena_index128_cache.add((code, scope, table, lp))
                    }
                    None => -1,
                }
            } else if let Some((code, scope, table, cur)) =
                inner.arena_index128_cache.row_of(iterator)
            {
                match self.db.arena_idx128_previous(code, scope, table, cur) {
                    Some(pp) => {
                        self.db.arena_note_pos(res < 0 || pp == *primary);
                        inner.arena_index128_cache.add((code, scope, table, pp))
                    }
                    None => -1,
                }
            } else {
                res
            };
            self.note_iter_handle("idx128:prev", 0, 0, 0, arena_h, res);
        }
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
        #[cfg(feature = "arena-shadow")]
        let table_name = table;
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
            let obj = self
                .db
                .create_index256_object(table, payer, primary_key, secondary_key)?;
            let obj = unsafe { &*obj };
            inner.index256_cache.cache_table(&table)?;
            let handle = inner.index256_cache.add(obj)?;

            #[cfg(feature = "arena-shadow")]
            {
                let code = self.receiver.as_u64();
                inner
                    .arena_index256_cache
                    .cache_table((code, scope, table_name));
                let arena_h =
                    inner
                        .arena_index256_cache
                        .add((code, scope, table_name, primary_key));
                self.note_iter_handle("idx256:store", code, scope, table_name, arena_h, handle);
            }

            handle
        };

        let billable_size = billable_size_v::<Index256Object>() as i64;
        self.update_db_usage(&payer.into(), billable_size)?;

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
            let obj = inner.index256_cache.get(iterator)?;
            let table_obj = inner.index256_cache.get_table(obj.get_table_id())?;
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
            // Mirror before the FFI update moves `secondary` (U256 is not Copy);
            // the two writes are independent so order does not matter.
            #[cfg(feature = "arena-shadow")]
            self.db.arena_update_index256(
                table_obj.get_code().to_uint64_t(),
                table_obj.get_scope().to_uint64_t(),
                table_obj.get_table().to_uint64_t(),
                obj.get_primary_key(),
                new_payer,
                &secondary,
            );
            self.db.update_index256_object(obj, new_payer, secondary)?;
            (old_payer, new_payer)
        };

        if old_payer != new_payer {
            self.update_db_usage(&Name::new(old_payer), -billing_size)?;
            self.update_db_usage(&Name::new(new_payer), billing_size)?;
        }

        Ok(())
    }

    pub fn db_idx256_remove(&mut self, iterator: i32) -> Result<(), ChainError> {
        {
            let mut inner = self.inner.write()?;
            self.db.db_idx256_remove(
                &mut inner.index256_cache,
                iterator,
                self.receiver.as_u64(),
            )?;
            #[cfg(feature = "arena-shadow")]
            inner.arena_index256_cache.remove(iterator);
        }

        self.update_db_usage(
            &Name::new(self.receiver.as_u64()),
            -(billable_size_v::<Index256Object>() as i64),
        )?;

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
        #[cfg(feature = "arena-shadow")]
        let search = secondary.value;
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx256_find_secondary(
            &mut inner.index256_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx256_find_secondary(code, scope, table, search);
            let ffi = if res >= 0 { Some(*primary) } else { None };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some(p) = arena
            {
                *primary = p;
            }
            self.note_secondary_handle(
                &mut inner.arena_index256_cache,
                "idx256:find_sec",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

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
        let res = self.db.db_idx256_find_primary(
            &mut inner.index256_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx256_find_primary(code, scope, table, primary);
            let ffi = if res >= 0 {
                Some(secondary.value)
            } else {
                None
            };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some(b) = arena
            {
                secondary.value = b;
            }
            self.note_secondary_handle(
                &mut inner.arena_index256_cache,
                "idx256:find_pri",
                code,
                scope,
                table,
                primary,
                res,
            );
        }

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
        #[cfg(feature = "arena-shadow")]
        let search = secondary.value;
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx256_lowerbound(
            &mut inner.index256_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self.db.arena_idx256_lower_bound(code, scope, table, search);
            let ffi = if res >= 0 {
                Some((*primary, secondary.value))
            } else {
                None
            };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some((p, b)) = arena
            {
                *primary = p;
                secondary.value = b;
            }
            self.note_secondary_handle(
                &mut inner.arena_index256_cache,
                "idx256:lb",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

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
        #[cfg(feature = "arena-shadow")]
        let search = secondary.value;
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx256_upperbound(
            &mut inner.index256_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self.db.arena_idx256_upper_bound(code, scope, table, search);
            let ffi = if res >= 0 {
                Some((*primary, secondary.value))
            } else {
                None
            };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some((p, b)) = arena
            {
                *primary = p;
                secondary.value = b;
            }
            self.note_secondary_handle(
                &mut inner.arena_index256_cache,
                "idx256:ub",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

        Ok(res)
    }

    pub fn db_idx256_end(&mut self, code: u64, scope: u64, table: u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self
            .db
            .db_idx256_end(&mut inner.index256_cache, code, scope, table)?;
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if res == -1 {
                -1
            } else {
                inner.arena_index256_cache.cache_table((code, scope, table))
            };
            self.note_iter_handle("idx256:end", code, scope, table, arena_h, res);
        }
        Ok(res)
    }

    pub fn db_idx256_next(&mut self, iterator: i32, primary: &mut u64) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self
            .db
            .db_idx256_next(&mut inner.index256_cache, iterator, primary)?;
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if iterator < -1 {
                -1
            } else if let Some((code, scope, table, cur)) =
                inner.arena_index256_cache.row_of(iterator)
            {
                match self.db.arena_idx256_next(code, scope, table, cur) {
                    Some(np) => {
                        self.db.arena_note_pos(res < 0 || np == *primary);
                        inner.arena_index256_cache.add((code, scope, table, np))
                    }
                    None => inner.arena_index256_cache.cache_table((code, scope, table)),
                }
            } else {
                res
            };
            self.note_iter_handle("idx256:next", 0, 0, 0, arena_h, res);
        }
        Ok(res)
    }

    pub fn db_idx256_previous(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self
            .db
            .db_idx256_previous(&mut inner.index256_cache, iterator, primary)?;
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if let Some((code, scope, table)) =
                inner.arena_index256_cache.table_of_end(iterator)
            {
                match self.db.arena_idx256_last(code, scope, table) {
                    Some(lp) => {
                        self.db.arena_note_pos(res < 0 || lp == *primary);
                        inner.arena_index256_cache.add((code, scope, table, lp))
                    }
                    None => -1,
                }
            } else if let Some((code, scope, table, cur)) =
                inner.arena_index256_cache.row_of(iterator)
            {
                match self.db.arena_idx256_previous(code, scope, table, cur) {
                    Some(pp) => {
                        self.db.arena_note_pos(res < 0 || pp == *primary);
                        inner.arena_index256_cache.add((code, scope, table, pp))
                    }
                    None => -1,
                }
            } else {
                res
            };
            self.note_iter_handle("idx256:prev", 0, 0, 0, arena_h, res);
        }
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
        #[cfg(feature = "arena-shadow")]
        let table_name = table;
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
            let obj = self
                .db
                .create_idx_double_object(table, payer, primary_key, secondary_key)?;
            let obj = unsafe { &*obj };
            inner.index_double_cache.cache_table(&table)?;
            let handle = inner.index_double_cache.add(obj)?;

            #[cfg(feature = "arena-shadow")]
            {
                let code = self.receiver.as_u64();
                inner
                    .arena_index_double_cache
                    .cache_table((code, scope, table_name));
                let arena_h =
                    inner
                        .arena_index_double_cache
                        .add((code, scope, table_name, primary_key));
                self.note_iter_handle("idxdbl:store", code, scope, table_name, arena_h, handle);
            }

            handle
        };

        let billable_size = billable_size_v::<IndexDoubleObject>() as i64;
        self.update_db_usage(&payer.into(), billable_size)?;

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
            let obj = inner.index_double_cache.get(iterator)?;
            let table_obj = inner.index_double_cache.get_table(obj.get_table_id())?;
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
            self.db
                .update_idx_double_object(obj, new_payer, secondary)?;
            #[cfg(feature = "arena-shadow")]
            self.db.arena_update_idx_double(
                table_obj.get_code().to_uint64_t(),
                table_obj.get_scope().to_uint64_t(),
                table_obj.get_table().to_uint64_t(),
                obj.get_primary_key(),
                new_payer,
                secondary,
            );
            (old_payer, new_payer)
        };

        if old_payer != new_payer {
            self.update_db_usage(&Name::new(old_payer), -billing_size)?;
            self.update_db_usage(&Name::new(new_payer), billing_size)?;
        }

        Ok(())
    }

    pub fn db_idx_double_remove(&mut self, iterator: i32) -> Result<(), ChainError> {
        {
            let mut inner = self.inner.write()?;
            self.db.db_idx_double_remove(
                &mut inner.index_double_cache,
                iterator,
                self.receiver.as_u64(),
            )?;
            #[cfg(feature = "arena-shadow")]
            inner.arena_index_double_cache.remove(iterator);
        }

        self.update_db_usage(
            &Name::new(self.receiver.as_u64()),
            -(billable_size_v::<IndexDoubleObject>() as i64),
        )?;

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
        let res = self.db.db_idx_double_find_secondary(
            &mut inner.index_double_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx_double_find_secondary(code, scope, table, secondary);
            let ffi = if res >= 0 { Some(*primary) } else { None };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some(p) = arena
            {
                *primary = p;
            }
            self.note_secondary_handle(
                &mut inner.arena_index_double_cache,
                "idxdbl:find_sec",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

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
        let res = self.db.db_idx_double_find_primary(
            &mut inner.index_double_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx_double_find_primary(code, scope, table, primary);
            let ffi = if res >= 0 { Some(*secondary) } else { None };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some(s) = arena
            {
                *secondary = s;
            }
            self.note_secondary_handle(
                &mut inner.arena_index_double_cache,
                "idxdbl:find_pri",
                code,
                scope,
                table,
                primary,
                res,
            );
        }

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
        #[cfg(feature = "arena-shadow")]
        let search = *secondary;
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx_double_lowerbound(
            &mut inner.index_double_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx_double_lower_bound(code, scope, table, search);
            let ffi = if res >= 0 {
                Some((*primary, *secondary))
            } else {
                None
            };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some((p, s)) = arena
            {
                *primary = p;
                *secondary = s;
            }
            self.note_secondary_handle(
                &mut inner.arena_index_double_cache,
                "idxdbl:lb",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

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
        #[cfg(feature = "arena-shadow")]
        let search = *secondary;
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx_double_upperbound(
            &mut inner.index_double_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx_double_upper_bound(code, scope, table, search);
            let ffi = if res >= 0 {
                Some((*primary, *secondary))
            } else {
                None
            };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some((p, s)) = arena
            {
                *primary = p;
                *secondary = s;
            }
            self.note_secondary_handle(
                &mut inner.arena_index_double_cache,
                "idxdbl:ub",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

        Ok(res)
    }

    pub fn db_idx_double_end(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self
            .db
            .db_idx_double_end(&mut inner.index_double_cache, code, scope, table)?;
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if res == -1 {
                -1
            } else {
                inner
                    .arena_index_double_cache
                    .cache_table((code, scope, table))
            };
            self.note_iter_handle("idxdbl:end", code, scope, table, arena_h, res);
        }
        Ok(res)
    }

    pub fn db_idx_double_next(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self
            .db
            .db_idx_double_next(&mut inner.index_double_cache, iterator, primary)?;
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if iterator < -1 {
                -1
            } else if let Some((code, scope, table, cur)) =
                inner.arena_index_double_cache.row_of(iterator)
            {
                match self.db.arena_idx_double_next(code, scope, table, cur) {
                    Some(np) => {
                        self.db.arena_note_pos(res < 0 || np == *primary);
                        inner.arena_index_double_cache.add((code, scope, table, np))
                    }
                    None => inner
                        .arena_index_double_cache
                        .cache_table((code, scope, table)),
                }
            } else {
                res
            };
            self.note_iter_handle("idxdbl:next", 0, 0, 0, arena_h, res);
        }
        Ok(res)
    }

    pub fn db_idx_double_previous(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res =
            self.db
                .db_idx_double_previous(&mut inner.index_double_cache, iterator, primary)?;
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if let Some((code, scope, table)) =
                inner.arena_index_double_cache.table_of_end(iterator)
            {
                match self.db.arena_idx_double_last(code, scope, table) {
                    Some(lp) => {
                        self.db.arena_note_pos(res < 0 || lp == *primary);
                        inner.arena_index_double_cache.add((code, scope, table, lp))
                    }
                    None => -1,
                }
            } else if let Some((code, scope, table, cur)) =
                inner.arena_index_double_cache.row_of(iterator)
            {
                match self.db.arena_idx_double_previous(code, scope, table, cur) {
                    Some(pp) => {
                        self.db.arena_note_pos(res < 0 || pp == *primary);
                        inner.arena_index_double_cache.add((code, scope, table, pp))
                    }
                    None => -1,
                }
            } else {
                res
            };
            self.note_iter_handle("idxdbl:prev", 0, 0, 0, arena_h, res);
        }
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
        #[cfg(feature = "arena-shadow")]
        let table_name = table;
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
                    .create_idx_long_double_object(table, payer, primary_key, secondary_key)?;
            let obj = unsafe { &*obj };
            inner.index_long_double_cache.cache_table(&table)?;
            let handle = inner.index_long_double_cache.add(obj)?;

            #[cfg(feature = "arena-shadow")]
            {
                let code = self.receiver.as_u64();
                inner
                    .arena_index_long_double_cache
                    .cache_table((code, scope, table_name));
                let arena_h =
                    inner
                        .arena_index_long_double_cache
                        .add((code, scope, table_name, primary_key));
                self.note_iter_handle("idxldbl:store", code, scope, table_name, arena_h, handle);
            }

            handle
        };

        let billable_size = billable_size_v::<IndexLongDoubleObject>() as i64;
        self.update_db_usage(&payer.into(), billable_size)?;

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
            let obj = inner.index_long_double_cache.get(iterator)?;
            let table_obj = inner
                .index_long_double_cache
                .get_table(obj.get_table_id())?;
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
            // Mirror before the FFI update moves `secondary` (Float128 is not
            // Copy); the two writes are independent so order does not matter.
            #[cfg(feature = "arena-shadow")]
            self.db.arena_update_idx_long_double(
                table_obj.get_code().to_uint64_t(),
                table_obj.get_scope().to_uint64_t(),
                table_obj.get_table().to_uint64_t(),
                obj.get_primary_key(),
                new_payer,
                &secondary,
            );
            self.db
                .update_idx_long_double_object(obj, new_payer, secondary)?;
            (old_payer, new_payer)
        };

        if old_payer != new_payer {
            self.update_db_usage(&Name::new(old_payer), -billing_size)?;
            self.update_db_usage(&Name::new(new_payer), billing_size)?;
        }

        Ok(())
    }

    pub fn db_idx_long_double_remove(&mut self, iterator: i32) -> Result<(), ChainError> {
        {
            let mut inner = self.inner.write()?;
            self.db.db_idx_long_double_remove(
                &mut inner.index_long_double_cache,
                iterator,
                self.receiver.as_u64(),
            )?;
            #[cfg(feature = "arena-shadow")]
            inner.arena_index_long_double_cache.remove(iterator);
        }

        self.update_db_usage(
            &Name::new(self.receiver.as_u64()),
            -(billable_size_v::<IndexLongDoubleObject>() as i64),
        )?;

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
        #[cfg(feature = "arena-shadow")]
        let search = (secondary.lo, secondary.hi);
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx_long_double_find_secondary(
            &mut inner.index_long_double_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx_long_double_find_secondary(code, scope, table, search);
            let ffi = if res >= 0 { Some(*primary) } else { None };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some(p) = arena
            {
                *primary = p;
            }
            self.note_secondary_handle(
                &mut inner.arena_index_long_double_cache,
                "idxldbl:find_sec",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

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
        let res = self.db.db_idx_long_double_find_primary(
            &mut inner.index_long_double_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx_long_double_find_primary(code, scope, table, primary);
            let ffi = if res >= 0 {
                Some((secondary.lo, secondary.hi))
            } else {
                None
            };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some((lo, hi)) = arena
            {
                secondary.lo = lo;
                secondary.hi = hi;
            }
            self.note_secondary_handle(
                &mut inner.arena_index_long_double_cache,
                "idxldbl:find_pri",
                code,
                scope,
                table,
                primary,
                res,
            );
        }

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
        #[cfg(feature = "arena-shadow")]
        let search = (secondary.lo, secondary.hi);
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx_long_double_lowerbound(
            &mut inner.index_long_double_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx_long_double_lower_bound(code, scope, table, search);
            let ffi = if res >= 0 {
                Some((*primary, (secondary.lo, secondary.hi)))
            } else {
                None
            };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some((p, (lo, hi))) = arena
            {
                *primary = p;
                secondary.lo = lo;
                secondary.hi = hi;
            }
            self.note_secondary_handle(
                &mut inner.arena_index_long_double_cache,
                "idxldbl:lb",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

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
        #[cfg(feature = "arena-shadow")]
        let search = (secondary.lo, secondary.hi);
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx_long_double_upperbound(
            &mut inner.index_long_double_cache,
            code,
            scope,
            table,
            secondary,
            primary,
        )?;

        #[cfg(feature = "arena-shadow")]
        {
            let arena = self
                .db
                .arena_idx_long_double_upper_bound(code, scope, table, search);
            let ffi = if res >= 0 {
                Some((*primary, (secondary.lo, secondary.hi)))
            } else {
                None
            };
            self.db.arena_note_pos(arena == ffi);
            if self.db.arena_reads_enabled()
                && res >= 0
                && let Some((p, (lo, hi))) = arena
            {
                *primary = p;
                secondary.lo = lo;
                secondary.hi = hi;
            }
            self.note_secondary_handle(
                &mut inner.arena_index_long_double_cache,
                "idxldbl:ub",
                code,
                scope,
                table,
                *primary,
                res,
            );
        }

        Ok(res)
    }

    pub fn db_idx_long_double_end(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx_long_double_end(
            &mut inner.index_long_double_cache,
            code,
            scope,
            table,
        )?;
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if res == -1 {
                -1
            } else {
                inner
                    .arena_index_long_double_cache
                    .cache_table((code, scope, table))
            };
            self.note_iter_handle("idxldbl:end", code, scope, table, arena_h, res);
        }
        Ok(res)
    }

    pub fn db_idx_long_double_next(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx_long_double_next(
            &mut inner.index_long_double_cache,
            iterator,
            primary,
        )?;
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if iterator < -1 {
                -1
            } else if let Some((code, scope, table, cur)) =
                inner.arena_index_long_double_cache.row_of(iterator)
            {
                match self.db.arena_idx_long_double_next(code, scope, table, cur) {
                    Some(np) => {
                        self.db.arena_note_pos(res < 0 || np == *primary);
                        inner
                            .arena_index_long_double_cache
                            .add((code, scope, table, np))
                    }
                    None => inner
                        .arena_index_long_double_cache
                        .cache_table((code, scope, table)),
                }
            } else {
                res
            };
            self.note_iter_handle("idxldbl:next", 0, 0, 0, arena_h, res);
        }
        Ok(res)
    }

    pub fn db_idx_long_double_previous(
        &mut self,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut inner = self.inner.write()?;
        let res = self.db.db_idx_long_double_previous(
            &mut inner.index_long_double_cache,
            iterator,
            primary,
        )?;
        #[cfg(feature = "arena-shadow")]
        {
            let arena_h = if let Some((code, scope, table)) =
                inner.arena_index_long_double_cache.table_of_end(iterator)
            {
                match self.db.arena_idx_long_double_last(code, scope, table) {
                    Some(lp) => {
                        self.db.arena_note_pos(res < 0 || lp == *primary);
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
                        self.db.arena_note_pos(res < 0 || pp == *primary);
                        inner
                            .arena_index_long_double_cache
                            .add((code, scope, table, pp))
                    }
                    None => -1,
                }
            } else {
                res
            };
            self.note_iter_handle("idxldbl:prev", 0, 0, 0, arena_h, res);
        }
        Ok(res)
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

    /// Record the value a contract set via `set_action_return_value` on this
    /// action's trace. This is informational (history/RPC) only — the action
    /// receipt digest is unchanged — so surfacing it does not affect consensus.
    pub fn set_trace_return_value(&self, value: Vec<u8>) -> Result<(), ChainError> {
        self.trx_context
            .modify_action_trace(self.action_ordinal, |trace| {
                trace.return_value = value;
            })
    }

    pub fn next_recv_sequence(&mut self, account_name: u64) -> Result<u64, ChainError> {
        self.db.next_recv_sequence(account_name)
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

/// The `(code, scope, table, primary)` a live iterator points at, or `None` for
/// an end iterator (no backing row). Used to seed the arena positioning checks.
#[cfg(feature = "arena-shadow")]
fn current_iter_key(cache: &KeyValueIteratorCache, iterator: i32) -> Option<(u64, u64, u64, u64)> {
    let obj = cache.get(iterator).ok()?;
    let table = cache.get_table(obj.get_table_id()).ok()?;
    Some((
        table.get_code().to_uint64_t(),
        table.get_scope().to_uint64_t(),
        table.get_table().to_uint64_t(),
        obj.get_primary_key(),
    ))
}

/// The primary key iterator `res` lands on, or `None` for an end iterator.
#[cfg(feature = "arena-shadow")]
fn landing_primary(cache: &KeyValueIteratorCache, res: i32) -> Option<u64> {
    if res < 0 {
        return None;
    }
    cache.get(res).ok().map(|o| o.get_primary_key())
}

/// The `(code, scope, table)` an end iterator belongs to, so a step back from
/// the end can be positioned against the arena. `None` if `iterator` isn't a
/// known end iterator.
#[cfg(feature = "arena-shadow")]
fn end_iter_table(cache: &KeyValueIteratorCache, iterator: i32) -> Option<(u64, u64, u64)> {
    let table = cache.find_table_by_end_iterator(iterator).ok().flatten()?;
    Some((
        table.get_code().to_uint64_t(),
        table.get_scope().to_uint64_t(),
        table.get_table().to_uint64_t(),
    ))
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
#[cfg(feature = "arena-shadow")]
#[derive(Default)]
struct ArenaIteratorCache {
    end_to_table: Vec<(u64, u64, u64)>,
    table_to_end: std::collections::HashMap<(u64, u64, u64), i32>,
    // `None` marks a slot whose row was removed — the index is never reused, so
    // a later re-insert of the same key takes a fresh handle, as in chainbase.
    iter_to_row: Vec<Option<(u64, u64, u64, u64)>>,
    row_to_iter: std::collections::HashMap<(u64, u64, u64, u64), i32>,
}

#[cfg(feature = "arena-shadow")]
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
