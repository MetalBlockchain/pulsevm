use std::sync::{Arc, RwLock};

use cxx::UniquePtr;
use pulsevm_error::ChainError;
use pulsevm_name::Name;

use crate::{
    AccountMetadataObject, ChainConfigV0, Float128, Index64IteratorCache, Index128IteratorCache,
    IndexDoubleIteratorCache, IndexLongDoubleIteratorCache, IndexLongDoubleObject, KeyValueObject,
    bridge::ffi::{
        self, Authority, CxxDigest, CxxGenesisState, ElasticLimitParameters, Index64Object,
        Index128Object, Index256Object, IndexDoubleObject, TableObject, TimePoint, U128, U256,
        get_account_info_with_core_symbol, get_account_info_without_core_symbol,
        get_currency_balance_with_symbol, get_currency_balance_without_symbol, get_currency_stats,
        get_table_by_scope, get_table_rows,
    },
    iterator_cache::{Index256IteratorCache, KeyValueIteratorCache},
};

/// Copies a chainbase `digest_type` (sha256) into a fixed 32-byte array for the
/// arena mirror. A digest that is not 32 bytes is zero-padded/truncated, which
/// only degrades the mirror's fidelity, never chainbase.
#[cfg(feature = "arena-shadow")]
fn digest_to_array(digest: &CxxDigest) -> [u8; 32] {
    let data = ffi::get_digest_data(digest);
    let mut out = [0u8; 32];
    let n = data.len().min(32);
    out[..n].copy_from_slice(&data[..n]);
    out
}

/// Serializes an [`Authority`] into the deterministic byte layout the arena
/// mirror stores for `permission_object::auth` (a `shared_authority`). The exact
/// encoding is private to the mirror; it only has to be stable so equal
/// authorities hash equal.
#[cfg(feature = "arena-shadow")]
fn encode_authority(auth: &Authority) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&auth.threshold.to_le_bytes());
    out.extend_from_slice(&(auth.keys.len() as u32).to_le_bytes());
    for k in &auth.keys {
        let bytes = match k.key.as_ref() {
            Some(pk) => ffi::packed_public_key_bytes(pk),
            None => Vec::new(),
        };
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
        out.extend_from_slice(&k.weight.to_le_bytes());
    }
    out.extend_from_slice(&(auth.accounts.len() as u32).to_le_bytes());
    for a in &auth.accounts {
        out.extend_from_slice(&a.permission.actor.to_le_bytes());
        out.extend_from_slice(&a.permission.permission.to_le_bytes());
        out.extend_from_slice(&a.weight.to_le_bytes());
    }
    out.extend_from_slice(&(auth.waits.len() as u32).to_le_bytes());
    for w in &auth.waits {
        out.extend_from_slice(&w.wait_sec.to_le_bytes());
        out.extend_from_slice(&w.weight.to_le_bytes());
    }
    out
}

/// The `(code, scope, table)` triple of a contract table, packed into `u64`s for
/// the arena mirror, which keys its contract-table rows by this triple.
#[cfg(feature = "arena-shadow")]
fn table_key(table: &TableObject) -> (u64, u64, u64) {
    (
        table.get_code().to_uint64_t(),
        table.get_scope().to_uint64_t(),
        table.get_table().to_uint64_t(),
    )
}

#[derive(Clone)]
pub struct Database {
    inner: Arc<RwLock<UniquePtr<ffi::Database>>>,
    /// The native pulsevm_arena mirror, shared across clones. Carried here so
    /// writes reach it through the same handle every apply/transaction context
    /// already uses (see `shadow.rs`). Only present in arena-shadow builds.
    #[cfg(feature = "arena-shadow")]
    shadow: Option<crate::shadow::ArenaShadow>,
}

impl Database {
    pub fn new(path: &str, size: u64) -> Result<Self, String> {
        let db = ffi::open_database(path, ffi::DatabaseOpenFlags::ReadWrite, size);

        if db.is_null() {
            Err("Failed to open database".to_string())
        } else {
            Ok(Database {
                inner: Arc::new(RwLock::new(db)),
                #[cfg(feature = "arena-shadow")]
                shadow: None,
            })
        }
    }

    // ----- arena shadow (differential testing; no-ops without the feature) ---

    /// Attaches a fresh arena mirror at chainbase's current revision. Every
    /// clone of this handle then shares it, so ported writes are mirrored.
    pub fn enable_shadow(&mut self) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        {
            let shadow = crate::shadow::ArenaShadow::new()
                .map_err(|e| ChainError::InternalError(format!("arena shadow init: {e:?}")))?;
            shadow
                .set_revision(self.revision())
                .map_err(|e| ChainError::InternalError(format!("arena set_revision: {e:?}")))?;
            self.shadow = Some(shadow);
        }
        Ok(())
    }

    /// The arena mirror's account_metadata privileged flag for `name`, or
    /// `None` if the mirror has no such row / shadowing is off — for diffing
    /// against chainbase's `find_account_metadata`.
    pub fn arena_account_metadata_privileged(&self, name: u64) -> Option<bool> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_metadata_privileged(name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = name;
            None
        }
    }

    /// Whether the arena mirror holds an account_object for `name` — for diffing
    /// against chainbase's `find_account`.
    pub fn arena_account_exists(&self, name: u64) -> bool {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.account_exists(name)).unwrap_or(false)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = name;
            false
        }
    }

    /// State root of the mirrored subset, or `None` when shadowing is off. Only
    /// ported tables contribute, so it is comparable to chainbase for those.
    pub fn arena_state_root(&self) -> Option<[u8; 32]> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.state_root())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    /// Arena undo-session lifecycle, driven by the controller in lockstep with
    /// the chainbase session boundaries.
    pub fn arena_start_undo_session(&self) {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.start_undo_session();
        }
    }
    pub fn arena_squash(&self) {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.squash();
        }
    }
    pub fn arena_undo(&self) {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.undo();
        }
    }
    pub fn arena_commit(&self, revision: i64) {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.commit(revision);
        }
        #[cfg(not(feature = "arena-shadow"))]
        let _ = revision;
    }

    // Replace the inner database with null to call the destructors
    pub fn close(&self) -> Result<(), ChainError> {
        let mut db = self.inner.write()?;
        *db = UniquePtr::<ffi::Database>::null();
        Ok(())
    }

    pub fn commit(&mut self, revision: i64) -> Result<(), ChainError> {
        self.inner
            .write()?
            .pin_mut()
            .commit(revision)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn undo(&mut self) -> Result<(), ChainError> {
        self.inner
            .write()?
            .pin_mut()
            .undo()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn revision(&self) -> i64 {
        self.inner.read().unwrap().revision()
    }

    pub fn set_revision(&mut self, revision: i64) -> Result<(), ChainError> {
        self.inner
            .write()?
            .pin_mut()
            .set_revision(revision)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn add_indices(&mut self) -> Result<(), ChainError> {
        self.inner.write()?.pin_mut().add_indices();
        Ok(())
    }

    pub fn initialize_database(&mut self, genesis: &CxxGenesisState) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .initialize_database(genesis)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_account(
        &mut self,
        account_name: u64,
        creation_date: u32,
    ) -> Result<*const ffi::AccountObject, ChainError> {
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_account(account_name, creation_date)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const ffi::AccountObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_account(account_name, creation_date)
        {
            eprintln!("arena mirror of account {account_name} diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn find_account(&self, account_name: u64) -> Result<*const ffi::AccountObject, ChainError> {
        let guard = self.inner.read()?;
        let account = guard
            .find_account(account_name)
            .map_err(|e| ChainError::InternalError(format!("failed to get account: {}", e)))?;

        Ok(account)
    }

    pub fn get_account(
        &self,
        account_name: u64,
    ) -> Result<&'static ffi::AccountObject, ChainError> {
        let guard = self.inner.read()?;
        let account = guard
            .find_account(account_name)
            .map_err(|e| ChainError::InternalError(format!("failed to get account: {}", e)))?;

        if account.is_null() {
            return Err(ChainError::InternalError(format!(
                "account not found: {}",
                account_name
            )));
        }

        Ok(unsafe { &*account })
    }

    pub fn create_account_metadata(
        &mut self,
        account_name: u64,
        is_privileged: bool,
    ) -> Result<*const ffi::AccountMetadataObject, ChainError> {
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_account_metadata(account_name, is_privileged)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const ffi::AccountMetadataObject
        };
        // Mirror after releasing the chainbase lock, so the two locks are never
        // held at once. Chainbase is authoritative; a mirror error is logged.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_account_metadata(account_name, is_privileged)
        {
            eprintln!("arena mirror of account_metadata {account_name} diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn find_account_metadata(
        &self,
        account_name: u64,
    ) -> Result<*const ffi::AccountMetadataObject, ChainError> {
        let guard = self.inner.read()?;

        guard.find_account_metadata(account_name).map_err(|e| {
            ChainError::InternalError(format!("failed to find account metadata: {}", e))
        })
    }

    pub fn set_privileged(&mut self, account: u64, is_privileged: bool) -> Result<(), ChainError> {
        {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .set_privileged(account, is_privileged)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.set_privileged(account, is_privileged)
        {
            eprintln!("arena mirror of set_privileged {account} diverged: {e:?}");
        }
        Ok(())
    }

    pub fn get_account_metadata(
        &self,
        account_name: u64,
    ) -> Result<&'static ffi::AccountMetadataObject, ChainError> {
        let guard = self.inner.read()?;
        let res = guard.find_account_metadata(account_name).map_err(|e| {
            ChainError::InternalError(format!("failed to find account metadata: {}", e))
        })?;

        if res.is_null() {
            return Err(ChainError::InternalError(format!(
                "account metadata not found for account: {}",
                account_name
            )));
        }

        Ok(unsafe { &*res })
    }

    pub fn unlink_account_code(
        &mut self,
        old_code_entry: &ffi::CodeObject,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let hash = digest_to_array(old_code_entry.get_code_hash());
        {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .unlink_account_code(old_code_entry)
                .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.unlink_account_code(hash)
        {
            eprintln!("arena mirror of unlink_account_code diverged: {e:?}");
        }
        Ok(())
    }

    pub fn update_account_code(
        &mut self,
        account: &ffi::AccountMetadataObject,
        new_code: &[u8],
        head_block_num: u32,
        pending_block_time: &TimePoint,
        code_hash: &CxxDigest,
        vm_type: u8,
        vm_version: u8,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .update_account_code(
                    account,
                    new_code,
                    head_block_num,
                    pending_block_time,
                    code_hash,
                    vm_type,
                    vm_version,
                )
                .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let hash = digest_to_array(code_hash);
            if let Err(e) =
                s.update_account_code(new_code, hash, head_block_num, vm_type, vm_version)
            {
                eprintln!("arena mirror of update_account_code diverged: {e:?}");
            }
        }
        Ok(())
    }

    pub fn update_account_abi(
        &mut self,
        account: &ffi::AccountObject,
        account_metadata: &ffi::AccountMetadataObject,
        abi: &[u8],
    ) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_account_abi(account, account_metadata, abi)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_undo_session(
        &mut self,
        enabled: bool,
    ) -> Result<cxx::UniquePtr<ffi::UndoSession>, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .create_undo_session(enabled)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn initialize_resource_limits(&mut self) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .initialize_resource_limits()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn initialize_account_resource_limits(
        &mut self,
        account_name: u64,
    ) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .initialize_account_resource_limits(account_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn update_account_usage(
        &mut self,
        account: &Name,
        time_slot: u32,
    ) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_account_usage(account.as_u64(), time_slot)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn add_transaction_usage(
        &mut self,
        account: &Name,
        cpu_usage: u64,
        net_usage: u64,
        time_slot: u32,
    ) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .add_transaction_usage(account.as_u64(), cpu_usage, net_usage, time_slot)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn add_pending_ram_usage(
        &mut self,
        account_name: u64,
        ram_bytes: i64,
    ) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .add_pending_ram_usage(account_name, ram_bytes)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn verify_account_ram_usage(&mut self, account_name: u64) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .verify_account_ram_usage(account_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_ram_usage(&self, account_name: u64) -> Result<i64, ChainError> {
        let guard = self.inner.read()?;

        guard
            .get_account_ram_usage(account_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn set_account_limits(
        &mut self,
        account_name: u64,
        ram_bytes: i64,
        net_weight: i64,
        cpu_weight: i64,
    ) -> Result<bool, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .set_account_limits(account_name, ram_bytes, net_weight, cpu_weight)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_limits(
        &self,
        account_name: u64,
        ram_bytes: &mut i64,
        net_weight: &mut i64,
        cpu_weight: &mut i64,
    ) -> Result<(), ChainError> {
        let guard = self.inner.read()?;

        guard
            .get_account_limits(account_name, ram_bytes, net_weight, cpu_weight)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_total_cpu_weight(&self) -> Result<u64, ChainError> {
        let guard = self.inner.read()?;

        guard
            .get_total_cpu_weight()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_total_net_weight(&self) -> Result<u64, ChainError> {
        let guard = self.inner.read()?;

        guard
            .get_total_net_weight()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_net_limit(
        &self,
        name: u64,
        greylist_limit: u32,
    ) -> Result<ffi::NetLimitResult, ChainError> {
        let guard = self.inner.read()?;

        guard
            .get_account_net_limit(name, greylist_limit)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_cpu_limit(
        &self,
        name: u64,
        greylist_limit: u32,
    ) -> Result<ffi::CpuLimitResult, ChainError> {
        let guard = self.inner.read()?;

        guard
            .get_account_cpu_limit(name, greylist_limit)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn process_account_limit_updates(&mut self) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .process_account_limit_updates()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn set_block_parameters(
        &mut self,
        cpu_limit_parameters: &ElasticLimitParameters,
        net_limit_parameters: &ElasticLimitParameters,
    ) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .set_block_parameters(cpu_limit_parameters, net_limit_parameters)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn process_block_usage(&mut self, block_num: u32) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .process_block_usage(block_num)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn find_table(
        &self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<*const TableObject, ChainError> {
        let guard = self.inner.read()?;
        let res = guard
            .find_table(code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn get_table(
        &self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<*const TableObject, ChainError> {
        let guard = self.inner.read()?;
        let res = guard
            .find_table(code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        if res.is_null() {
            return Err(ChainError::InternalError(format!(
                "table not found for code: {} scope: {} table: {}",
                code, scope, table
            )));
        }

        Ok(res)
    }

    pub fn create_table(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
    ) -> Result<*const TableObject, ChainError> {
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_table(code, scope, table, payer)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const TableObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_table(code, scope, table, payer)
        {
            eprintln!("arena mirror of create_table diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn db_find_i64(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        id: u64,
        keyval_cache: &mut KeyValueIteratorCache,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        { pinned.db_find_i64(code, scope, table, id, keyval_cache.pin_mut()) }
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_key_value_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        buffer: &[u8],
    ) -> Result<*const KeyValueObject, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_key_value_object(table, payer, id, buffer)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const KeyValueObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_key_value_object(key.0, key.1, key.2, payer, id, buffer)
        {
            eprintln!("arena mirror of create_key_value_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn create_index64_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: u64,
    ) -> Result<*const Index64Object, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_index64_object(table, payer, id, secondary_key)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const Index64Object
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_index64_object(key.0, key.1, key.2, payer, id, secondary_key)
        {
            eprintln!("arena mirror of create_index64_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_key_value_object(
        &mut self,
        obj: &KeyValueObject,
        payer: u64,
        buffer: &[u8],
    ) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_key_value_object(obj, payer, buffer)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn update_index64_object(
        &mut self,
        obj: &Index64Object,
        payer: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_index64_object(obj, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn remove_table(&mut self, table: &TableObject) -> Result<(), ChainError> {
        // Read the key before removal, while the object is still valid.
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .remove_table(table)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.remove_table(key.0, key.1, key.2)
        {
            eprintln!("arena mirror of remove_table diverged: {e:?}");
        }
        Ok(())
    }

    pub fn is_account(&self, account: u64) -> Result<bool, ChainError> {
        let guard = self.inner.read()?;

        guard
            .is_account(account)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn find_permission(&self, id: i64) -> Result<*const ffi::PermissionObject, ChainError> {
        let guard = self.inner.read()?;
        let res = guard
            .find_permission(id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn find_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<*const ffi::PermissionObject, ChainError> {
        let guard = self.inner.read()?;
        let res = guard
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn get_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<*const ffi::PermissionObject, ChainError> {
        let guard = self.inner.read()?;
        let res = guard
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        if res.is_null() {
            return Err(ChainError::InternalError(format!(
                "permission not found for actor: {} permission: {}",
                pulsevm_name::Name::new(actor),
                pulsevm_name::Name::new(permission)
            )));
        }

        Ok(res)
    }

    pub fn delete_auth(&mut self, account: u64, permission_name: u64) -> Result<i64, ChainError> {
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .delete_auth(account, permission_name)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        // delete_auth removes the permission (and its usage row) in C++.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.remove_permission(account, permission_name)
        {
            eprintln!("arena mirror of delete_auth {account} diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn link_auth(
        &mut self,
        account_name: u64,
        code_name: u64,
        requirement_name: u64,
        requirement_type: u64,
    ) -> Result<i64, ChainError> {
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .link_auth(account_name, code_name, requirement_name, requirement_type)
                .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))?
        };
        // In C++ the link's message_type is the requirement_type and its
        // required_permission is the requirement_name.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) =
                s.link_auth(account_name, code_name, requirement_type, requirement_name)
        {
            eprintln!("arena mirror of link_auth diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn unlink_auth(
        &mut self,
        account_name: u64,
        code_name: u64,
        requirement_type: u64,
    ) -> Result<i64, ChainError> {
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .unlink_auth(account_name, code_name, requirement_type)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.unlink_auth(account_name, code_name, requirement_type)
        {
            eprintln!("arena mirror of unlink_auth diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn get_code_object_by_hash(
        &self,
        code_hash: &CxxDigest,
        vm_type: u8,
        vm_version: u8,
    ) -> Result<*const ffi::CodeObject, ChainError> {
        let guard = self.inner.read()?;
        let res = guard
            .get_code_object_by_hash(code_hash, vm_type, vm_version)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn next_recv_sequence(
        &mut self,
        receiver_account: &AccountMetadataObject,
    ) -> Result<u64, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .next_recv_sequence(receiver_account)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn next_auth_sequence(&mut self, actor: u64) -> Result<u64, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .next_auth_sequence(actor)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn next_global_sequence(&mut self) -> Result<u64, ChainError> {
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .next_global_sequence()
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.set_global_action_sequence(res)
        {
            eprintln!("arena mirror of next_global_sequence diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn db_remove_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<i64, ChainError> {
        // Resolve the row's (code, scope, table, primary) through the cache
        // before it is deleted; a mirror-resolution error must never abort the
        // authoritative removal, so it is swallowed to `None`.
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_remove_i64(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_key_value_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_remove_i64 diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn db_idx64_remove(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx64_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_index64_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx64_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx64_find_secondary(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_find_primary(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_lowerbound(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_upperbound(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_end(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_next(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_previous(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_index128_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: u128,
    ) -> Result<*const Index128Object, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_index128_object(table, payer, id, secondary_key.into())
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const Index128Object
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_index128_object(key.0, key.1, key.2, payer, id, secondary_key)
        {
            eprintln!("arena mirror of create_index128_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_index128_object(
        &mut self,
        obj: &Index128Object,
        payer: u64,
        secondary_key: u128,
    ) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_index128_object(obj, payer, secondary_key.into())
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx128_remove(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx128_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_index128_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx128_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx128_find_secondary(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: u128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();
        let secondary_key_u128: U128 = secondary_key.into();

        let res = pinned
            .db_idx128_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key_u128,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx128_find_primary(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u128,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();
        let mut secondary_u128: U128 = (*secondary).into();
        let res = pinned
            .db_idx128_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                &mut secondary_u128,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        *secondary = secondary_u128.into();
        Ok(res)
    }

    pub fn db_idx128_lowerbound(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();
        let mut secondary_key_u128: U128 = (*secondary_key).into();

        let res = pinned
            .db_idx128_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                &mut secondary_key_u128,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        *secondary_key = secondary_key_u128.into();
        Ok(res)
    }

    pub fn db_idx128_upperbound(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();
        let mut secondary_key_u128: U128 = (*secondary_key).into();
        let res = pinned
            .db_idx128_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                &mut secondary_key_u128,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        *secondary_key = secondary_key_u128.into();
        Ok(res)
    }

    pub fn db_idx128_end(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx128_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx128_next(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx128_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx128_previous(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx128_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_index256_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: U256,
    ) -> Result<*const Index256Object, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        #[cfg(feature = "arena-shadow")]
        let sec_bytes = secondary_key.value;
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_index256_object(table, payer, id, secondary_key)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const Index256Object
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_index256_object(key.0, key.1, key.2, payer, id, sec_bytes)
        {
            eprintln!("arena mirror of create_index256_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_index256_object(
        &mut self,
        obj: &Index256Object,
        payer: u64,
        secondary_key: U256,
    ) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_index256_object(obj, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx256_remove(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx256_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_index256_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx256_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx256_find_secondary(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: U256,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx256_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx256_find_primary(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut U256,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx256_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx256_lowerbound(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut U256,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx256_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx256_upperbound(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut U256,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx256_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx256_end(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx256_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx256_next(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx256_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx256_previous(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx256_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_idx_double_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: u64,
    ) -> Result<*const IndexDoubleObject, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_idx_double_object(table, payer, id, secondary_key)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const IndexDoubleObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_idx_double_object(key.0, key.1, key.2, payer, id, secondary_key)
        {
            eprintln!("arena mirror of create_idx_double_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_idx_double_object(
        &mut self,
        obj: &IndexDoubleObject,
        payer: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_idx_double_object(obj, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_double_remove(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx_double_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_idx_double_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx_double_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx_double_find_secondary(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx_double_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_double_find_primary(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx_double_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_double_lowerbound(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx_double_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_double_upperbound(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx_double_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_double_end(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_double_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_double_next(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_double_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_double_previous(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_double_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_idx_long_double_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: Float128,
    ) -> Result<*const IndexLongDoubleObject, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        #[cfg(feature = "arena-shadow")]
        let (sec_lo, sec_hi) = (secondary_key.lo, secondary_key.hi);
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_idx_long_double_object(table, payer, id, secondary_key)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const IndexLongDoubleObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) =
                s.create_idx_long_double_object(key.0, key.1, key.2, payer, id, (sec_lo, sec_hi))
        {
            eprintln!("arena mirror of create_idx_long_double_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_idx_long_double_object(
        &mut self,
        obj: &IndexLongDoubleObject,
        payer: u64,
        secondary_key: Float128,
    ) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_idx_long_double_object(obj, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_long_double_remove(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx_long_double_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_idx_long_double_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx_long_double_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx_long_double_find_secondary(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: Float128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx_long_double_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_long_double_find_primary(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut Float128,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx_long_double_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_long_double_lowerbound(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut Float128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx_long_double_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_long_double_upperbound(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut Float128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx_long_double_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_long_double_end(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_long_double_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_long_double_next(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_long_double_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_long_double_previous(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_long_double_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_next_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_next_i64(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_previous_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_previous_i64(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_end_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_end_i64(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_lowerbound_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        id: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_lowerbound_i64(keyval_cache.pin_mut(), code, scope, table, id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_upperbound_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        id: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_upperbound_i64(keyval_cache.pin_mut(), code, scope, table, id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn remove_permission(
        &mut self,
        permission: &ffi::PermissionObject,
    ) -> Result<(), ChainError> {
        // Read the key before removal, while the object is still valid.
        #[cfg(feature = "arena-shadow")]
        let owner_perm = (
            permission.get_owner().to_uint64_t(),
            permission.get_name().to_uint64_t(),
        );
        {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .remove_permission(permission)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.remove_permission(owner_perm.0, owner_perm.1)
        {
            eprintln!("arena mirror of remove_permission diverged: {e:?}");
        }
        Ok(())
    }

    pub fn create_permission(
        &mut self,
        account: u64,
        name: u64,
        parent: u64,
        auth: &Authority,
        creation_time: &TimePoint,
    ) -> Result<*const ffi::PermissionObject, ChainError> {
        let res = {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_permission(account, name, parent, auth, creation_time)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const ffi::PermissionObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let auth_bytes = encode_authority(auth);
            if let Err(e) = s.create_permission(
                parent as i64,
                account,
                name,
                creation_time.elapsed.count,
                &auth_bytes,
            ) {
                eprintln!("arena mirror of create_permission diverged: {e:?}");
            }
        }
        Ok(res)
    }

    pub fn permission_satisfies_other_permission(
        &self,
        permission: &ffi::PermissionObject,
        other_permission: &ffi::PermissionObject,
    ) -> Result<bool, ChainError> {
        let guard = self.inner.read()?;
        let res = guard
            .permission_satisfies_other_permission(permission, other_permission)
            .map_err(|e| ChainError::TransactionError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn modify_permission(
        &mut self,
        actor: u64,
        permission: u64,
        authority: &Authority,
        pending_block_time: &TimePoint,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.inner.write()?;
            // Resolve and modify under one write guard; the resolved pointer never
            // escapes this method, so no shared reference is held across the mutation.
            let perm = guard
                .find_permission_by_actor_and_permission(actor, permission)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
            if perm.is_null() {
                return Err(ChainError::InternalError(format!(
                    "permission not found for actor: {} permission: {}",
                    Name::new(actor),
                    Name::new(permission)
                )));
            }
            let perm = unsafe { &*perm };
            let pinned = guard.pin_mut();

            pinned
                .modify_permission(perm, authority, pending_block_time)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let auth_bytes = encode_authority(authority);
            if let Err(e) = s.modify_permission(
                actor,
                permission,
                &auth_bytes,
                pending_block_time.elapsed.count,
            ) {
                eprintln!("arena mirror of modify_permission diverged: {e:?}");
            }
        }
        Ok(())
    }

    pub fn update_permission_usage(
        &mut self,
        actor: u64,
        permission: u64,
        pending_block_time: &TimePoint,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.inner.write()?;
            // Resolve and modify under one write guard; the resolved pointer never
            // escapes this method, so no shared reference is held across the mutation.
            let perm = guard
                .find_permission_by_actor_and_permission(actor, permission)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
            if perm.is_null() {
                return Err(ChainError::InternalError(format!(
                    "permission not found for actor: {} permission: {}",
                    Name::new(actor),
                    Name::new(permission)
                )));
            }
            let perm = unsafe { &*perm };
            let pinned = guard.pin_mut();

            pinned
                .update_permission_usage(perm, pending_block_time)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) =
                s.update_permission_usage(actor, permission, pending_block_time.elapsed.count)
        {
            eprintln!("arena mirror of update_permission_usage diverged: {e:?}");
        }
        Ok(())
    }

    pub fn get_permission_last_used(
        &self,
        permission: &ffi::PermissionObject,
    ) -> Result<TimePoint, ChainError> {
        let guard = self.inner.read()?;
        let res = guard
            .get_permission_last_used(permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn lookup_linked_permission(
        &self,
        account: u64,
        code: u64,
        requirement_type: u64,
    ) -> Result<Option<u64>, ChainError> {
        let guard = self.inner.read()?;
        let res = guard
            .lookup_linked_permission(account, code, requirement_type)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        if res.is_null() {
            return Ok(None);
        }

        Ok(Some(unsafe { &*res }.to_uint64_t()))
    }

    pub fn get_global_properties(&self) -> Result<*const ffi::GlobalPropertyObject, ChainError> {
        let guard = self.inner.read()?;
        let res = guard
            .get_global_properties()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn set_global_properties(&self, cfg: &ChainConfigV0) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .set_global_properties(cfg)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(())
    }

    pub fn get_virtual_block_cpu_limit(&self) -> Result<u64, ChainError> {
        let guard = self.inner.read()?;
        guard
            .get_virtual_block_cpu_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_virtual_block_net_limit(&self) -> Result<u64, ChainError> {
        let guard = self.inner.read()?;
        guard
            .get_virtual_block_net_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_block_cpu_limit(&self) -> Result<u64, ChainError> {
        let guard = self.inner.read()?;
        guard
            .get_block_cpu_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_block_net_limit(&self) -> Result<u64, ChainError> {
        let guard = self.inner.read()?;
        guard
            .get_block_net_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn is_known_unexpired_transaction(
        &self,
        trx_id: &ffi::CxxDigest,
    ) -> Result<bool, ChainError> {
        let guard = self.inner.read()?;

        guard
            .is_known_unexpired_transaction(trx_id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn record_transaction(
        &mut self,
        trx_id: &ffi::CxxDigest,
        expiration: u32,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .record_transaction(trx_id, expiration)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let id = digest_to_array(trx_id);
            if let Err(e) = s.record_transaction(id, expiration) {
                eprintln!("arena mirror of record_transaction diverged: {e:?}");
            }
        }
        Ok(())
    }

    pub fn clear_expired_input_transactions(
        &mut self,
        cutoff: &TimePoint,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.inner.write()?;
            let pinned = guard.pin_mut();
            pinned
                .clear_expired_input_transactions(cutoff)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.clear_expired_input_transactions(cutoff.elapsed.count)
        {
            eprintln!("arena mirror of clear_expired_input_transactions diverged: {e:?}");
        }
        Ok(())
    }

    pub fn get_currency_balance_with_symbol(
        &self,
        code: u64,
        account: u64,
        symbol: &str,
    ) -> Result<String, ChainError> {
        let guard = self.inner.read()?;

        get_currency_balance_with_symbol(guard.as_ref().unwrap(), code, account, symbol)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_currency_balance_without_symbol(
        &self,
        code: u64,
        account: u64,
    ) -> Result<String, ChainError> {
        let guard = self.inner.read()?;

        get_currency_balance_without_symbol(guard.as_ref().unwrap(), code, account)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_currency_stats(&self, code: u64, symbol: &str) -> Result<String, ChainError> {
        let guard = self.inner.read()?;

        get_currency_stats(guard.as_ref().unwrap(), code, symbol)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_table_by_scope(
        &self,
        code: u64,
        table: u64,
        lower_bound: &str,
        upper_bound: &str,
        limit: u32,
        reverse: bool,
    ) -> Result<String, ChainError> {
        let guard = self.inner.read()?;

        get_table_by_scope(
            guard.as_ref().unwrap(),
            code,
            table,
            lower_bound,
            upper_bound,
            limit,
            reverse,
        )
        .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_table_rows(
        &self,
        json: bool,
        code: u64,
        scope: &str,
        table: u64,
        table_key: &str,
        lower_bound: &str,
        upper_bound: &str,
        limit: u32,
        key_type: &str,
        index_position: &str,
        encode_type: &str,
        reverse: bool,
        show_payer: bool,
    ) -> Result<String, ChainError> {
        let guard = self.inner.read()?;

        get_table_rows(
            guard.as_ref().unwrap(),
            json,
            code,
            scope,
            table,
            table_key,
            lower_bound,
            upper_bound,
            limit,
            key_type,
            index_position,
            encode_type,
            reverse,
            show_payer,
        )
        .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_info_without_core_symbol(
        &self,
        account: u64,
        head_block_num: u32,
        head_block_time: &TimePoint,
    ) -> Result<String, ChainError> {
        let guard = self.inner.read()?;

        get_account_info_without_core_symbol(
            guard.as_ref().unwrap(),
            account,
            head_block_num,
            head_block_time,
        )
        .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_info_with_core_symbol(
        &self,
        account: u64,
        expected_core_symbol: &str,
        head_block_num: u32,
        head_block_time: &TimePoint,
    ) -> Result<String, ChainError> {
        let guard = self.inner.read()?;

        get_account_info_with_core_symbol(
            guard.as_ref().unwrap(),
            account,
            expected_core_symbol,
            head_block_num,
            head_block_time,
        )
        .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn pack_deltas(&self, full_snapshot: bool) -> Result<Vec<u8>, ChainError> {
        let guard = self.inner.read()?;

        guard
            .pack_deltas(full_snapshot)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::string_to_name;

    use super::*;

    #[test]
    fn test_database_creation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1 * 1024 * 1024 * 1024).unwrap();
        let name = string_to_name("test").unwrap();
        db.add_indices();
    }

    #[test]
    fn test_pack_deltas() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1 * 1024 * 1024 * 1024).unwrap();
        let name = string_to_name("test").unwrap();
        db.add_indices().unwrap();
        let mut session = db.create_undo_session(true).unwrap();
        let _account = db.create_account(name.to_uint64_t(), 0).unwrap();
        session.pin_mut().push().unwrap();
        let deltas = db.pack_deltas(false).unwrap();
        let hex_deltas = hex::encode(deltas);
        assert_eq!(
            hex_deltas,
            "0100076163636f756e7401010e00000000000090b1ca0000000000"
        );
    }
}

impl Database {
    /// Acquire a read view. The lock is held for the lifetime of the returned
    /// `DbRead`, and every reference it hands out is bound to `&self`, so a
    /// chainbase reference can never outlive the lock or escape the view.
    pub fn read(&self) -> Result<DbRead<'_>, ChainError> {
        Ok(DbRead {
            guard: self.inner.read()?,
        })
    }

    /// Acquire a write view. Exposes the same reads as [`DbRead`] plus mutation,
    /// all under a single write lock, so reads and the mutations that depend on
    /// them share one guard instead of re-locking.
    pub fn write(&self) -> Result<DbWrite<'_>, ChainError> {
        Ok(DbWrite {
            guard: self.inner.write()?,
        })
    }
}

/// Read view over the chainbase database. Holds an [`RwLockReadGuard`] for its
/// lifetime; references returned by its methods borrow `&self` and therefore
/// cannot outlive the held lock.
pub struct DbRead<'g> {
    guard: std::sync::RwLockReadGuard<'g, UniquePtr<ffi::Database>>,
}

impl<'g> DbRead<'g> {
    fn db(&self) -> &ffi::Database {
        &self.guard
    }

    pub fn find_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<Option<&ffi::PermissionObject>, ChainError> {
        let res = self
            .db()
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(unsafe { res.as_ref() })
    }

    pub fn find_permission(&self, id: i64) -> Result<Option<&ffi::PermissionObject>, ChainError> {
        let res = self
            .db()
            .find_permission(id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(unsafe { res.as_ref() })
    }

    pub fn find_account(&self, account_name: u64) -> Result<Option<&ffi::AccountObject>, ChainError> {
        let res = self
            .db()
            .find_account(account_name)
            .map_err(|e| ChainError::InternalError(format!("failed to get account: {}", e)))?;
        Ok(unsafe { res.as_ref() })
    }

    pub fn find_account_metadata(
        &self,
        account_name: u64,
    ) -> Result<Option<&ffi::AccountMetadataObject>, ChainError> {
        let res = self.db().find_account_metadata(account_name).map_err(|e| {
            ChainError::InternalError(format!("failed to find account metadata: {}", e))
        })?;
        Ok(unsafe { res.as_ref() })
    }

    pub fn get_global_properties(&self) -> Result<&ffi::GlobalPropertyObject, ChainError> {
        let res = self
            .db()
            .get_global_properties()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    /// Like [`find_permission_by_actor_and_permission`] but errors when absent.
    pub fn get_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<&ffi::PermissionObject, ChainError> {
        self.find_permission_by_actor_and_permission(actor, permission)?
            .ok_or_else(|| {
                ChainError::InternalError(format!(
                    "permission not found for actor: {} permission: {}",
                    Name::new(actor),
                    Name::new(permission)
                ))
            })
    }

    pub fn permission_satisfies_other_permission(
        &self,
        permission: &ffi::PermissionObject,
        other_permission: &ffi::PermissionObject,
    ) -> Result<bool, ChainError> {
        self.db()
            .permission_satisfies_other_permission(permission, other_permission)
            .map_err(|e| ChainError::TransactionError(format!("{}", e)))
    }

    pub fn get_permission_last_used(
        &self,
        permission: &ffi::PermissionObject,
    ) -> Result<TimePoint, ChainError> {
        self.db()
            .get_permission_last_used(permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn lookup_linked_permission(
        &self,
        account: u64,
        code: u64,
        requirement_type: u64,
    ) -> Result<Option<u64>, ChainError> {
        let res = self
            .db()
            .lookup_linked_permission(account, code, requirement_type)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        if res.is_null() {
            return Ok(None);
        }

        Ok(Some(unsafe { &*res }.to_uint64_t()))
    }
}

/// Write view over the chainbase database. Wraps a write guard and exposes the
/// same reads as [`DbRead`] (via [`DbWrite::reads`]) plus mutating operations.
pub struct DbWrite<'g> {
    guard: std::sync::RwLockWriteGuard<'g, UniquePtr<ffi::Database>>,
}

impl<'g> DbWrite<'g> {
    fn db(&self) -> &ffi::Database {
        &self.guard
    }

    pub fn find_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<Option<&ffi::PermissionObject>, ChainError> {
        let res = self
            .db()
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(unsafe { res.as_ref() })
    }
}

impl Default for Database {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(UniquePtr::null())),
            #[cfg(feature = "arena-shadow")]
            shadow: None,
        }
    }
}

unsafe impl Send for Database {}
unsafe impl Sync for Database {}
