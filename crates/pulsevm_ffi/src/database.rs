use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};

use cxx::UniquePtr;
use pulsevm_error::ChainError;

use crate::{
    AccountMetadataObject, KeyValueObject,
    bridge::ffi::{
        self, Authority, CxxDigest, CxxGenesisState, CxxTimePoint, TableObject,
        get_account_info_with_core_symbol, get_account_info_without_core_symbol,
        get_currency_balance_with_symbol, get_currency_balance_without_symbol, get_currency_stats,
        get_table_rows,
    },
    iterator_cache::KeyValueIteratorCache,
};

#[derive(Clone)]
pub struct Database {
    inner: Arc<RwLock<UniquePtr<ffi::Database>>>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self, String> {
        let db = ffi::open_database(
            path,
            ffi::DatabaseOpenFlags::ReadWrite,
            20 * 1024 * 1024 * 1024,
        );

        if db.is_null() {
            Err("Failed to open database".to_string())
        } else {
            Ok(Database {
                inner: Arc::new(RwLock::new(db)),
            })
        }
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
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        let acct_ref = pinned
            .create_account(account_name, creation_date)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(acct_ref as *const ffi::AccountObject)
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
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .create_account_metadata(account_name, is_privileged)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res as *const ffi::AccountMetadataObject)
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
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .set_privileged(account, is_privileged)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
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
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .unlink_account_code(old_code_entry)
            .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))
    }

    pub fn update_account_code(
        &mut self,
        account: &ffi::AccountMetadataObject,
        new_code: &[u8],
        head_block_num: u32,
        pending_block_time: &CxxTimePoint,
        code_hash: &CxxDigest,
        vm_type: u8,
        vm_version: u8,
    ) -> Result<(), ChainError> {
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
            .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))
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

    pub fn add_transaction_usage(
        &mut self,
        accounts: &HashSet<u64>,
        cpu_usage: u64,
        net_usage: u64,
        time_slot: u32,
    ) -> Result<(), ChainError> {
        let accounts_vec: Vec<u64> = accounts.iter().map(|name| name.clone()).collect();
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .add_transaction_usage(&accounts_vec, cpu_usage, net_usage, time_slot)
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
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .create_table(code, scope, table, payer)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res as *const TableObject)
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

        unsafe { pinned.db_find_i64(code, scope, table, id, keyval_cache.pin_mut()) }
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_key_value_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        buffer: &[u8],
    ) -> Result<*const KeyValueObject, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .create_key_value_object(table, payer, id, buffer)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res as *const KeyValueObject)
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

    pub fn remove_table(&mut self, table: &TableObject) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .remove_table(table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
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
                actor, permission
            )));
        }

        Ok(res)
    }

    pub fn delete_auth(&mut self, account: u64, permission_name: u64) -> Result<i64, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .delete_auth(account, permission_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn link_auth(
        &mut self,
        account_name: u64,
        code_name: u64,
        requirement_name: u64,
        requirement_type: u64,
    ) -> Result<i64, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .link_auth(account_name, code_name, requirement_name, requirement_type)
            .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))
    }

    pub fn unlink_auth(
        &mut self,
        account_name: u64,
        code_name: u64,
        requirement_type: u64,
    ) -> Result<i64, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .unlink_auth(account_name, code_name, requirement_type)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
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
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .next_global_sequence()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_remove_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<i64, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_remove_i64(keyval_cache.pin_mut(), iterator, receiver)
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
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .remove_permission(permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_permission(
        &mut self,
        account: u64,
        name: u64,
        parent: u64,
        auth: &Authority,
        creation_time: &CxxTimePoint,
    ) -> Result<*const ffi::PermissionObject, ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .create_permission(account, name, parent, auth, creation_time)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res as *const ffi::PermissionObject)
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
        permission: &ffi::PermissionObject,
        authority: &Authority,
        pending_block_time: &CxxTimePoint,
    ) -> Result<(), ChainError> {
        let mut guard = self.inner.write()?;
        let pinned = guard.pin_mut();

        pinned
            .modify_permission(permission, authority, pending_block_time)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
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
        head_block_time: &CxxTimePoint,
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
        head_block_time: &CxxTimePoint,
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
        let mut db = Database::new(path).unwrap();
        let name = string_to_name("test").unwrap();
        db.add_indices();
    }
}

impl Default for Database {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(UniquePtr::null())),
        }
    }
}

unsafe impl Send for Database {}
unsafe impl Sync for Database {}
