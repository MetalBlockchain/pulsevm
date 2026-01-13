use std::{
    cell::RefCell,
    collections::HashSet,
    rc::Rc,
    sync::{Arc, RwLock},
};

use cxx::{SharedPtr, UniquePtr};
use pulsevm_error::ChainError;

use crate::{
    KeyValueIteratorCache, Name,
    bridge::ffi::{self, Table},
    iterator_cache::ffi::KeyValue,
};

#[derive(Clone)]
pub struct Database {
    inner: SharedPtr<ffi::Database>,
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
            Ok(Database { inner: db })
        }
    }

    pub fn add_indices(&mut self) {
        unsafe {
            self.inner.pin_mut_unchecked().add_indices();
        }
    }

    pub fn create_account(
        &mut self,
        account_name: &Name,
        creation_date: u32,
    ) -> Result<&ffi::Account, ChainError> {
        unsafe {
            self.inner
                .pin_mut_unchecked()
                .create_account(account_name, creation_date)
                .map_err(|e| {
                    ChainError::InternalError(Some(format!("Failed to create account: {}", e)))
                })
        }
    }

    pub fn find_account(
        &mut self,
        account_name: &Name,
    ) -> Result<Option<&ffi::Account>, ChainError> {
        let account = unsafe { self.inner.pin_mut_unchecked().find_account(account_name) }
            .map_err(|e| {
                ChainError::InternalError(Some(format!("Failed to get account: {}", e)))
            })?;

        if account.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { &*account }))
        }
    }

    pub fn get_account(&mut self, account_name: &Name) -> Result<&ffi::Account, ChainError> {
        match self.find_account(account_name)? {
            Some(account) => Ok(account),
            None => Err(ChainError::InternalError(Some(format!(
                "Account not found"
            )))),
        }
    }

    pub fn create_account_metadata(
        &mut self,
        account_name: &Name,
        is_privileged: bool,
    ) -> Result<&ffi::AccountMetadata, ChainError> {
        unsafe {
            self.inner
                .pin_mut_unchecked()
                .create_account_metadata(account_name, is_privileged)
                .map_err(|e| {
                    ChainError::InternalError(Some(format!(
                        "Failed to create account metadata: {}",
                        e
                    )))
                })
        }
    }

    pub fn find_account_metadata(
        &mut self,
        account_name: &Name,
    ) -> Result<Option<&ffi::AccountMetadata>, ChainError> {
        let account_metadata = unsafe {
            self.inner
                .pin_mut_unchecked()
                .find_account_metadata(account_name)
        }
        .map_err(|e| ChainError::InternalError(Some(format!("Failed to get account: {}", e))))?;

        if account_metadata.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { &*account_metadata }))
        }
    }

    pub fn get_account_metadata(
        &mut self,
        account_name: &Name,
    ) -> Result<&ffi::AccountMetadata, ChainError> {
        match self.find_account_metadata(account_name)? {
            Some(account_metadata) => Ok(account_metadata),
            None => Err(ChainError::InternalError(Some(format!(
                "Account metadata not found"
            )))),
        }
    }

    pub fn create_undo_session(
        &mut self,
        enabled: bool,
    ) -> Result<cxx::UniquePtr<ffi::UndoSession>, ChainError> {
        unsafe { self.inner.pin_mut_unchecked().create_undo_session(enabled) }
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn initialize_resource_limits(&mut self) -> Result<(), ChainError> {
        unsafe { self.inner.pin_mut_unchecked().initialize_resource_limits() }
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn initialize_account_resource_limits(
        &mut self,
        account_name: &Name,
    ) -> Result<(), ChainError> {
        unsafe {
            self.inner
                .pin_mut_unchecked()
                .initialize_account_resource_limits(account_name)
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn add_transaction_usage(
        &mut self,
        accounts: &HashSet<Name>,
        cpu_usage: u64,
        net_usage: u64,
        time_slot: u32,
    ) -> Result<(), ChainError> {
        let accounts_vec: Vec<u64> = accounts.iter().map(|name| name.to_uint64_t()).collect();
        unsafe {
            self.inner.pin_mut_unchecked().add_transaction_usage(
                &accounts_vec,
                cpu_usage,
                net_usage,
                time_slot,
            )
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn add_pending_ram_usage(
        &mut self,
        account_name: &Name,
        ram_bytes: i64,
    ) -> Result<(), ChainError> {
        unsafe {
            self.inner
                .pin_mut_unchecked()
                .add_pending_ram_usage(account_name, ram_bytes)
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn verify_account_ram_usage(&mut self, account_name: &Name) -> Result<(), ChainError> {
        unsafe {
            self.inner
                .pin_mut_unchecked()
                .verify_account_ram_usage(account_name)
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn get_account_ram_usage(&mut self, account_name: &Name) -> Result<i64, ChainError> {
        unsafe {
            self.inner
                .pin_mut_unchecked()
                .get_account_ram_usage(account_name)
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn set_account_limits(
        &mut self,
        account_name: &Name,
        ram_bytes: i64,
        net_weight: i64,
        cpu_weight: i64,
    ) -> Result<bool, ChainError> {
        unsafe {
            self.inner.pin_mut_unchecked().set_account_limits(
                account_name,
                ram_bytes,
                net_weight,
                cpu_weight,
            )
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn get_account_limits(
        &mut self,
        account_name: &Name,
        ram_bytes: &mut i64,
        net_weight: &mut i64,
        cpu_weight: &mut i64,
    ) -> Result<(), ChainError> {
        unsafe {
            self.inner.pin_mut_unchecked().get_account_limits(
                account_name,
                ram_bytes,
                net_weight,
                cpu_weight,
            )
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn get_total_cpu_weight(&mut self) -> Result<u64, ChainError> {
        unsafe { self.inner.pin_mut_unchecked().get_total_cpu_weight() }
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn get_total_net_weight(&mut self) -> Result<u64, ChainError> {
        unsafe { self.inner.pin_mut_unchecked().get_total_net_weight() }
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn get_account_net_limit(
        &mut self,
        name: &Name,
        greylist_limit: u32,
    ) -> Result<ffi::NetLimitResult, ChainError> {
        unsafe {
            self.inner
                .pin_mut_unchecked()
                .get_account_net_limit(name, greylist_limit)
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn get_account_cpu_limit(
        &mut self,
        name: &Name,
        greylist_limit: u32,
    ) -> Result<ffi::CpuLimitResult, ChainError> {
        unsafe {
            self.inner
                .pin_mut_unchecked()
                .get_account_cpu_limit(name, greylist_limit)
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn process_account_limit_updates(&mut self) -> Result<(), ChainError> {
        unsafe {
            self.inner
                .pin_mut_unchecked()
                .process_account_limit_updates()
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn get_table(
        &mut self,
        code: &Name,
        scope: &Name,
        table: &Name,
    ) -> Result<&Table, ChainError> {
        unsafe { self.inner.pin_mut_unchecked().get_table(code, scope, table) }
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn create_table(
        &mut self,
        code: &Name,
        scope: &Name,
        table: &Name,
        payer: &Name,
    ) -> Result<&Table, ChainError> {
        unsafe {
            self.inner
                .pin_mut_unchecked()
                .create_table(code, scope, table, payer)
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn db_find_i64(
        &mut self,
        code: &Name,
        scope: &Name,
        table: &Name,
        id: u64,
        keyval_cache: &mut KeyValueIteratorCache,
    ) -> Result<i32, ChainError> {
        unsafe {
            self.inner.pin_mut_unchecked().db_find_i64(
                code,
                scope,
                table,
                id,
                keyval_cache.pin_mut(),
            )
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn create_key_value_object(
        &mut self,
        table: &Table,
        payer: &Name,
        id: u64,
        buffer: &[u8],
    ) -> Result<&KeyValue, ChainError> {
        unsafe {
            self.inner
                .pin_mut_unchecked()
                .create_key_value_object(table, payer, id, buffer)
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn update_key_value_object(
        &mut self,
        obj: &KeyValue,
        payer: &Name,
        buffer: &[u8],
    ) -> Result<(), ChainError> {
        unsafe {
            self.inner
                .pin_mut_unchecked()
                .update_key_value_object(obj, payer, buffer)
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn remove_key_value_object(
        &mut self,
        obj: &KeyValue,
        table_obj: &Table,
    ) -> Result<(), ChainError> {
        unsafe {
            self.inner
                .pin_mut_unchecked()
                .remove_key_value_object(obj, table_obj)
        }
        .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn remove_table(&mut self, table: &Table) -> Result<(), ChainError> {
        unsafe { self.inner.pin_mut_unchecked().remove_table(table) }
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn is_account(&self, account: &Name) -> Result<bool, ChainError> {
        self.inner
            .is_account(account)
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn find_permission(&self, id: i64) -> Result<Option<&ffi::PermissionObject>, ChainError> {
        let res = self
            .inner
            .find_permission(id)
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))?;

        if res.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { &*res }))
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::{TempDir, env::temp_dir};

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
            inner: SharedPtr::null(),
        }
    }
}
