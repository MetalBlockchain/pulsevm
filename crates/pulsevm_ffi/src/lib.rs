mod bridge;
mod block_log;
use std::{collections::HashSet, sync::{Arc, RwLock}};

use bridge::ffi as ffi;

use crate::bridge::ffi::{Name, name_to_uint64};

pub struct Database {
    inner: cxx::UniquePtr<ffi::Database>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self, String> {
        let db = ffi::open_database(path, ffi::DatabaseOpenFlags::ReadWrite, 20*1024*1024*1024);

        if db.is_null() {
            Err("Failed to open database".to_string())
        } else {
            Ok(Database { inner: db })
        }
    }

    pub fn add_indices(&mut self) {
        self.inner.pin_mut().add_indices();
    }

    pub fn add_account(&mut self, account_name: &Name) {
        self.inner.pin_mut().add_account(account_name);
    }

    pub fn get_account(&mut self) -> Result<cxx::UniquePtr<ffi::Account>, String> {
        let account = self.inner.pin_mut().get_account().map_err(
            |e| format!("Failed to get account: {}", e)
        )?;
        Ok(account)
    }

    pub fn create_undo_session(&mut self, enabled: bool) -> Result<cxx::UniquePtr<ffi::UndoSession>, String> {
        self.inner.pin_mut().create_undo_session(enabled).map_err(|e| format!("Failed to create undo session: {}", e))
    }

    pub fn initialize_resource_limits(&mut self) -> Result<(), String> {
        self.inner.pin_mut().initialize_resource_limits().map_err(|e| format!("Failed to initialize resource limits: {}", e))
    }

    pub fn initialize_account_resource_limits(&mut self, account_name: &Name) -> Result<(), String> {
        self.inner.pin_mut().initialize_account_resource_limits(account_name).map_err(|e| format!("Failed to initialize account resource limits: {}", e))
    }

    pub fn add_transaction_usage(
        &mut self,
        accounts: &HashSet<Name>,
        cpu_usage: u64,
        net_usage: u64,
        time_slot: u32,
    ) -> Result<(), String> {
        let accounts_vec: Vec<u64> = accounts.iter().map(|name| name_to_uint64(name)).collect();
        self.inner.pin_mut().add_transaction_usage(&accounts_vec, cpu_usage, net_usage, time_slot).map_err(|e| format!("Failed to add transaction usage: {}", e))
    }

    pub fn add_pending_ram_usage(&mut self, account_name: &Name, ram_bytes: i64) -> Result<(), String> {
        self.inner.pin_mut().add_pending_ram_usage(account_name, ram_bytes).map_err(|e| format!("Failed to add pending ram usage: {}", e))
    }

    pub fn verify_account_ram_usage(&mut self,  account_name: &Name) -> Result<(), String> {
        self.inner.pin_mut().verify_account_ram_usage(account_name).map_err(|e| format!("Failed to verify account ram usage: {}", e))
    }

    pub fn get_account_ram_usage(&mut self, account_name: &Name) -> Result<i64, String> {
        self.inner.pin_mut().get_account_ram_usage(account_name).map_err(|e| format!("Failed to get account ram usage: {}", e))
    }

    pub fn set_account_limits(&mut self, account_name: &Name, ram_bytes: i64, net_weight: i64, cpu_weight: i64) -> Result<bool, String> {
        self.inner.pin_mut().set_account_limits(account_name, ram_bytes, net_weight, cpu_weight).map_err(|e| format!("Failed to set account limits: {}", e))
    }

    pub fn get_account_limits(&mut self, account_name: &Name, ram_bytes: &mut i64, net_weight: &mut i64, cpu_weight: &mut i64) -> Result<(), String> {
        self.inner.pin_mut().get_account_limits(account_name, ram_bytes, net_weight, cpu_weight).map_err(|e| format!("Failed to get account limits: {}", e))
    }

    pub fn get_total_cpu_weight(&mut self) -> Result<u64, String> {
        self.inner.pin_mut().get_total_cpu_weight().map_err(|e| format!("Failed to get total cpu weight: {}", e))
    }

    pub fn get_total_net_weight(&mut self) -> Result<u64, String> {
        self.inner.pin_mut().get_total_net_weight().map_err(|e| format!("Failed to get total net weight: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::{TempDir, env::temp_dir};

    use super::*;

    #[test]
    fn test_database_creation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path).unwrap();
        db.add_indices();
        //db.add_account(123);
        let account = db.get_account().unwrap();
    }
}