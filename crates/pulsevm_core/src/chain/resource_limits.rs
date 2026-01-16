use std::collections::HashSet;

use pulsevm_error::ChainError;
use pulsevm_ffi::{Database, Name};

pub struct ResourceLimitsManager;

impl ResourceLimitsManager {
    pub fn initialize_database(db: &mut Database) -> Result<(), ChainError> {
        db.initialize_resource_limits()
    }

    pub fn initialize_account(db: &mut Database, account: &Name) -> Result<(), ChainError> {
        db.initialize_account_resource_limits(account)
            .map_err(|e| {
                ChainError::DatabaseError(format!(
                    "failed to initialize resource limits for account {}: {}",
                    account, e
                ))
            })?;
        Ok(())
    }

    pub fn add_transaction_usage(
        db: &mut Database,
        accounts: &HashSet<Name>,
        cpu_usage: u64,
        net_usage: u64,
        time_slot: u32,
    ) -> Result<(), ChainError> {
        db.add_transaction_usage(accounts, cpu_usage, net_usage, time_slot)
            .map_err(|e| {
                ChainError::DatabaseError(format!(
                    "failed to add transaction usage for accounts: {}",
                    e
                ))
            })?;
        Ok(())
    }

    pub fn add_pending_ram_usage(
        db: &mut Database,
        account: &Name,
        ram_delta: i64,
    ) -> Result<(), ChainError> {
        db.add_pending_ram_usage(account, ram_delta).map_err(|e| {
            ChainError::DatabaseError(format!(
                "failed to add pending ram usage for account {}: {}",
                account, e
            ))
        })?;
        Ok(())
    }

    pub fn verify_account_ram_usage(
        db: &mut Database,
        account_name: &Name,
    ) -> Result<(), ChainError> {
        db.verify_account_ram_usage(account_name).map_err(|e| {
            ChainError::DatabaseError(format!(
                "failed to verify ram usage for account {}: {}",
                account_name, e
            ))
        })?;
        Ok(())
    }

    pub fn get_account_ram_usage(db: &mut Database, account: &Name) -> Result<i64, ChainError> {
        match db.get_account_ram_usage(account) {
            Ok(usage) => Ok(usage),
            Err(e) => Err(ChainError::DatabaseError(format!(
                "failed to get ram usage for account {}: {}",
                account, e
            ))),
        }
    }

    pub fn set_account_limits(
        db: &mut Database,
        account: &Name,
        net_weight: i64,
        cpu_weight: i64,
        ram_bytes: i64,
    ) -> Result<bool, ChainError> {
        match db.set_account_limits(account, ram_bytes, net_weight, cpu_weight) {
            Ok(decreased) => Ok(decreased),
            Err(e) => Err(ChainError::DatabaseError(format!(
                "failed to set resource limits for account {}: {}",
                account, e
            ))),
        }
    }

    pub fn get_account_limits(
        db: &mut Database,
        account: &Name,
        ram_bytes: &mut i64,
        net_weight: &mut i64,
        cpu_weight: &mut i64,
    ) -> Result<(), ChainError> {
        db.get_account_limits(account, ram_bytes, net_weight, cpu_weight)
            .map_err(|e| {
                ChainError::DatabaseError(format!(
                    "failed to get resource limits for account {}: {}",
                    account, e
                ))
            })?;

        Ok(())
    }

    pub fn get_account_net_limit(
        db: &mut Database,
        account: &Name,
        greylist_limit: Option<u32>,
    ) -> Result<(i64, bool), ChainError> {
        let res = db
            .get_account_net_limit(account, greylist_limit)
            .map_err(|e| {
                ChainError::DatabaseError(format!(
                    "failed to get net limit for account {}: {}",
                    account, e
                ))
            })?;

        Ok((res.limit, res.greylisted))
    }

    pub fn get_account_cpu_limit(
        db: &mut Database,
        account: &Name,
        greylist_limit: Option<u32>,
    ) -> Result<(i64, bool), ChainError> {
        let res = db
            .get_account_cpu_limit(account, greylist_limit)
            .map_err(|e| {
                ChainError::DatabaseError(format!(
                    "failed to get cpu limit for account {}: {}",
                    account, e
                ))
            })?;

        Ok((res.limit, res.greylisted))
    }

    pub fn process_account_limit_updates(db: &mut Database) -> Result<(), ChainError> {
        db.process_account_limit_updates().map_err(|e| {
            ChainError::DatabaseError(format!("failed to process account limit updates: {}", e))
        })?;
        Ok(())
    }

    pub fn get_total_cpu_weight(db: &mut Database) -> Result<u64, ChainError> {
        match db.get_total_cpu_weight() {
            Ok(weight) => Ok(weight),
            Err(e) => Err(ChainError::DatabaseError(format!(
                "failed to get total cpu weight: {}",
                e
            ))),
        }
    }

    pub fn get_total_net_weight(db: &mut Database) -> Result<u64, ChainError> {
        match db.get_total_net_weight() {
            Ok(weight) => Ok(weight),
            Err(e) => Err(ChainError::DatabaseError(format!(
                "failed to get total net weight: {}",
                e
            ))),
        }
    }
}
