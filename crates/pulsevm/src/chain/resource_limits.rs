use std::{cell::RefCell, collections::HashSet, rc::Rc};

use pulsevm_chainbase::UndoSession;
use wasmtime::Ref;

use crate::chain::UsageAccumulator;

use super::{Name, ResourceLimits, ResourceUsage, error::ChainError, pulse_assert};

pub struct ResourceLimitsManager {}

impl ResourceLimitsManager {
    pub fn initialize_account(session: &mut UndoSession, account: Name) -> Result<(), ChainError> {
        let limits = ResourceLimits::new(account, false, -1, -1, -1);
        session.insert(&limits).map_err(|_| {
            ChainError::TransactionError(format!("failed to insert resource limits"))
        })?;

        let usage = ResourceUsage::new(
            account,
            UsageAccumulator::default(),
            UsageAccumulator::default(),
            0,
        );
        session.insert(&usage).map_err(|_| {
            ChainError::TransactionError(format!("failed to insert resource usage"))
        })?;

        Ok(())
    }

    pub fn add_transaction_usage(
        session: &mut UndoSession,
        accounts: &HashSet<Name>,
        cpu_usage: u64,
        net_usage: u64,
        time_slot: u32,
    ) -> Result<(), ChainError> {
        for account in accounts {
            let mut usage = session.get::<ResourceUsage>(account.clone())?;
            let mut ram_bytes = 0;
            let mut net_weight = 0;
            let mut cpu_weight = 0;
            Self::get_account_limits(
                session,
                account,
                &mut ram_bytes,
                &mut net_weight,
                &mut cpu_weight,
            )?;
        }
        Ok(())
    }

    pub fn add_pending_ram_usage(
        session: &mut UndoSession,
        account: &Name,
        ram_delta: i64,
    ) -> Result<(), ChainError> {
        if ram_delta == 0 {
            return Ok(());
        }
        let mut usage = session.get::<ResourceUsage>(account.clone())?;
        let new_usage: u64;

        if ram_delta < 0 {
            new_usage = usage
                .ram_usage
                .checked_sub(-ram_delta as u64)
                .ok_or_else(|| {
                    ChainError::TransactionError(format!(
                        "ram usage underflow for account {}",
                        account
                    ))
                })?;
        } else {
            new_usage = usage
                .ram_usage
                .checked_add(ram_delta as u64)
                .ok_or_else(|| {
                    ChainError::TransactionError(format!(
                        "ram usage overflow for account {}",
                        account
                    ))
                })?;
        }

        session.modify(&mut usage, |usage| {
            usage.ram_usage = new_usage;
        })?;
        Ok(())
    }

    pub fn verify_account_ram_usage(
        session: &mut UndoSession,
        account: &Name,
    ) -> Result<(), ChainError> {
        let mut ram_bytes: i64 = 0;
        let mut net_weight: i64 = 0;
        let mut cpu_weight: i64 = 0;
        Self::get_account_limits(
            session,
            account,
            &mut ram_bytes,
            &mut net_weight,
            &mut cpu_weight,
        )?;
        let usage = session.get::<ResourceUsage>(account.clone())?;
        if ram_bytes >= 0 {
            pulse_assert(
                usage.ram_usage <= ram_bytes as u64,
                ChainError::TransactionError(format!(
                    "account {} has insufficient ram; needs {} bytes has {} bytes",
                    account, usage.ram_usage, ram_bytes
                )),
            )?;
        }
        Ok(())
    }

    pub fn get_account_ram_usage(
        session: &mut UndoSession,
        account: &Name,
    ) -> Result<u64, ChainError> {
        let usage = session.get::<ResourceUsage>(account.clone())?;
        Ok(usage.ram_usage)
    }

    pub fn set_account_limits(
        session: &mut UndoSession,
        account: &Name,
        net_weight: i64,
        cpu_weight: i64,
        ram_bytes: i64,
    ) -> Result<bool, ChainError> {
        /*
         * Since we need to delay these until the next resource limiting boundary, these are created in a "pending"
         * state or adjusted in an existing "pending" state.  The chain controller will collapse "pending" state into
         * the actual state at the next appropriate boundary.
         */
        let mut limits = {
            let pending_limits = session.find::<ResourceLimits>((true, account.clone()))?;

            if let Some(limits) = pending_limits {
                limits
            } else {
                let limits = session.get::<ResourceLimits>((false, account.clone()))?;
                let pending_limits = ResourceLimits::new(
                    account.clone(),
                    true,
                    limits.net_weight,
                    limits.cpu_weight,
                    limits.ram_bytes,
                );
                session.insert(&pending_limits)?;
                pending_limits
            }
        };

        let mut decreased_limit = false;

        if ram_bytes >= 0 {
            decreased_limit = (limits.ram_bytes < 0) || (ram_bytes < limits.ram_bytes);
        }

        session.modify(&mut limits, |limits| {
            limits.net_weight = net_weight;
            limits.cpu_weight = cpu_weight;
            limits.ram_bytes = ram_bytes;
        })?;

        Ok(decreased_limit)
    }

    pub fn get_account_limits(
        session: &mut UndoSession,
        account: &Name,
        ram_bytes: &mut i64,
        net_weight: &mut i64,
        cpu_weight: &mut i64,
    ) -> Result<(), ChainError> {
        let limits = session.find::<ResourceLimits>((true, account.clone()))?;
        if let Some(limits) = limits {
            *ram_bytes = limits.ram_bytes;
            *net_weight = limits.net_weight;
            *cpu_weight = limits.cpu_weight;
            return Ok(());
        }

        let limits = session.find::<ResourceLimits>((false, account.clone()))?;
        if let Some(limits) = limits {
            *ram_bytes = limits.ram_bytes;
            *net_weight = limits.net_weight;
            *cpu_weight = limits.cpu_weight;
            return Ok(());
        }

        Err(ChainError::TransactionError(format!(
            "resource limits for account {} not found",
            account
        )))
    }

    pub fn is_unlimited_cpu(session: &mut UndoSession, account: &Name) -> Result<bool, ChainError> {
        let limits = session.find::<ResourceLimits>((false, account.clone()))?;
        if let Some(limits) = limits {
            return Ok(limits.cpu_weight < 0);
        }

        Ok(false)
    }
}
