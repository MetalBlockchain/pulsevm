use std::collections::HashSet;

use pulsevm_chainbase::{ChainbaseObject, SecondaryKey, UndoSession};

use crate::chain::{integer_divide_ceil, AccountResourceLimit, BlockTimestamp, Ratio, ResourceLimitsConfig, ResourceLimitsState, UsageAccumulator, RATE_LIMITING_PRECISION};

use super::{Name, ResourceLimits, ResourceUsage, error::ChainError, pulse_assert};

pub struct ResourceLimitsManager {}

impl ResourceLimitsManager {
    pub fn initialize_database(session: &mut UndoSession) -> Result<(), ChainError> {
        let config = ResourceLimitsConfig::default();
        session.insert(&config).map_err(|_| {
            ChainError::TransactionError(format!("failed to insert resource limits config"))
        })?;

        let mut state = ResourceLimitsState::default();
        state.virtual_cpu_limit = config.cpu_limit_parameters.max;
        state.virtual_net_limit = config.net_limit_parameters.max;
        session.insert(&state).map_err(|_| {
            ChainError::TransactionError(format!("failed to insert resource limits state"))
        })?;

        Ok(())
    }

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

    pub fn get_account_net_limit(
        session: &mut UndoSession,
        account: &Name,
        current_time: Option<BlockTimestamp>,
    ) -> Result<AccountResourceLimit, ChainError> {
        let config = session.get::<ResourceLimitsConfig>(0)?;
        let state = session.get::<ResourceLimitsState>(0)?;
        let usage = session.get::<ResourceUsage>(account.clone())?;

        let mut net_weight: i64 = 0;
        let mut _x: i64 = 0;
        let mut _y: i64 = 0;
        Self::get_account_limits(session, account, &mut _x, &mut net_weight, &mut _y)?;

        if net_weight < 0 || state.total_net_weight == 0 {
            return Ok(AccountResourceLimit::new(-1, -1, -1, BlockTimestamp::new(usage.net_usage.last_ordinal), -1));
        }

        let mut arl = AccountResourceLimit::default();
        let window_size: u128 = config.account_net_usage_average_window as u128;
        let virtual_network_capacity_in_window: u128 = window_size * state.virtual_net_limit as u128;
        let user_weight: u128 = net_weight as u128;
        let all_user_weight: u128 = state.total_net_weight as u128;

        let max_user_use_in_window = (virtual_network_capacity_in_window * user_weight) / all_user_weight;
        let net_used_in_window = integer_divide_ceil(usage.net_usage.value_ex as u128 * window_size, RATE_LIMITING_PRECISION as u128);

        if max_user_use_in_window <= net_used_in_window {
            arl.available = 0;
        } else {
            arl.available = (max_user_use_in_window - net_used_in_window) as i64;
        }

        arl.used = net_used_in_window as i64;
        arl.max = max_user_use_in_window as i64;
        arl.last_usage_update_time = BlockTimestamp::new(usage.net_usage.last_ordinal);
        arl.current_used = arl.used;

        if let Some(current_time) = current_time {
            if current_time.slot > usage.net_usage.last_ordinal {
                let mut history_usage = usage.net_usage.clone();
                history_usage.add(0, current_time.slot, window_size as u64)?;
                arl.current_used = integer_divide_ceil(history_usage.value_ex as u128 * window_size, RATE_LIMITING_PRECISION as u128) as i64;
            }
        }

        Ok(arl)
    }

    pub fn get_account_cpu_limit(
        session: &mut UndoSession,
        account: &Name,
        current_time: Option<BlockTimestamp>,
    ) -> Result<AccountResourceLimit, ChainError> {
        let config = session.get::<ResourceLimitsConfig>(0)?;
        let state = session.get::<ResourceLimitsState>(0)?;
        let usage = session.get::<ResourceUsage>(account.clone())?;

        let mut cpu_weight: i64 = 0;
        let mut _x: i64 = 0;
        let mut _y: i64 = 0;
        Self::get_account_limits(session, account, &mut _x, &mut _y, &mut cpu_weight)?;

        if cpu_weight < 0 || state.total_cpu_weight == 0 {
            return Ok(AccountResourceLimit::new(-1, -1, -1, BlockTimestamp::new(usage.cpu_usage.last_ordinal), -1));
        }

        let mut arl = AccountResourceLimit::default();
        let window_size: u128 = config.account_cpu_usage_average_window as u128;
        let virtual_cpu_capacity_in_window: u128 = window_size * state.virtual_cpu_limit as u128;
        let user_weight: u128 = cpu_weight as u128;
        let all_user_weight: u128 = state.total_cpu_weight as u128;

        let max_user_use_in_window = (virtual_cpu_capacity_in_window * user_weight) / all_user_weight;
        let cpu_used_in_window = integer_divide_ceil(usage.cpu_usage.value_ex as u128 * window_size, RATE_LIMITING_PRECISION as u128);

        if max_user_use_in_window <= cpu_used_in_window {
            arl.available = 0;
        } else {
            arl.available = (max_user_use_in_window - cpu_used_in_window) as i64;
        }

        arl.used = cpu_used_in_window as i64;
        arl.max = max_user_use_in_window as i64;
        arl.last_usage_update_time = BlockTimestamp::new(usage.cpu_usage.last_ordinal);
        arl.current_used = arl.used;

        if let Some(current_time) = current_time {
            if current_time.slot > usage.cpu_usage.last_ordinal {
                let mut history_usage = usage.cpu_usage.clone();
                history_usage.add(0, current_time.slot, window_size as u64)?;
                arl.current_used = integer_divide_ceil(history_usage.value_ex as u128 * window_size, RATE_LIMITING_PRECISION as u128) as i64;
            }
        }

        Ok(arl)
    }
}