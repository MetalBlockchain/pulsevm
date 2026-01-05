use std::collections::HashSet;

use pulsevm_ffi::Database;

use crate::chain::{
    block::BlockTimestamp,
    config::RATE_LIMITING_PRECISION,
    error::ChainError,
    name::Name,
    resource::{
        AccountResourceLimit, ElasticLimitParameters, ResourceLimits, ResourceLimitsByOwnerIndex,
        ResourceLimitsConfig, ResourceLimitsState, ResourceUsage,
    },
    utils::{UsageAccumulator, integer_divide_ceil, pulse_assert},
};

pub struct ResourceLimitsManager {}

impl ResourceLimitsManager {
    pub fn initialize_database(db: &mut Database) -> Result<(), ChainError> {
        db.initialize_resource_limits().map_err(|e| {
            ChainError::DatabaseError(format!("failed to initialize resource limits: {}", e))
        })?;
    }

    pub fn initialize_account(db: &mut Database, account: Name) -> Result<(), ChainError> {
        db.initialize_account_resource_limits(account.as_u64()).map_err(|e| {
            ChainError::DatabaseError(format!(
                "failed to initialize resource limits for account {}: {}",
                account, e
            ))
        })?;
    }

    pub fn add_transaction_usage(
        db: &mut Database,
        accounts: &HashSet<Name>,
        cpu_usage: u64,
        net_usage: u64,
        time_slot: u32,
    ) -> Result<(), ChainError> {
        db.add_transaction_usage(accounts, cpu_usage, net_usage, time_slot).map_err(|e| {
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

    pub fn get_account_ram_usage(
        db: &mut Database,
        account: &Name,
    ) -> Result<i64, ChainError> {
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
        db.get_account_limits(account, ram_bytes, net_weight, cpu_weight).map_err(|e| {
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
            return Ok(AccountResourceLimit::new(
                -1,
                -1,
                -1,
                BlockTimestamp::new(usage.net_usage.last_ordinal),
                -1,
            ));
        }

        let mut arl = AccountResourceLimit::default();
        let window_size: u128 = config.account_net_usage_average_window as u128;
        let virtual_network_capacity_in_window: u128 =
            window_size * state.virtual_net_limit as u128;
        let user_weight: u128 = net_weight as u128;
        let all_user_weight: u128 = state.total_net_weight as u128;

        let max_user_use_in_window =
            (virtual_network_capacity_in_window * user_weight) / all_user_weight;
        let net_used_in_window = integer_divide_ceil(
            usage.net_usage.value_ex as u128 * window_size,
            RATE_LIMITING_PRECISION as u128,
        );

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
                arl.current_used = integer_divide_ceil(
                    history_usage.value_ex as u128 * window_size,
                    RATE_LIMITING_PRECISION as u128,
                ) as i64;
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
            return Ok(AccountResourceLimit::new(
                -1,
                -1,
                -1,
                BlockTimestamp::new(usage.cpu_usage.last_ordinal),
                -1,
            ));
        }

        let mut arl = AccountResourceLimit::default();
        let window_size: u128 = config.account_cpu_usage_average_window as u128;
        let virtual_cpu_capacity_in_window: u128 = window_size * state.virtual_cpu_limit as u128;
        let user_weight: u128 = cpu_weight as u128;
        let all_user_weight: u128 = state.total_cpu_weight as u128;

        let max_user_use_in_window =
            (virtual_cpu_capacity_in_window * user_weight) / all_user_weight;
        let cpu_used_in_window = integer_divide_ceil(
            usage.cpu_usage.value_ex as u128 * window_size,
            RATE_LIMITING_PRECISION as u128,
        );

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
                arl.current_used = integer_divide_ceil(
                    history_usage.value_ex as u128 * window_size,
                    RATE_LIMITING_PRECISION as u128,
                ) as i64;
            }
        }

        Ok(arl)
    }

    pub fn process_account_limit_updates(session: &mut UndoSession) -> Result<(), ChainError> {
        let mut by_owner_index = session.get_index::<ResourceLimits, ResourceLimitsByOwnerIndex>();
        let mut itr = by_owner_index.lower_bound(true)?;

        let update_state_and_value =
            |total: &mut u64, value: &mut i64, pending_value: i64| -> Result<(), ChainError> {
                if *value > 0 {
                    *total =
                        total
                            .checked_sub(*value as u64)
                            .ok_or(ChainError::TransactionError(
                                "underflow when reverting old value".to_owned(),
                            ))?;
                }

                if pending_value > 0 {
                    *total = total.checked_add(pending_value as u64).ok_or(
                        ChainError::TransactionError("overflow when applying new value".to_owned()),
                    )?;
                }

                *value = pending_value;

                Ok(())
            };

        let state = session.get::<ResourceLimitsState>(0)?;
        let mut total_ram_bytes = state.total_ram_bytes;
        let mut total_cpu_weight = state.total_cpu_weight;
        let mut total_net_weight = state.total_net_weight;

        while let Some(pending_limit) = itr.next()? {
            if !pending_limit.pending {
                break;
            }

            let mut actual_limits = session
                .get_by_secondary::<ResourceLimits, ResourceLimitsByOwnerIndex>((
                    false,
                    pending_limit.owner.clone(),
                ))?;
            let mut new_ram_bytes = actual_limits.ram_bytes;
            let mut new_cpu_weight = actual_limits.cpu_weight;
            let mut new_net_weight = actual_limits.net_weight;
            update_state_and_value(
                &mut total_ram_bytes,
                &mut new_ram_bytes,
                pending_limit.ram_bytes,
            )?;
            update_state_and_value(
                &mut total_cpu_weight,
                &mut new_cpu_weight,
                pending_limit.cpu_weight,
            )?;
            update_state_and_value(
                &mut total_net_weight,
                &mut new_net_weight,
                pending_limit.net_weight,
            )?;

            session.modify(&mut actual_limits, |rlo| {
                rlo.ram_bytes = new_ram_bytes;
                rlo.cpu_weight = new_cpu_weight;
                rlo.net_weight = new_net_weight;
                Ok(())
            })?;
            session.remove(pending_limit)?;
        }

        Ok(())
    }

    pub fn set_block_parameters(
        session: &mut UndoSession,
        cpu_limit_parameters: ElasticLimitParameters,
        net_limit_parameters: ElasticLimitParameters,
    ) -> Result<(), ChainError> {
        cpu_limit_parameters.validate()?;
        net_limit_parameters.validate()?;
        let mut config = session.get::<ResourceLimitsConfig>(0)?;

        if config.cpu_limit_parameters == cpu_limit_parameters
            && config.net_limit_parameters == net_limit_parameters
        {
            return Ok(());
        }

        session.modify(&mut config, |config| {
            config.cpu_limit_parameters = cpu_limit_parameters;
            config.net_limit_parameters = net_limit_parameters;
            Ok(())
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