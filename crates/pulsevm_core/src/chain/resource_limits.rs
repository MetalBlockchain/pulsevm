use std::collections::HashSet;

use pulsevm_chainbase::UndoSession;

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
        let id = session.generate_id::<ResourceLimits>()?;
        let limits = ResourceLimits::new(id, account, false, -1, -1, -1);
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
        let mut state = session.get::<ResourceLimitsState>(0)?;
        let config = session.get::<ResourceLimitsConfig>(0)?;

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

            session.modify(&mut usage, |bu| {
                bu.cpu_usage.add(
                    cpu_usage,
                    time_slot,
                    config.account_cpu_usage_average_window as u64,
                )?;
                bu.net_usage.add(
                    net_usage,
                    time_slot,
                    config.account_net_usage_average_window as u64,
                )?;
                Ok(())
            })?;

            if cpu_weight >= 0 && state.total_cpu_weight > 0 {
                let window_size: u128 = config.account_cpu_usage_average_window as u128;
                let virtual_cpu_capacity_in_window: u128 =
                    window_size * state.virtual_cpu_limit as u128;
                let cpu_used_in_window = usage.cpu_usage.value_ex as u128 * window_size
                    / RATE_LIMITING_PRECISION as u128;

                let user_weight: u128 = cpu_weight as u128;
                let all_user_weight: u128 = state.total_cpu_weight as u128;

                let max_user_use_in_window =
                    (virtual_cpu_capacity_in_window * user_weight) / all_user_weight;
                pulse_assert(
                    cpu_used_in_window <= max_user_use_in_window,
                    ChainError::TransactionError(format!(
                        "authorizing account '{}' has insufficient objective cpu resources for this transaction, used in window {}, allowed in window {}",
                        account, cpu_used_in_window, max_user_use_in_window
                    )),
                )?;
            }

            if net_weight >= 0 && state.total_net_weight > 0 {
                let window_size: u128 = config.account_net_usage_average_window as u128;
                let virtual_network_capacity_in_window: u128 =
                    window_size * state.virtual_net_limit as u128;
                let net_used_in_window = usage.net_usage.value_ex as u128 * window_size
                    / RATE_LIMITING_PRECISION as u128;

                let user_weight: u128 = net_weight as u128;
                let all_user_weight: u128 = state.total_net_weight as u128;

                let max_user_use_in_window =
                    (virtual_network_capacity_in_window * user_weight) / all_user_weight;
                pulse_assert(
                    net_used_in_window <= max_user_use_in_window,
                    ChainError::TransactionError(format!(
                        "authorizing account '{}' has insufficient objective net resources for this transaction, used in window {}, allowed in window {}",
                        account, net_used_in_window, max_user_use_in_window
                    )),
                )?;
            }
        }

        session.modify(&mut state, |state| {
            state.pending_cpu_usage = state.pending_cpu_usage.checked_add(cpu_usage).ok_or(
                ChainError::TransactionError("overflow when adding pending cpu usage".to_owned()),
            )?;
            state.pending_net_usage = state.pending_net_usage.checked_add(net_usage).ok_or(
                ChainError::TransactionError("overflow when adding pending net usage".to_owned()),
            )?;
            Ok(())
        })?;

        pulse_assert(
            state.pending_cpu_usage <= config.cpu_limit_parameters.max,
            ChainError::TransactionError("block has insufficient cpu resources".to_owned()),
        )?;
        pulse_assert(
            state.pending_net_usage <= config.net_limit_parameters.max,
            ChainError::TransactionError("block has insufficient net resources".to_owned()),
        )?;

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
            Ok(())
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
            let pending_limits = session
                .find_by_secondary::<ResourceLimits, ResourceLimitsByOwnerIndex>((
                    true, *account,
                ))?;

            if let Some(limits) = pending_limits {
                limits
            } else {
                let limits = session
                    .get_by_secondary::<ResourceLimits, ResourceLimitsByOwnerIndex>((
                        false, *account,
                    ))?;
                let id = session.generate_id::<ResourceLimits>()?;
                let pending_limits = ResourceLimits::new(
                    id,
                    *account,
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
            Ok(())
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
        let limits = session.find_by_secondary::<ResourceLimits, ResourceLimitsByOwnerIndex>((
            true,
            account.clone(),
        ))?;
        if let Some(limits) = limits {
            *ram_bytes = limits.ram_bytes;
            *net_weight = limits.net_weight;
            *cpu_weight = limits.cpu_weight;
            return Ok(());
        }

        let limits = session.find_by_secondary::<ResourceLimits, ResourceLimitsByOwnerIndex>((
            false,
            account.clone(),
        ))?;
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

    pub fn get_total_cpu_weight(session: &mut UndoSession) -> Result<u64, ChainError> {
        let state = session.find::<ResourceLimitsState>(0)?;
        
        match state {
            Some(s) => Ok(s.total_cpu_weight),
            None => Err(ChainError::TransactionError("failed to get resource limits state".to_string())),
        }
    }

    pub fn get_total_net_weight(session: &mut UndoSession) -> Result<u64, ChainError> {
        let state = session.find::<ResourceLimitsState>(0)?;
        
        match state {
            Some(s) => Ok(s.total_net_weight),
            None => Err(ChainError::TransactionError("failed to get resource limits state".to_string())),
        }
    }
}