use std::{cell::RefCell, rc::Rc};

use pulsevm_chainbase::UndoSession;
use wasmtime::Ref;

use super::{Name, ResourceLimits, ResourceUsage, error::ChainError, pulse_assert};

pub struct ResourceLimitsManager {}

impl ResourceLimitsManager {
    pub fn initialize_account(session: &mut UndoSession, account: Name) -> Result<(), ChainError> {
        let limits = ResourceLimits::new(account, -1, -1, -1);
        session.insert(&limits).map_err(|_| {
            ChainError::TransactionError(format!("failed to insert resource limits"))
        })?;

        let usage = ResourceUsage::new(account, 0, 0, 0);
        session.insert(&usage).map_err(|_| {
            ChainError::TransactionError(format!("failed to insert resource usage"))
        })?;

        Ok(())
    }

    pub fn add_pending_ram_usage(
        session: &mut UndoSession,
        account: Name,
        ram_delta: i64,
    ) -> Result<(), ChainError> {
        if ram_delta == 0 {
            return Ok(());
        }

        let mut usage = session.get::<ResourceUsage>(account).map_err(|_| {
            ChainError::TransactionError(format!(
                "failed to get resource usage for account {}",
                account
            ))
        })?;

        pulse_assert(
            usage.ram_usage.checked_add_signed(ram_delta).is_some(),
            ChainError::TransactionError(format!("ram usage delta would underflow or overflow")),
        )?;

        session
            .modify(&mut usage, |usage: &mut ResourceUsage| {
                usage.ram_usage = usage.ram_usage;
            })
            .map_err(|_| {
                ChainError::TransactionError(format!("failed to modify resource usage"))
            })?;

        Ok(())
    }
}
