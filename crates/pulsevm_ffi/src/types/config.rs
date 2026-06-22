use pulsevm_error::ChainError;
use pulsevm_serialization::{NumBytes, Read, ReadError, Write, WriteError};

use crate::ChainConfigV0;

pub const PERCENT_100: u32 = 10_000;
pub const PERCENT_1: u32 = 100;
pub const MIN_NET_USAGE_DELTA_BETWEEN_BASE_AND_MAX_FOR_TRX: u32 = 10240;

impl ChainConfigV0 {
    pub fn validate(&self) -> Result<(), ChainError> {
        macro_rules! ensure {
            ($cond:expr, $msg:expr) => {
                if !($cond) {
                    return Err(ChainError::ActionValidationError($msg.into()));
                }
            };
        }

        ensure!(
            self.target_block_net_usage_pct <= PERCENT_100,
            "target block net usage percentage cannot exceed 100%"
        );
        ensure!(
            self.target_block_net_usage_pct >= PERCENT_1 / 10,
            "target block net usage percentage must be at least 0.1%"
        );
        ensure!(
            self.target_block_cpu_usage_pct <= PERCENT_100,
            "target block cpu usage percentage cannot exceed 100%"
        );
        ensure!(
            self.target_block_cpu_usage_pct >= PERCENT_1 / 10,
            "target block cpu usage percentage must be at least 0.1%"
        );

        ensure!(
            (self.max_transaction_net_usage as u64) < self.max_block_net_usage,
            "max transaction net usage must be less than max block net usage"
        );
        ensure!(
            self.max_transaction_cpu_usage < self.max_block_cpu_usage,
            "max transaction cpu usage must be less than max block cpu usage"
        );

        ensure!(
            self.base_per_transaction_net_usage < self.max_transaction_net_usage,
            "base net usage per transaction must be less than the max transaction net usage"
        );
        ensure!(
            self.max_transaction_net_usage - self.base_per_transaction_net_usage
                >= MIN_NET_USAGE_DELTA_BETWEEN_BASE_AND_MAX_FOR_TRX,
            format!(
                "max transaction net usage must be at least {} bytes larger than base net usage per transaction",
                MIN_NET_USAGE_DELTA_BETWEEN_BASE_AND_MAX_FOR_TRX
            )
        );
        ensure!(
            self.context_free_discount_net_usage_den > 0,
            "net usage discount ratio for context free data cannot have a 0 denominator"
        );
        ensure!(
            self.context_free_discount_net_usage_num <= self.context_free_discount_net_usage_den,
            "net usage discount ratio for context free data cannot exceed 1"
        );

        ensure!(
            self.min_transaction_cpu_usage <= self.max_transaction_cpu_usage,
            "min transaction cpu usage cannot exceed max transaction cpu usage"
        );
        ensure!(
            self.max_transaction_cpu_usage
                < self.max_block_cpu_usage - self.min_transaction_cpu_usage,
            "max transaction cpu usage must be at less than the difference between the max block cpu usage and the min transaction cpu usage"
        );

        ensure!(
            self.max_authority_depth >= 1,
            "max authority depth should be at least 1"
        );

        Ok(())
    }
}

impl NumBytes for ChainConfigV0 {
    fn num_bytes(&self) -> usize {
        68
    }
}

impl Read for ChainConfigV0 {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        Ok(ChainConfigV0 {
            max_block_net_usage: u64::read(bytes, pos)?,
            target_block_net_usage_pct: u32::read(bytes, pos)?,
            max_transaction_net_usage: u32::read(bytes, pos)?,
            base_per_transaction_net_usage: u32::read(bytes, pos)?,
            net_usage_leeway: u32::read(bytes, pos)?,
            context_free_discount_net_usage_num: u32::read(bytes, pos)?,
            context_free_discount_net_usage_den: u32::read(bytes, pos)?,
            max_block_cpu_usage: u32::read(bytes, pos)?,
            target_block_cpu_usage_pct: u32::read(bytes, pos)?,
            max_transaction_cpu_usage: u32::read(bytes, pos)?,
            min_transaction_cpu_usage: u32::read(bytes, pos)?,
            max_transaction_lifetime: u32::read(bytes, pos)?,
            deferred_trx_expiration_window: u32::read(bytes, pos)?,
            max_transaction_delay: u32::read(bytes, pos)?,
            max_inline_action_size: u32::read(bytes, pos)?,
            max_inline_action_depth: u16::read(bytes, pos)?,
            max_authority_depth: u16::read(bytes, pos)?,
        })
    }
}

impl Write for ChainConfigV0 {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.max_block_net_usage.write(bytes, pos)?;
        self.target_block_net_usage_pct.write(bytes, pos)?;
        self.max_transaction_net_usage.write(bytes, pos)?;
        self.base_per_transaction_net_usage.write(bytes, pos)?;
        self.net_usage_leeway.write(bytes, pos)?;
        self.context_free_discount_net_usage_num.write(bytes, pos)?;
        self.context_free_discount_net_usage_den.write(bytes, pos)?;
        self.max_block_cpu_usage.write(bytes, pos)?;
        self.target_block_cpu_usage_pct.write(bytes, pos)?;
        self.max_transaction_cpu_usage.write(bytes, pos)?;
        self.min_transaction_cpu_usage.write(bytes, pos)?;
        self.max_transaction_lifetime.write(bytes, pos)?;
        self.deferred_trx_expiration_window.write(bytes, pos)?;
        self.max_transaction_delay.write(bytes, pos)?;
        self.max_inline_action_size.write(bytes, pos)?;
        self.max_inline_action_depth.write(bytes, pos)?;
        self.max_authority_depth.write(bytes, pos)?;

        Ok(())
    }
}
