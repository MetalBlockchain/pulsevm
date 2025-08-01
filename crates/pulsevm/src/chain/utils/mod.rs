mod usage_accumulator;
pub use usage_accumulator::*;

use crate::chain::config::PERCENT_100;

pub fn pulse_assert<T>(condition: bool, error: T) -> Result<(), T> {
    if condition {
        Ok(())
    } else {
        return Err(error);
    }
}

pub const fn eos_percent(value: u64, percentage: u32) -> u64 {
    (value * percentage as u64) / PERCENT_100
}
