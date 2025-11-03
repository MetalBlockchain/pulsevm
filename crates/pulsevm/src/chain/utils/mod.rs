mod base64_bytes;
pub use base64_bytes::*;

mod i32_flex;
pub use i32_flex::*;

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
