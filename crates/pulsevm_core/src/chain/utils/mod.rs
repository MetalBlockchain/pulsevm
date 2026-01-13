mod base64_bytes;
pub use base64_bytes::*;

mod i32_flex;
pub use i32_flex::*;

mod usage_accumulator;
pub use usage_accumulator::*;

#[inline]
pub fn pulse_assert<T>(condition: bool, error: T) -> Result<(), T> {
    if condition {
        Ok(())
    } else {
        return Err(error);
    }
}
