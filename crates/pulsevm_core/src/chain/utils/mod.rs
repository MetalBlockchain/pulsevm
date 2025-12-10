mod base64_bytes;
pub use base64_bytes::*;

mod i32_flex;
pub use i32_flex::*;

mod usage_accumulator;
use pulsevm_chainbase::{ChainbaseObject, Database};
pub use usage_accumulator::*;

use crate::error::ChainError;

#[inline]
pub fn pulse_assert<T>(condition: bool, error: T) -> Result<(), T> {
    if condition {
        Ok(())
    } else {
        return Err(error);
    }
}

pub fn prepare_db_object<T: ChainbaseObject>(db: &Database) -> Result<(), ChainError> {
    db.open_partition_handle(T::table_name())
        .map_err(|e| ChainError::DatabaseError(e.to_string()))?;

    for secondary_index in T::default().secondary_indexes() {
        db.open_partition_handle(secondary_index.index_name)
            .map_err(|e| ChainError::DatabaseError(e.to_string()))?;
    }

    Ok(())
}