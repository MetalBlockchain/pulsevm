use std::sync::{RwLock, RwLockReadGuard};

use sha2::digest::{consts::U32, generic_array::GenericArray};

use super::error::ChainError;

pub fn pulse_assert(condition: bool, error: ChainError) -> Result<(), ChainError> {
    if condition {
        Ok(())
    } else {
        return Err(error);
    }
}

pub fn zero_hash() -> GenericArray<u8, U32> {
    let hash: GenericArray<u8, U32> = GenericArray::default();
    hash
}

trait RwLockExt<T> {
    fn read_or_internal_error(&self) -> Result<RwLockReadGuard<T>, ChainError>;
}

impl<T> RwLockExt<T> for std::sync::RwLock<T> {
    fn read_or_internal_error(&self) -> Result<RwLockReadGuard<T>, ChainError> {
        self.read()
            .map_err(|_| ChainError::LockError("lock poisoned".into()))
    }
}
