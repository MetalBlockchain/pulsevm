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
