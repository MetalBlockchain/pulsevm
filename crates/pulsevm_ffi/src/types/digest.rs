use core::fmt;

use cxx::UniquePtr;
use pulsevm_error::ChainError;

use crate::{
    CxxDigest,
    bridge::ffi::{
        get_digest_data, make_digest_from_data, make_digest_from_existing_hash, make_empty_digest,
    },
};

impl CxxDigest {
    pub fn new_empty() -> UniquePtr<CxxDigest> {
        make_empty_digest()
    }

    pub fn hash(data: &[u8]) -> Result<UniquePtr<CxxDigest>, ChainError> {
        make_digest_from_data(data).map_err(|e| {
            ChainError::InternalError(format!("failed to create digest from data: {}", e))
        })
    }

    pub fn new_from_existing_hash(data: &[u8]) -> Result<UniquePtr<CxxDigest>, ChainError> {
        make_digest_from_existing_hash(data).map_err(|e| {
            ChainError::InternalError(format!("failed to create digest from existing hash: {}", e))
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        get_digest_data(self)
    }
}

impl PartialEq for &CxxDigest {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl fmt::Debug for CxxDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_slice()))
    }
}

impl fmt::Display for CxxDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_slice()))
    }
}
