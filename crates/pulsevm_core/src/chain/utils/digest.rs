use std::ops::Deref;

use cxx::SharedPtr;
use pulsevm_ffi::CxxDigest;

#[derive(Clone)]
pub struct Digest {
    inner: SharedPtr<CxxDigest>,
}

impl Digest {
    pub fn new(inner: SharedPtr<CxxDigest>) -> Self {
        Digest { inner }
    }

    // Ths function creates a Digest from existing hash data, it does not compute the hash
    pub fn from_data(data: &[u8]) -> Self {
        let cxx_digest = pulsevm_ffi::make_shared_digest_from_existing_hash(data);
        Digest { inner: cxx_digest }
    }
}

impl Deref for Digest {
    type Target = SharedPtr<CxxDigest>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Into<Digest> for &[u8; 32] {
    fn into(self) -> Digest {
        Digest::from_data(self)
    }
}

impl Into<Digest> for [u8; 32] {
    fn into(self) -> Digest {
        Digest::from_data(&self)
    }
}
