use std::hash::{Hash, Hasher};

use crate::{CxxPublicKey, bridge::ffi};

impl CxxPublicKey {
    pub fn packed_bytes(&self) -> Vec<u8> {
        ffi::packed_public_key_bytes(self)
    }

    pub fn to_string_rust(&self) -> &str {
        ffi::public_key_to_string(self)
    }

    pub fn num_bytes(&self) -> usize {
        ffi::public_key_num_bytes(self)
    }
}

impl PartialEq for CxxPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == 0
    }
}

impl Eq for CxxPublicKey {}

impl Hash for CxxPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.packed_bytes().hash(state);
    }
}