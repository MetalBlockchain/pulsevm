use std::fmt;

use cxx::SharedPtr;

use crate::{CxxPrivateKey, CxxPublicKey, bridge::ffi::get_public_key_from_private_key};

impl CxxPrivateKey {
    pub fn get_public_key(&self) -> SharedPtr<CxxPublicKey> {
        get_public_key_from_private_key(self)
    }
}

impl fmt::Display for CxxPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = crate::bridge::ffi::private_key_to_string(self);
        write!(f, "{}", s)
    }
}
