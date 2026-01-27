use cxx::SharedPtr;

use crate::{CxxPrivateKey, CxxPublicKey, bridge::ffi::get_public_key_from_private_key};

impl CxxPrivateKey {
    pub fn get_public_key(&self) -> SharedPtr<CxxPublicKey> {
        get_public_key_from_private_key(self)
    }
}