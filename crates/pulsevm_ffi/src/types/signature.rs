use crate::{
    CxxSignature,
    bridge::ffi::{packed_signature_bytes, signature_num_bytes, signature_to_string},
};

impl CxxSignature {
    pub fn packed_bytes(&self) -> Vec<u8> {
        packed_signature_bytes(self)
    }

    pub fn to_string_rust(&self) -> String {
        signature_to_string(self)
    }

    pub fn num_bytes(&self) -> usize {
        signature_num_bytes(self)
    }
}

unsafe impl Send for CxxSignature {}
unsafe impl Sync for CxxSignature {}
