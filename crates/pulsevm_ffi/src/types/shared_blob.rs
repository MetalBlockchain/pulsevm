use crate::bridge::ffi::{CxxSharedBlob, get_shared_blob_data};

impl CxxSharedBlob {
    pub fn as_slice(&self) -> &[u8] {
        get_shared_blob_data(self)
    }
}