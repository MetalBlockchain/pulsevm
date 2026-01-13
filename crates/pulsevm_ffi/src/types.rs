use crate::types::ffi::SharedBlob;

#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    unsafe extern "C++" {
        include!("types.hpp");

        #[cxx_name = "shared_blob"]
        type SharedBlob;
        pub fn data(self: &SharedBlob) -> *const u8;
        pub fn size(self: &SharedBlob) -> u32;
    }
}

impl SharedBlob {
    pub fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data(), self.size() as usize) }
    }

    pub fn len(&self) -> usize {
        self.size() as usize
    }
}
