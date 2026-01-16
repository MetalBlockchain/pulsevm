use cxx::{SharedPtr, UniquePtr};

use crate::{TimePoint, types::ffi::{Digest, SharedBlob}};

#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    unsafe extern "C++" {
        include!("types.hpp");

        #[cxx_name = "digest_type"]
        type Digest;
        pub fn data(self: &Digest) -> *const u8;
        pub fn empty(self: &Digest) -> bool;

        #[cxx_name = "shared_blob"]
        type SharedBlob;
        pub fn data(self: &SharedBlob) -> *const u8;
        pub fn size(self: &SharedBlob) -> u32;

        #[cxx_name = "block_timestamp_type"]
        type BlockTimestamp;
        pub fn to_time_point(self: &BlockTimestamp) -> SharedPtr<TimePoint>;

        #[cxx_name = "time_point"]
        type TimePoint;

        // Global functions
        pub fn make_empty_digest() -> UniquePtr<Digest>;
        pub fn make_digest_from_data(data: &[u8]) -> UniquePtr<Digest>;
        pub fn make_time_point_from_now() -> SharedPtr<TimePoint>;
        pub fn make_block_timestamp_from_now() -> SharedPtr<BlockTimestamp>;
    }
}

impl Digest {
    pub fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data(), 32) }
    }

    pub fn new_empty() -> UniquePtr<Digest> {
        ffi::make_empty_digest()
    }

    pub fn hash(data: &[u8]) -> UniquePtr<Digest> {
        ffi::make_digest_from_data(data)
    }
}

impl PartialEq for &Digest {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
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

impl TimePoint {
    pub fn now() -> SharedPtr<TimePoint> {
        ffi::make_time_point_from_now()
    }
}