use cxx::{SharedPtr, UniquePtr};

use crate::{
    BlockTimestamp, TimePoint,
    types::ffi::{Digest, SharedBlob},
};

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
        pub fn get_slot(self: &BlockTimestamp) -> u32;

        #[cxx_name = "time_point"]
        type TimePoint;
        pub fn time_since_epoch(self: &TimePoint) -> &Microseconds;
        pub fn sec_since_epoch(self: &TimePoint) -> u32;

        #[cxx_name = "microseconds"]
        type Microseconds;
        pub fn count(self: &Microseconds) -> i64;

        #[cxx_name = "authority"]
        type Authority;

        #[cxx_name = "shared_authority"]
        type SharedAuthority;

        // Global functions
        pub fn make_empty_digest() -> UniquePtr<Digest>;
        pub fn make_digest_from_data(data: &[u8]) -> UniquePtr<Digest>;
        pub fn make_time_point_from_now() -> SharedPtr<TimePoint>;
        pub fn make_block_timestamp_from_now() -> SharedPtr<BlockTimestamp>;
        pub fn make_block_timestamp_from_slot(slot: u32) -> SharedPtr<BlockTimestamp>;
        pub fn make_time_point_from_i64(us: i64) -> SharedPtr<TimePoint>;
        pub fn make_time_point_from_microseconds(us: &Microseconds) -> SharedPtr<TimePoint>;
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
    pub fn new(microseconds: i64) -> SharedPtr<TimePoint> {
        ffi::make_time_point_from_i64(microseconds)
    }

    pub fn now() -> SharedPtr<TimePoint> {
        ffi::make_time_point_from_now()
    }
}

impl BlockTimestamp {
    pub fn now() -> SharedPtr<BlockTimestamp> {
        ffi::make_block_timestamp_from_now()
    }

    pub fn from_slot(slot: u32) -> SharedPtr<BlockTimestamp> {
        ffi::make_block_timestamp_from_slot(slot)
    }
}

unsafe impl Send for ffi::BlockTimestamp {}
unsafe impl Sync for ffi::BlockTimestamp {}