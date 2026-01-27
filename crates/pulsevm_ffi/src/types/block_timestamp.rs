use cxx::SharedPtr;

use crate::{CxxBlockTimestamp, bridge::ffi::{make_block_timestamp_from_now, make_block_timestamp_from_slot}};

impl CxxBlockTimestamp {
    pub fn now() -> SharedPtr<CxxBlockTimestamp> {
        make_block_timestamp_from_now()
    }

    pub fn from_slot(slot: u32) -> SharedPtr<CxxBlockTimestamp> {
        make_block_timestamp_from_slot(slot)
    }
}

unsafe impl Send for CxxBlockTimestamp {}
unsafe impl Sync for CxxBlockTimestamp {}