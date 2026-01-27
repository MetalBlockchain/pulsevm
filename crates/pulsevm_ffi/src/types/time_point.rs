use cxx::SharedPtr;

use crate::{CxxTimePoint, bridge::ffi::{make_time_point_from_i64, make_time_point_from_now}};

impl CxxTimePoint {
    pub fn new(microseconds: i64) -> SharedPtr<CxxTimePoint> {
        make_time_point_from_i64(microseconds)
    }

    pub fn now() -> SharedPtr<CxxTimePoint> {
        make_time_point_from_now()
    }
}