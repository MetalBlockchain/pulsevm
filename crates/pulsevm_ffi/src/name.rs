use std::fmt;

use cxx::UniquePtr;

use crate::name::ffi::CxxName;

#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    unsafe extern "C++" {
        include!("name.hpp");

        pub type CxxName;

        // Name methods
        pub fn u64_to_name(val: u64) -> UniquePtr<CxxName>;
        pub fn string_to_name(str: &str) -> Result<UniquePtr<CxxName>>;
        pub fn name_to_uint64(name: &CxxName) -> u64;
        pub fn to_uint64_t(self: &CxxName) -> u64;
        pub fn empty(self: &CxxName) -> bool;
    }
}

impl CxxName {
    pub fn new(val: u64) -> UniquePtr<CxxName> {
        ffi::u64_to_name(val)
    }
}

impl fmt::Display for CxxName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name_u64 = ffi::name_to_uint64(self);
        write!(f, "{}", name_u64)
    }
}

impl PartialEq for &CxxName {
    fn eq(&self, other: &Self) -> bool {
        ffi::name_to_uint64(self) == ffi::name_to_uint64(other)
    }
}

unsafe impl Send for ffi::CxxName {}
unsafe impl Sync for ffi::CxxName {}
