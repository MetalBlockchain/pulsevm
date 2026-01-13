use std::fmt;

use cxx::UniquePtr;

use crate::name::ffi::Name;

#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    unsafe extern "C++" {
        include!("name.hpp");

        #[cxx_name = "name"]
        pub type Name;

        // Name methods
        pub fn u64_to_name(val: u64) -> UniquePtr<Name>;
        pub fn string_to_name(str: &str) -> Result<UniquePtr<Name>>;
        pub fn name_to_uint64(name: &Name) -> u64;
        pub fn to_uint64_t(self: &Name) -> u64;
        pub fn empty(self: &Name) -> bool;
    }
}

impl Name {
    pub fn new(val: u64) -> UniquePtr<Name> {
        ffi::u64_to_name(val)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name_u64 = ffi::name_to_uint64(self);
        write!(f, "{}", name_u64)
    }
}

impl PartialEq for &Name {
    fn eq(&self, other: &Self) -> bool {
        ffi::name_to_uint64(self) == ffi::name_to_uint64(other)
    }
}
