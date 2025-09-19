pub const PLUGIN_VERSION: u32 = 38;
pub const VERSION: &str = "v0.0.1";

pub const OVERHEAD_PER_ACCOUNT_RAM_BYTES: u32 = 2048;
pub const OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES: u32 = 32;
pub const BILLABLE_ALIGNMENT: u64 = 16;
pub const FIXED_OVERHEAD_SHARED_VECTOR_RAM_BYTES: u32 = 32;
pub const SETCODE_RAM_BYTES_MULTIPLIER: u32 = 10;
///< multiplier on contract size to account for multiple copies and cached compilation
///

pub const RATE_LIMITING_PRECISION: u64 = 1000 * 1000;

pub const PERCENT_100: u64 = 10000; // Assuming EOS uses basis points (10000 = 100%)

// Names
pub const NEWACCOUNT_NAME: Name = Name::new(name!("newaccount"));
pub const SETCODE_NAME: Name = Name::new(name!("setcode"));
pub const SETABI_NAME: Name = Name::new(name!("setabi"));
pub const UPDATEAUTH_NAME: Name = Name::new(name!("updateauth"));
pub const DELETEAUTH_NAME: Name = Name::new(name!("deleteauth"));
pub const LINKAUTH_NAME: Name = Name::new(name!("linkauth"));
pub const UNLINKAUTH_NAME: Name = Name::new(name!("unlinkauth"));
pub const ONERROR_NAME: Name = Name::new(name!("onerror"));
pub const ONBLOCK_NAME: Name = Name::new(name!("onblock"));

pub trait BillableSize {
    fn billable_size() -> u64;
}

pub fn billable_size_v<T: BillableSize>() -> u64 {
    return ((T::billable_size() + BILLABLE_ALIGNMENT - 1) / BILLABLE_ALIGNMENT)
        * BILLABLE_ALIGNMENT;
}

mod gpo;
pub use gpo::GlobalPropertyObject;

mod dgpo;
pub use dgpo::DynamicGlobalPropertyObject;
use pulsevm_proc_macros::name;

use crate::chain::Name;
