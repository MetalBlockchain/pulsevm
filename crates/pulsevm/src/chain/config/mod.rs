pub const OVERHEAD_PER_ACCOUNT_RAM_BYTES: u32 = 2048;
pub const OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES: u32 = 32;
pub const BILLABLE_ALIGNMENT: u64 = 16;
pub const FIXED_OVERHEAD_SHARED_VECTOR_RAM_BYTES: u32 = 32;
pub const SETCODE_RAM_BYTES_MULTIPLIER: u32 = 10;
///< multiplier on contract size to account for multiple copies and cached compilation
///

pub const RATE_LIMITING_PRECISION: u64 = 1000 * 1000;

pub const PERCENT_100: u64 = 10000; // Assuming EOS uses basis points (10000 = 100%)

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
