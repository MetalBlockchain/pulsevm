pub const OVERHEAD_PER_ACCOUNT_RAM_BYTES: u32 = 2048;
pub const OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES: u32 = 32;
pub const BILLABLE_ALIGNMENT: u64 = 16;
pub const FIXED_OVERHEAD_SHARED_VECTOR_RAM_BYTES: u32 = 32;

pub trait BillableSize {
    fn billable_size() -> u64;
}

pub fn billable_size_v<T: BillableSize>() -> u64 {
    return ((T::billable_size() + BILLABLE_ALIGNMENT - 1) / BILLABLE_ALIGNMENT)
        * BILLABLE_ALIGNMENT;
}
