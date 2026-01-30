pub const BILLABLE_ALIGNMENT: u64 = 16;

pub trait BillableSize {
    const OVERHEAD: u64;
    const VALUE: u64;
}

pub const fn billable_size_v<T: BillableSize>() -> u64 {
    return ((T::VALUE + BILLABLE_ALIGNMENT - 1) / BILLABLE_ALIGNMENT) * BILLABLE_ALIGNMENT;
}
