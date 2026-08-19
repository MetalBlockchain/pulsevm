pub const BILLABLE_ALIGNMENT: u64 = 16;

pub trait BillableSize {
    const OVERHEAD: u64;
    const VALUE: u64;
}

#[allow(clippy::manual_div_ceil)]
pub const fn billable_size_v<T: BillableSize>() -> u64 {
    // Keep the historical add-before-divide overflow behavior: this value is
    // consensus-visible RAM billing.
    ((T::VALUE + BILLABLE_ALIGNMENT - 1) / BILLABLE_ALIGNMENT) * BILLABLE_ALIGNMENT
}
