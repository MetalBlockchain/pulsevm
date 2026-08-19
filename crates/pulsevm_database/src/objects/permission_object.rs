use pulsevm_billable_size::{
    BillableSize,
    billable_size_v,
};
use pulsevm_constants::{
    FIXED_OVERHEAD_SHARED_VECTOR_RAM_BYTES,
    OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES,
};

/// Zero-sized billing marker for the `shared_authority` a permission stores. Its
/// billable value is the three shared vectors (keys/accounts/waits) plus the
/// four-byte threshold; the per-element weight of each vector is billed
/// separately by `authority_billable_size`.
pub struct SharedAuthority;

impl BillableSize for SharedAuthority {
    const OVERHEAD: u64 = 0;
    const VALUE: u64 = (3 * FIXED_OVERHEAD_SHARED_VECTOR_RAM_BYTES as u64) + 4;
}

/// Zero-sized billing marker for a permission row. The permission itself lives in
/// the arena; this constant is the fixed RAM a permission bills on top of its
/// authority.
pub struct PermissionObject;

impl BillableSize for PermissionObject {
    const OVERHEAD: u64 = 5 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
    const VALUE: u64 = (billable_size_v::<SharedAuthority>() + 64) + PermissionObject::OVERHEAD;
}
