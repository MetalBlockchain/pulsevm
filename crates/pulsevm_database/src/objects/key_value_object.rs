use pulsevm_billable_size::BillableSize;
use pulsevm_constants::OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES;

/// Zero-sized billing marker for a primary key/value row. Kept as a distinct type
/// so `billable_size_v::<KeyValueObject>()` bills the same RAM the reference chain
/// charges per stored row.
pub struct KeyValueObject;

impl BillableSize for KeyValueObject {
    const OVERHEAD: u64 = 2 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
    const VALUE: u64 = 32 + 8 + 4 + KeyValueObject::OVERHEAD;
}
