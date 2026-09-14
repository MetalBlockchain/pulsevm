use pulsevm_billable_size::BillableSize;
use pulsevm_constants::OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES;

/// Zero-sized billing marker for a `double` secondary index row.
pub struct IndexDoubleObject;

impl BillableSize for IndexDoubleObject {
    const OVERHEAD: u64 = 3 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
    const VALUE: u64 = 24 + 8 + Self::OVERHEAD;
}
