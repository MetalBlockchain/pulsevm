use pulsevm_billable_size::BillableSize;
use pulsevm_constants::OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES;

/// Zero-sized billing marker for a `uint256` secondary index row.
pub struct Index256Object;

impl BillableSize for Index256Object {
    const OVERHEAD: u64 = 3 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
    const VALUE: u64 = 24 + 32 + Self::OVERHEAD;
}
