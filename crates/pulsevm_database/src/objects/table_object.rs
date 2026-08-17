use pulsevm_billable_size::BillableSize;
use pulsevm_constants::OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES;

/// Zero-sized billing marker. The table rows themselves live in the arena; this
/// type only carries the compile-time `billable_size_v::<TableObject>()` constant
/// that RAM accounting charges when a contract creates a table.
pub struct TableObject;

impl BillableSize for TableObject {
    const OVERHEAD: u64 = 2 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
    const VALUE: u64 = 44 + TableObject::OVERHEAD;
}
