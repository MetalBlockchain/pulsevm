use pulsevm_billable_size::BillableSize;
use pulsevm_constants::OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES;

use crate::TableObject;

impl BillableSize for TableObject {
    const OVERHEAD: u64 = 2 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
    const VALUE: u64 = 44 + TableObject::OVERHEAD;
}
