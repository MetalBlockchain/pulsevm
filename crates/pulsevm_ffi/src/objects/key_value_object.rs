use pulsevm_billable_size::{BillableSize, billable_size_v};
use pulsevm_constants::OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES;

use crate::KeyValueObject;

impl BillableSize for KeyValueObject {
    const OVERHEAD: u64 = 2 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
    const VALUE: u64 = 32 + 8 + 4 + KeyValueObject::OVERHEAD;
}
