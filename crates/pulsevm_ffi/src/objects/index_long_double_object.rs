use pulsevm_billable_size::BillableSize;
use pulsevm_constants::OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES;

use crate::{KeyValueObject, bridge::ffi::IndexLongDoubleObject};

impl BillableSize for IndexLongDoubleObject {
    const OVERHEAD: u64 = 3 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
    const VALUE: u64 = 24 + 16 + KeyValueObject::OVERHEAD;
}
