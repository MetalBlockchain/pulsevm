use pulsevm_billable_size::BillableSize;
use pulsevm_constants::OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES;

use crate::{KeyValueObject, bridge::ffi::Index64Object};

impl BillableSize for Index64Object {
    const OVERHEAD: u64 = 3 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
    const VALUE: u64 = 24 + 8 + KeyValueObject::OVERHEAD;
}
