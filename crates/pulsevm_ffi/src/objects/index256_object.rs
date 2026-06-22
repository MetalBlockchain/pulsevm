use pulsevm_billable_size::{BillableSize, billable_size_v};
use pulsevm_constants::OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES;

use crate::{Index256Object, KeyValueObject};

impl BillableSize for Index256Object {
    const OVERHEAD: u64 = 3 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
    const VALUE: u64 = 24 + 32 + KeyValueObject::OVERHEAD;
}
