use pulsevm_billable_size::{BillableSize, billable_size_v};
use pulsevm_constants::OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES;

use crate::{
    Index256Object, KeyValueObject,
    bridge::ffi::{IndexDoubleObject, IndexLongDoubleObject},
};

impl BillableSize for IndexLongDoubleObject {
    const OVERHEAD: u64 = 3 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
    const VALUE: u64 = 24 + 16 + KeyValueObject::OVERHEAD;
}
