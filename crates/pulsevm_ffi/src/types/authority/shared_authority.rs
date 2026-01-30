use pulsevm_billable_size::BillableSize;
use pulsevm_constants::FIXED_OVERHEAD_SHARED_VECTOR_RAM_BYTES;

use crate::bridge::ffi::CxxSharedAuthority;

impl BillableSize for CxxSharedAuthority {
    const OVERHEAD: u64 = 0;
    const VALUE: u64 = (3 * FIXED_OVERHEAD_SHARED_VECTOR_RAM_BYTES as u64) + 4;
}
