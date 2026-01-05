use std::sync::Arc;

use pulsevm_crypto::Bytes;
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::id::Id;

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct CodeObject {
    pub code_hash: Id,
    pub code: Arc<Bytes>,
    pub code_ref_count: u64,
    pub first_block_used: u32,
    pub vm_type: u8,
    pub vm_version: u8,
}