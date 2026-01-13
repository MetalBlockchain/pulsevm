use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{genesis::ChainConfig, id::Id};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct GlobalPropertyObject {
    pub chain_id: Id,
    pub configuration: ChainConfig,
}
