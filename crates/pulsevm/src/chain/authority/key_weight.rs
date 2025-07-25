
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{PublicKey, config::BillableSize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct KeyWeight {
    key: PublicKey,
    weight: u16,
}

impl KeyWeight {
    pub fn new(key: PublicKey, weight: u16) -> Self {
        KeyWeight { key, weight }
    }

    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    pub fn weight(&self) -> u16 {
        self.weight
    }
}

impl BillableSize for KeyWeight {
    fn billable_size() -> u64 {
        8
    }
}
