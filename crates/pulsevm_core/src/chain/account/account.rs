use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{Name, block::BlockTimestamp};

#[derive(Debug, Clone, Default, Read, Write, NumBytes)]
pub struct Account {
    pub name: Name,
    pub creation_date: BlockTimestamp,
    pub abi: Vec<u8>,
}

impl Account {
    pub fn new(name: Name, creation_date: BlockTimestamp, abi: Vec<u8>) -> Self {
        Account { name, creation_date, abi }
    }
}
