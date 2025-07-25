use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::Name;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct Account {
    pub name: Name,
    pub creation_date: u64,
    pub abi: Vec<u8>,
}

impl Account {
    pub fn new(name: Name, creation_date: u64, abi: Vec<u8>) -> Self {
        Account {
            name,
            creation_date,
            abi,
        }
    }
}

impl ChainbaseObject for Account {
    type PrimaryKey = Name;

    fn primary_key(&self) -> Vec<u8> {
        Account::primary_key_to_bytes(self.name)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.as_u64().to_be_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "account"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
}
