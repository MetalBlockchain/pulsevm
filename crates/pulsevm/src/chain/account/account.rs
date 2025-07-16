use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::Name;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
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

impl Serialize for Account {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.name.serialize(bytes);
        self.creation_date.serialize(bytes);
        self.abi.serialize(bytes);
    }
}

impl Deserialize for Account {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let name = Name::deserialize(data, pos)?;
        let creation_date = u64::deserialize(data, pos)?;
        let abi = Vec::<u8>::deserialize(data, pos)?;

        Ok(Account {
            name,
            creation_date,
            abi,
        })
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
