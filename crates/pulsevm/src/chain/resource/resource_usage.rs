use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::Name;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ResourceUsage {
    pub owner: Name,
    pub cpu_usage: u64,
    pub net_usage: u64,
    pub ram_usage: u64,
}

impl ResourceUsage {
    pub fn new(owner: Name, cpu_usage: u64, net_usage: u64, ram_usage: u64) -> Self {
        ResourceUsage {
            owner,
            cpu_usage,
            net_usage,
            ram_usage,
        }
    }
}

impl Serialize for ResourceUsage {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.owner.serialize(bytes);
        self.cpu_usage.serialize(bytes);
        self.net_usage.serialize(bytes);
        self.ram_usage.serialize(bytes);
    }
}

impl Deserialize for ResourceUsage {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let owner = Name::deserialize(data, pos)?;
        let cpu_usage = u64::deserialize(data, pos)?;
        let net_usage = u64::deserialize(data, pos)?;
        let ram_usage = u64::deserialize(data, pos)?;
        Ok(ResourceUsage {
            owner,
            cpu_usage,
            net_usage,
            ram_usage,
        })
    }
}

impl ChainbaseObject for ResourceUsage {
    type PrimaryKey = Name;

    fn primary_key(&self) -> Vec<u8> {
        ResourceUsage::primary_key_to_bytes(self.owner)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.as_u64().to_be_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "resource_usage"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
}
