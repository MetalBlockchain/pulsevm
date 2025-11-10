use pulsevm_chainbase::{ChainbaseObject, SecondaryIndex, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;

use crate::chain::Name;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct ResourceLimits {
    pub id: u64,
    pub owner: Name,
    pub pending: bool,
    pub net_weight: i64,
    pub cpu_weight: i64,
    pub ram_bytes: i64,
}

impl ResourceLimits {
    pub fn new(
        id: u64,
        owner: Name,
        pending: bool,
        net_weight: i64,
        cpu_weight: i64,
        ram_bytes: i64,
    ) -> Self {
        ResourceLimits {
            id,
            owner,
            pending,
            net_weight,
            cpu_weight,
            ram_bytes,
        }
    }
}

impl ChainbaseObject for ResourceLimits {
    type PrimaryKey = u64;

    fn primary_key(&self) -> Vec<u8> {
        ResourceLimits::primary_key_to_bytes(self.id)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.pack().unwrap()
    }

    fn table_name() -> &'static str {
        "resource_limits"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![SecondaryKey {
            key: ResourceLimitsByOwnerIndex::secondary_key_as_bytes((self.pending, self.owner)),
            index_name: ResourceLimitsByOwnerIndex::index_name(),
        }]
    }
}

#[derive(Debug, Default)]
pub struct ResourceLimitsByOwnerIndex;

impl SecondaryIndex<ResourceLimits> for ResourceLimitsByOwnerIndex {
    type Key = (bool, Name);
    type Object = ResourceLimits;

    fn secondary_key(object: &ResourceLimits) -> Vec<u8> {
        ResourceLimitsByOwnerIndex::secondary_key_as_bytes((object.pending, object.owner))
    }

    fn secondary_key_as_bytes(key: Self::Key) -> Vec<u8> {
        key.pack().unwrap()
    }

    fn index_name() -> &'static str {
        "resource_limits_by_owner"
    }
}
