use std::fmt;

use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::config::{self, BillableSize, FIXED_OVERHEAD_SHARED_VECTOR_RAM_BYTES};

use super::{key_weight::KeyWeight, permission_level_weight::PermissionLevelWeight};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Authority {
    threshold: u32,
    keys: Vec<KeyWeight>,
    accounts: Vec<PermissionLevelWeight>,
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "authority {{ threshold: {}, keys: {:?}, accounts: {:?} }}",
            self.threshold, self.keys, self.accounts
        )
    }
}

impl Authority {
    pub fn new(threshold: u32, keys: Vec<KeyWeight>, accounts: Vec<PermissionLevelWeight>) -> Self {
        Authority {
            threshold,
            keys,
            accounts,
        }
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    pub fn keys(&self) -> &Vec<KeyWeight> {
        &self.keys
    }

    pub fn accounts(&self) -> &Vec<PermissionLevelWeight> {
        &self.accounts
    }

    pub fn validate(&self) -> bool {
        if (self.keys.len() + self.accounts.len()) > (1 << 16) {
            return false; // overflow protection (assumes weight_type is uint16_t and threshold is of type uint32_t)
        }
        if self.threshold == 0 {
            return false;
        }
        let mut total_weight = 0u32;
        for key in &self.keys {
            total_weight += key.weight() as u32;
        }
        for account in &self.accounts {
            total_weight += account.weight() as u32;
        }
        return total_weight >= self.threshold;
    }

    pub fn get_billable_size(&self) -> u64 {
        let accounts_size =
            self.accounts.len() as u64 * config::billable_size_v::<PermissionLevelWeight>();
        let mut keys_size: u64 = 0;

        for _ in &self.keys {
            keys_size += config::billable_size_v::<KeyWeight>();
            keys_size += 65; // 65 bytes for the public key
        }

        accounts_size + keys_size
    }
}

impl Serialize for Authority {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.threshold.serialize(bytes);
        self.keys.serialize(bytes);
        self.accounts.serialize(bytes);
    }
}

impl Deserialize for Authority {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let threshold = u32::deserialize(data, pos)?;
        let keys = Vec::<KeyWeight>::deserialize(data, pos)?;
        let accounts = Vec::<PermissionLevelWeight>::deserialize(data, pos)?;
        Ok(Authority {
            threshold,
            keys,
            accounts,
        })
    }
}

impl BillableSize for Authority {
    fn billable_size() -> u64 {
        return (3 * FIXED_OVERHEAD_SHARED_VECTOR_RAM_BYTES as u64) + 4;
    }
}
