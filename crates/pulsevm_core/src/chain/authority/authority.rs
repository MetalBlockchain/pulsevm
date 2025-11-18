use std::fmt;

use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::Serialize;

use crate::chain::{
    authority::WaitWeight,
    config::{self, BillableSize, FIXED_OVERHEAD_SHARED_VECTOR_RAM_BYTES},
};

use super::{key_weight::KeyWeight, permission_level_weight::PermissionLevelWeight};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes, Serialize)]
pub struct Authority {
    pub threshold: u32,
    pub keys: Vec<KeyWeight>,
    pub accounts: Vec<PermissionLevelWeight>,
    pub waits: Vec<WaitWeight>,
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
    pub fn new(
        threshold: u32,
        keys: Vec<KeyWeight>,
        accounts: Vec<PermissionLevelWeight>,
        waits: Vec<WaitWeight>,
    ) -> Self {
        Authority {
            threshold,
            keys,
            accounts,
            waits,
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
        // TODO: Validate waits
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
        // TODO: Validate waits
        accounts_size + keys_size
    }
}

impl BillableSize for Authority {
    fn billable_size() -> u64 {
        return (3 * FIXED_OVERHEAD_SHARED_VECTOR_RAM_BYTES as u64) + 4;
    }
}
