use pulsevm_serialization::{Deserialize, Serialize};

use super::{KeyWeight, PermissionLevelWeight};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Authority {
    threshold: u32,
    keys: Vec<KeyWeight>,
    accounts: Vec<PermissionLevelWeight>,
}

impl Authority {
    pub fn new(threshold: u32, keys: Vec<KeyWeight>, accounts: Vec<PermissionLevelWeight>) -> Self {
        Authority { threshold, keys, accounts }
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
}

impl Serialize for Authority {
    fn serialize(
        &self,
        bytes: &mut Vec<u8>,
    ) {
        self.threshold.serialize(bytes);
        self.keys.serialize(bytes);
        self.accounts.serialize(bytes);
    }
}

impl Deserialize for Authority {
    fn deserialize(
        data: &[u8],
        pos: &mut usize
    ) -> Result<Self, pulsevm_serialization::ReadError> {
        let threshold = u32::deserialize(data, pos)?;
        let keys = Vec::<KeyWeight>::deserialize(data, pos)?;
        let accounts = Vec::<PermissionLevelWeight>::deserialize(data, pos)?;
        Ok(Authority { threshold, keys, accounts })
    }
}