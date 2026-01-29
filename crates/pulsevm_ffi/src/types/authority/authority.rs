use std::fmt;

use cxx::SharedPtr;
use pulsevm_serialization::{NumBytes, Read, Write, WriteError};
use serde::{Serialize, ser::SerializeStruct};

use crate::{CxxPublicKey, bridge::ffi::{Authority, KeyWeight, PermissionLevelWeight, WaitWeight}};

impl Authority {
    pub fn new(threshold: u32, keys: Vec<KeyWeight>, accounts: Vec<PermissionLevelWeight>, waits: Vec<WaitWeight>) -> Self {
        Authority {
            threshold,
            keys,
            accounts,
            waits,
        }
    }

    pub fn new_from_public_key(key: SharedPtr<CxxPublicKey>) -> Self {        
        Authority {
            threshold: 1,
            keys: vec![KeyWeight::new(key, 1)],
            accounts: Vec::new(),
            waits: Vec::new(),
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

    pub fn waits(&self) -> &Vec<WaitWeight> {
        &self.waits
    }

    pub fn validate(&self) -> bool {
        return true;
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Authority(threshold: {}, keys: {:?}, accounts: {:?}, waits: {:?})",
            self.threshold, self.keys, self.accounts, self.waits
        )
    }
}

impl fmt::Debug for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority")
            .field("threshold", &self.threshold)
            .field("keys", &self.keys)
            .field("accounts", &self.accounts)
            .field("waits", &self.waits)
            .finish()
    }
}

impl NumBytes for Authority {
    fn num_bytes(&self) -> usize {
        self.threshold.num_bytes() + self.keys.num_bytes() + self.accounts.num_bytes() + self.waits.num_bytes()
    }
}

impl Read for Authority {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let threshold = u32::read(bytes, pos)?;
        let keys = Vec::<KeyWeight>::read(bytes, pos)?;
        let accounts = Vec::<PermissionLevelWeight>::read(bytes, pos)?;
        let waits = Vec::<WaitWeight>::read(bytes, pos)?;
        Ok(Authority {
            threshold,
            keys,
            accounts,
            waits,
        })
    }
}

impl Write for Authority {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.threshold.write(bytes, pos)?;
        self.keys.write(bytes, pos)?;
        self.accounts.write(bytes, pos)?;
        self.waits.write(bytes, pos)?;
        Ok(())
    }
}

impl Serialize for Authority {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Authority", 4)?;
        state.serialize_field("threshold", &self.threshold)?;
        state.serialize_field("keys", &self.keys)?;
        state.serialize_field("accounts", &self.accounts)?;
        state.serialize_field("waits", &self.waits)?;
        state.end()
    }
}