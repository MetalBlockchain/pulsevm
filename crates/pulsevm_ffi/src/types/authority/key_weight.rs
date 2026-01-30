use std::fmt;

use cxx::{SharedPtr, UniquePtr};
use pulsevm_billable_size::BillableSize;
use pulsevm_serialization::{NumBytes, Read, Write, WriteError};
use serde::{Serialize, ser::SerializeStruct};

use crate::{CxxPublicKey, bridge::ffi::KeyWeight, parse_public_key_from_bytes};

impl KeyWeight {
    pub fn new(key: SharedPtr<CxxPublicKey>, weight: u16) -> Self {
        KeyWeight { key, weight }
    }
}

impl fmt::Debug for KeyWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWeight")
            .field("key", &self.key.to_string_rust())
            .field("weight", &self.weight)
            .finish()
    }
}

impl NumBytes for KeyWeight {
    fn num_bytes(&self) -> usize {
        // Add the number of bytes for the packed public key and the weight
        self.key.num_bytes().num_bytes() + self.key.num_bytes() + self.weight.num_bytes()
    }
}

impl Read for KeyWeight {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let packed_key = Vec::<u8>::read(bytes, pos)?;
        let key = parse_public_key_from_bytes(&packed_key)
            .map_err(|e| pulsevm_serialization::ReadError::CustomError(format!("failed to parse public key in KeyWeight: {}", e)))?;
        let weight = u16::read(bytes, pos)?;
        Ok(KeyWeight { key, weight })
    }
}

impl Write for KeyWeight {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.key.packed_bytes().write(bytes, pos)?;
        self.weight.write(bytes, pos)?;
        Ok(())
    }
}

impl Serialize for KeyWeight {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("KeyWeight", 2)?;
        state.serialize_field("key", &self.key.to_string_rust())?;
        state.serialize_field("weight", &self.weight)?;
        state.end()
    }
}

impl BillableSize for KeyWeight {
    const OVERHEAD: u64 = 0;
    const VALUE: u64 = 8;
}