use std::fmt;

use cxx::SharedPtr;
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
        self.key.num_bytes() + self.weight.num_bytes()
    }
}

impl Read for KeyWeight {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let key = parse_public_key_from_bytes(bytes, pos)
            .map_err(|e| pulsevm_serialization::ReadError::CustomError(format!("failed to parse public key in KeyWeight: {}", e)))?;
        let weight = u16::read(bytes, pos)?;
        Ok(KeyWeight { key, weight })
    }
}

impl Write for KeyWeight {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let packed_key = self.key.packed_bytes();
        packed_key.write(bytes, pos)?;
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