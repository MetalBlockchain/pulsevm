use std::fmt;

use pulsevm_serialization::{NumBytes, Read, Write, WriteError};
use serde::{Serialize, ser::SerializeStruct};

use crate::bridge::ffi::{PermissionLevel, PermissionLevelWeight};

impl fmt::Debug for PermissionLevelWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PermissionLevelWeight")
            .field("permission", &self.permission)
            .field("weight", &self.weight)
            .finish()
    }
}

impl NumBytes for PermissionLevelWeight {
    fn num_bytes(&self) -> usize {
        self.permission.num_bytes() + self.weight.num_bytes()
    }
}

impl Read for PermissionLevelWeight {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let permission = PermissionLevel::read(bytes, pos)?;
        let weight = u16::read(bytes, pos)?;
        Ok(PermissionLevelWeight { permission, weight })
    }
}

impl Write for PermissionLevelWeight {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.permission.write(bytes, pos)?;
        self.weight.write(bytes, pos)?;
        Ok(())
    }
}

impl Serialize for PermissionLevelWeight {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PermissionLevelWeight", 2)?;
        state.serialize_field("permission", &self.permission)?;
        state.serialize_field("weight", &self.weight)?;
        state.end()
    }
}