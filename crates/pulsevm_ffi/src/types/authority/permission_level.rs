use std::{cmp::Ordering, fmt};

use pulsevm_name::Name;
use pulsevm_serialization::{NumBytes, Read, Write, WriteError};
use serde::{Serialize, ser::SerializeStruct};

use crate::bridge::ffi::PermissionLevel;

impl PermissionLevel {
    pub fn new(actor: u64, permission: u64) -> Self {
        PermissionLevel { actor, permission }
    }

    pub fn actor(&self) -> u64 {
        self.actor
    }

    pub fn permission(&self) -> u64 {
        self.permission
    }
}

impl fmt::Debug for PermissionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PermissionLevel")
            .field("actor", &Name::new(self.actor))
            .field("permission", &Name::new(self.permission))
            .finish()
    }
}

impl fmt::Display for PermissionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{}",
            Name::new(self.actor),
            Name::new(self.permission)
        )
    }
}

impl NumBytes for PermissionLevel {
    fn num_bytes(&self) -> usize {
        self.actor.num_bytes() + self.permission.num_bytes()
    }
}

impl Read for PermissionLevel {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let actor = u64::read(bytes, pos)?;
        let permission = u64::read(bytes, pos)?;
        Ok(PermissionLevel { actor, permission })
    }
}

impl Write for PermissionLevel {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.actor.write(bytes, pos)?;
        self.permission.write(bytes, pos)?;
        Ok(())
    }
}

impl Serialize for PermissionLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PermissionLevel", 2)?;
        state.serialize_field("actor", &self.actor)?;
        state.serialize_field("permission", &self.permission)?;
        state.end()
    }
}

impl From<(u64, u64)> for PermissionLevel {
    fn from(tuple: (u64, u64)) -> Self {
        PermissionLevel {
            actor: tuple.0,
            permission: tuple.1,
        }
    }
}

impl Ord for PermissionLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.actor, self.permission).cmp(&(other.actor, other.permission))
    }
}

impl PartialOrd for PermissionLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
