use core::{fmt, str};
use std::{
    cmp::Ordering,
    fmt::Debug,
    hash::{Hash, Hasher},
    str::FromStr,
    sync::Arc,
};

use cxx::UniquePtr;
use pulsevm_error::ChainError;
use pulsevm_ffi::{Name as FfiName, u64_to_name};
use pulsevm_name::{NAME_MAX_LEN, name_from_bytes, name_to_bytes};
use pulsevm_serialization::{NumBytes, Read, ReadError, Write, WriteError};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct Name {
    inner: Arc<UniquePtr<FfiName>>,
}

impl Name {
    pub fn new(value: u64) -> Self {
        let ffi_name = u64_to_name(value);

        Name {
            inner: Arc::new(ffi_name),
        }
    }

    pub fn as_u64(&self) -> u64 {
        self.inner.to_uint64_t()
    }

    pub fn empty(&self) -> bool {
        self.inner.empty()
    }

    pub fn as_bytes(&self) -> [u8; NAME_MAX_LEN] {
        name_to_bytes(self.inner.to_uint64_t())
    }

    pub fn as_ref(&self) -> &FfiName {
        &self.inner
    }
}

impl Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.to_string())
    }
}

impl From<u64> for Name {
    fn from(n: u64) -> Self {
        Name::new(n)
    }
}

impl From<&FfiName> for Name {
    fn from(ffi_name: &FfiName) -> Self {
        Name {
            inner: Arc::new(u64_to_name(ffi_name.to_uint64_t())),
        }
    }
}

impl FromStr for Name {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // First try to parse as u64
        if let Ok(value) = s.parse::<u64>() {
            return Ok(value.into()); // assuming `u64: Into<YourType>`
        }

        let name = name_from_bytes(s.bytes())
            .map_err(|e| ChainError::ParseError(format!("invalid name format: {}", e)))?;
        Ok(name.into())
    }
}

impl fmt::Display for Name {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.as_bytes();
        let value = str::from_utf8(&bytes)
            .map(|s| s.trim_end_matches('.'))
            .map_err(|_| fmt::Error)?;
        write!(f, "{}", value)
    }
}

impl PartialEq<u64> for Name {
    fn eq(&self, other: &u64) -> bool {
        &self.inner.to_uint64_t() == other
    }
}

impl PartialEq<Name> for u64 {
    fn eq(&self, other: &Name) -> bool {
        self == &other.inner.to_uint64_t()
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.inner.to_uint64_t() == other.inner.to_uint64_t()
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.to_uint64_t().hash(state);
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.to_uint64_t().cmp(&other.inner.to_uint64_t())
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Default for Name {
    fn default() -> Self {
        Name::new(0)
    }
}

impl Serialize for Name {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Name::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl NumBytes for Name {
    fn num_bytes(&self) -> usize {
        8
    }
}

impl Read for Name {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let res = u64::read(bytes, pos)?;
        Ok(Name::new(res))
    }
}

impl Write for Name {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.as_u64().write(bytes, pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        let name = Name::new(6138663577826885632);
        assert_eq!(name.as_u64(), 6138663577826885632);
        assert_eq!(name.to_string(), "eosio");
    }

    #[test]
    fn test_name_from_str() {
        let name = Name::from_str("eosio").unwrap();
        assert_eq!(name.as_u64(), 6138663577826885632);
    }
}
