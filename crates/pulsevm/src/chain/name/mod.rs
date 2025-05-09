use core::{fmt, str};
use std::str::FromStr;

use pulsevm_name::{ParseNameError, name_from_bytes, name_to_bytes};
use pulsevm_serialization::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Name(u64);

impl Name {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    pub const fn empty(&self) -> bool {
        self.0 == 0
    }
}

impl From<u64> for Name {
    fn from(n: u64) -> Self {
        Self(n)
    }
}

impl From<Name> for u64 {
    fn from(i: Name) -> Self {
        i.0
    }
}

impl FromStr for Name {
    type Err = ParseNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = name_from_bytes(s.bytes())?;
        Ok(name.into())
    }
}

impl fmt::Display for Name {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = name_to_bytes(self.0);
        let value = str::from_utf8(&bytes)
            .map(|s| s.trim_end_matches('.'))
            .map_err(|_| fmt::Error)?;
        write!(f, "{}", value)
    }
}

impl PartialEq<u64> for Name {
    fn eq(&self, other: &u64) -> bool {
        &self.0 == other
    }
}

impl Serialize for Name {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.0.serialize(bytes);
    }
}

impl Deserialize for Name {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let value = u64::deserialize(data, pos)?;
        Ok(Name(value))
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_name() {
        let name = Name::new(0x1234567890abcdef);
        assert_eq!(name.as_u64(), 0x1234567890abcdef);
        assert_eq!(name.to_string(), "1234567890abcdef");
    }

    #[test]
    fn test_name_from_str() {
        let name = Name::from_str("test").unwrap();
        assert_eq!(name.as_u64(), 0x7465737400000000);
    }
}
