use std::{
    fmt::{self, Debug, Display},
    hash::{Hash, Hasher},
    str::FromStr,
};

use cxx::SharedPtr;
use pulsevm_error::ChainError;
use pulsevm_ffi::CxxPublicKey;
use pulsevm_serialization::{NumBytes, Read, ReadError, Write, WriteError};
use serde::Serialize;

#[derive(Clone)]
pub struct PublicKey {
    inner: SharedPtr<CxxPublicKey>,
}

impl PublicKey {
    pub fn new(inner: SharedPtr<CxxPublicKey>) -> Self {
        PublicKey { inner }
    }

    pub fn new_unknown() -> Self {
        let cxx_key = pulsevm_ffi::make_unknown_public_key();
        PublicKey { inner: cxx_key }
    }

    pub fn inner(&self) -> SharedPtr<CxxPublicKey> {
        self.inner.clone()
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.to_string_rust())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.to_string_rust())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.packed_bytes() == other.inner.packed_bytes()
    }
}

impl Eq for PublicKey {}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.packed_bytes().hash(state);
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.inner.to_string_rust())
    }
}

impl NumBytes for PublicKey {
    fn num_bytes(&self) -> usize {
        self.inner.num_bytes().num_bytes() + self.inner.num_bytes() // Encode is as a vec<u8>
    }
}

impl Read for PublicKey {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let packed = Vec::<u8>::read(bytes, pos)?;
        let cxx_key = pulsevm_ffi::parse_public_key_from_bytes(&packed).map_err(|e| ReadError::CustomError(e.to_string()))?;
        Ok(PublicKey { inner: cxx_key })
    }
}

impl Write for PublicKey {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let packed = self.inner.packed_bytes();
        packed.write(bytes, pos)
    }
}

impl From<PublicKey> for SharedPtr<CxxPublicKey> {
    fn from(value: PublicKey) -> Self {
        value.inner()
    }
}

impl FromStr for PublicKey {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cxx_key = pulsevm_ffi::parse_public_key(s).map_err(|e| ChainError::ParseError(e.to_string()))?;
        Ok(PublicKey { inner: cxx_key })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr};

    use crate::crypto::PublicKey;

    #[test]
    fn test_public_key_display() {
        use std::str::FromStr;
        let key_str = "PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H";
        let public_key = PublicKey::from_str(key_str).unwrap();
        assert_eq!(public_key.to_string(), key_str);
    }

    #[test]
    fn test_public_key_hash() {
        let mut set = HashSet::new();
        let key_str = "PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H";
        let public_key = PublicKey::from_str(key_str).unwrap();
        set.insert(public_key);
        let public_key2 = PublicKey::from_str(key_str).unwrap();
        assert!(set.contains(&public_key2));
    }
}
