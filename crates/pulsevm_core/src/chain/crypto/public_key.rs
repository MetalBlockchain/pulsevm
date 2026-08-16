use std::{
    fmt::{
        self,
        Debug,
        Display,
    },
    hash::{
        Hash,
        Hasher,
    },
    str::FromStr,
};

use pulsevm_crypto::{
    FixedBytes,
    K1PublicKey,
};
use pulsevm_error::ChainError;
use pulsevm_serialization::{
    NumBytes,
    Read,
    ReadError,
    Write,
    WriteError,
};
use serde::{
    Deserialize,
    Serialize,
};

/// A secp256k1 (`K1`) public key. Pure Rust: parsing, packing, string encoding
/// and equality all run through [`K1PublicKey`], not the C++ crypto.
#[derive(Clone, Copy)]
pub struct PublicKey {
    inner: K1PublicKey,
}

impl PublicKey {
    pub fn new(inner: K1PublicKey) -> Self {
        PublicKey { inner }
    }

    pub fn k1(&self) -> &K1PublicKey {
        &self.inner
    }

    /// Consume this wrapper into the underlying pure-Rust key — for building a
    /// `KeyWeight`, which stores the `K1PublicKey` directly.
    pub fn into_k1(self) -> K1PublicKey {
        self.inner
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.to_string())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.to_string())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.compressed() == other.inner.compressed()
    }
}

impl Eq for PublicKey {}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.compressed().hash(state);
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.compressed().cmp(&other.inner.compressed())
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let k1 = K1PublicKey::from_string(&s)
            .map_err(|e| serde::de::Error::custom(format!("Failed to parse public key: {}", e)))?;
        Ok(PublicKey { inner: k1 })
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.inner.to_string())
    }
}

impl NumBytes for PublicKey {
    fn num_bytes(&self) -> usize {
        34 // Fixed size for packed public key representation
    }
}

impl Read for PublicKey {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let packed = FixedBytes::<34>::read(bytes, pos)?;
        let k1 = K1PublicKey::from_packed(packed.as_ref())
            .map_err(|e| ReadError::CustomError(e.to_string()))?;
        Ok(PublicKey { inner: k1 })
    }
}

impl Write for PublicKey {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let packed = FixedBytes::<34>(self.inner.to_packed());
        packed.write(bytes, pos)
    }
}

impl FromStr for PublicKey {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let k1 = K1PublicKey::from_string(s).map_err(|e| ChainError::ParseError(e.to_string()))?;
        Ok(PublicKey { inner: k1 })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        str::FromStr,
    };

    use crate::crypto::PublicKey;

    #[test]
    fn test_public_key_display() {
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

    #[test]
    fn test_public_key_not_equals() {
        let key_1_str = "PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H";
        let key_2_str = "PUB_K1_5JF4aXt1DrtCLioNsL4ZEcDq88PAXtLjVn5uwhrCUeYBHAw7YD";
        let public_key_1 = PublicKey::from_str(key_1_str).unwrap();
        let public_key_2 = PublicKey::from_str(key_2_str).unwrap();
        assert!(public_key_1 != public_key_2);
    }

    #[test]
    fn test_public_key_equals() {
        let key_1_str = "PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H";
        let key_2_str = "PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H";
        let public_key_1 = PublicKey::from_str(key_1_str).unwrap();
        let public_key_2 = PublicKey::from_str(key_2_str).unwrap();
        assert!(public_key_1 == public_key_2);
    }
}
