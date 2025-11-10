use std::{fmt, str::FromStr};

use pulsevm_serialization::{NumBytes, Read, Write};
use ripemd::{Digest, Ripemd160};
use secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use crate::chain::{error::ChainError, secp256k1::KeyType};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    pub key_type: KeyType,
    pub key: secp256k1::PublicKey,
}

impl PublicKey {
    /// Create a new PublicKey from a secp256k1::PublicKey, defaulting to KeyType::K1
    pub fn new(key: secp256k1::PublicKey) -> Self {
        PublicKey {
            key_type: KeyType::K1,
            key,
        }
    }
}

/// EOS-style helpers
fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut h = Ripemd160::new();
    h.update(data);
    let out = h.finalize();
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&out);
    arr
}

/// Compute EOS checksum (first 4 bytes of RIPEMD160)
fn eos_checksum(data: &[u8]) -> [u8; 4] {
    let d = ripemd160(data);
    [d[0], d[1], d[2], d[3]]
}

/// Decode a PUB_K1_ base58 string into the 33-byte compressed key, verifying checksum.
/// Checksum = RIPEMD160(key || "K1")[0..4]
fn decode_pub_k1(s: &str) -> Result<[u8; 33], ChainError> {
    let b58 = s
        .strip_prefix("PUB_K1_")
        .ok_or_else(|| ChainError::AuthorizationError("invalid PUB_K1 prefix".into()))?;

    let data = bs58::decode(b58)
        .into_vec()
        .map_err(|e| ChainError::AuthorizationError(format!("invalid base58: {e}")))?;

    if data.len() != 33 + 4 {
        return Err(ChainError::AuthorizationError(
            "invalid PUB_K1 length".into(),
        ));
    }
    let (key_bytes, cksum) = data.split_at(33);

    let mut to_hash = Vec::with_capacity(33 + 2);
    to_hash.extend_from_slice(key_bytes);
    to_hash.extend_from_slice(b"K1");
    let expected = eos_checksum(&to_hash);

    if cksum != expected {
        return Err(ChainError::AuthorizationError(
            "PUB_K1 checksum mismatch".into(),
        ));
    }

    let mut out = [0u8; 33];
    out.copy_from_slice(key_bytes);
    Ok(out)
}

/// Decode a legacy EOS… (K1) public key into the 33-byte compressed key, verifying checksum.
/// Checksum = RIPEMD160(key)[0..4]
fn decode_legacy_eos_k1(s: &str) -> Result<[u8; 33], ChainError> {
    let b58 = s
        .strip_prefix("EOS")
        .ok_or_else(|| ChainError::AuthorizationError("invalid EOS prefix".into()))?;

    let data = bs58::decode(b58)
        .into_vec()
        .map_err(|e| ChainError::AuthorizationError(format!("invalid base58: {e}")))?;

    if data.len() != 33 + 4 {
        return Err(ChainError::AuthorizationError(
            "invalid EOS key length".into(),
        ));
    }
    let (key_bytes, cksum) = data.split_at(33);

    let expected = eos_checksum(key_bytes);
    if cksum != expected {
        return Err(ChainError::AuthorizationError(
            "EOS legacy checksum mismatch".into(),
        ));
    }

    let mut out = [0u8; 33];
    out.copy_from_slice(key_bytes);
    Ok(out)
}

/// Encode to EOS new-format PUB_K1_ string
fn encode_pub_k1(key33: &[u8; 33]) -> String {
    let mut to_hash = Vec::with_capacity(33 + 2);
    to_hash.extend_from_slice(key33);
    to_hash.extend_from_slice(b"K1");
    let cksum = eos_checksum(&to_hash);

    let mut payload = Vec::with_capacity(33 + 4);
    payload.extend_from_slice(key33);
    payload.extend_from_slice(&cksum);

    format!("PUB_K1_{}", bs58::encode(payload).into_string())
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // By default, output EOS new-format PUB_K1_
        let key33 = self.key.serialize(); // compressed [u8; 33]
        let s = encode_pub_k1(&key33);
        write!(f, "{}", s)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PublicKey::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl FromStr for PublicKey {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Accept:
        // 1) New-format: PUB_K1_<base58>
        // 2) Legacy: EOS<base58>
        // 3) Raw 33-byte hex (compressed secp256k1)
        let key_bytes_33: [u8; 33] = if s.starts_with("PUB_K1_") {
            decode_pub_k1(s)?
        } else if s.starts_with("EOS") {
            decode_legacy_eos_k1(s)?
        } else {
            // Try hex (compressed)
            let s_clean = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s_clean)
                .map_err(|e| ChainError::AuthorizationError(format!("invalid hex: {e}")))?;
            if bytes.len() != 33 {
                return Err(ChainError::AuthorizationError(
                    "hex must be 33 compressed bytes".into(),
                ));
            }
            let mut tmp = [0u8; 33];
            tmp.copy_from_slice(&bytes);
            tmp
        };

        // Build secp256k1 key
        let key = Secp256k1PublicKey::from_slice(&key_bytes_33).map_err(|e| {
            ChainError::AuthorizationError(format!("invalid public key bytes: {e}"))
        })?;

        Ok(PublicKey::new(key))
    }
}

impl Read for PublicKey {
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        KeyType::read(data, pos)?; // Currently ignored, always K1
        if *pos + 33 > data.len() {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes);
        }
        let mut id = [0u8; 33];
        id.copy_from_slice(&data[*pos..*pos + 33]);
        *pos += 33;
        let key = secp256k1::PublicKey::from_slice(&id)
            .map_err(|_| pulsevm_serialization::ReadError::ParseError)?;
        Ok(PublicKey::new(key))
    }
}

impl NumBytes for PublicKey {
    fn num_bytes(&self) -> usize {
        1 + 33 // Type + compressed public key size
    }
}

impl Write for PublicKey {
    fn write(
        &self,
        bytes: &mut [u8],
        pos: &mut usize,
    ) -> Result<(), pulsevm_serialization::WriteError> {
        KeyType::K1.write(bytes, pos)?;
        if *pos + 33 > bytes.len() {
            return Err(pulsevm_serialization::WriteError::NotEnoughSpace);
        }
        let compressed = self.key.serialize();
        bytes[*pos..*pos + 33].copy_from_slice(&compressed);
        *pos += 33;
        Ok(())
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_byte_array(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = Secp256k1PublicKey::from_secret_key(&secp, &secret_key);
        PublicKey::new(public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_roundtrip_pub_k1() {
        // Compressed hex from your original test vector
        let hex_key = "030cd6c38a327849690b655003c50ca781d0f7020cc17e29428def19a342458961";
        let pk = PublicKey::from_str(hex_key).unwrap();

        // to_string now emits PUB_K1_...
        let s = pk.to_string();
        assert!(s.starts_with("PUB_K1_"));

        // Parse back from PUB_K1_ form
        let pk2 = PublicKey::from_str(&s).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_public_key_accepts_legacy_eos() {
        // Build PUB_K1 string first, then manually transform to legacy EOS to test acceptance.
        // NOTE: This isn't a strict EOS fixture, but ensures our decoder path works.
        let hex_key = "030cd6c38a327849690b655003c50ca781d0f7020cc17e29428def19a342458961";
        let pk = PublicKey::from_str(hex_key).unwrap();
        let key33 = pk.key.serialize();

        // Make a legacy EOS string: base58(key || ripemd160(key)[0..4])
        let mut payload = Vec::from(key33.as_slice());
        let cksum = super::eos_checksum(&key33);
        payload.extend_from_slice(&cksum);
        let legacy = format!("EOS{}", bs58::encode(payload).into_string());

        let parsed = PublicKey::from_str(&legacy).unwrap();
        assert_eq!(pk, parsed);
    }

    #[test]
    fn test_public_key_serialize_deserialize_bytes() {
        let hex_key = "030cd6c38a327849690b655003c50ca781d0f7020cc17e29428def19a342458961";
        let public_key = PublicKey::from_str(hex_key).unwrap();

        let serialized: Vec<u8> = public_key.pack().unwrap();
        let mut pos = 0;
        let deserialized = PublicKey::read(&serialized, &mut pos).unwrap();

        assert_eq!(public_key, deserialized);
    }
}
