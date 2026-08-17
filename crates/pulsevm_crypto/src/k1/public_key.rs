use secp256k1::PublicKey as SecpPublicKey;

use super::{
    K1_SUFFIX,
    K1_TAG,
    K1Error,
    decode_b58_checked,
    encode_b58_checked,
};

/// A secp256k1 public key in the EOSIO/Antelope `K1` encoding.
///
/// The canonical in-memory form is the 33-byte compressed point, exactly what
/// `fc::ecc::public_key::serialize()` returns.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct K1PublicKey {
    compressed: [u8; 33],
}

impl K1PublicKey {
    /// Wrap an already-validated secp256k1 public key.
    pub fn from_secp(key: &SecpPublicKey) -> Self {
        K1PublicKey {
            compressed: key.serialize(),
        }
    }

    /// Parse a 33-byte compressed point.
    pub fn from_compressed(bytes: &[u8; 33]) -> Result<Self, K1Error> {
        // Validate that the bytes are a real point on the curve.
        let key = SecpPublicKey::from_slice(bytes)?;
        Ok(K1PublicKey {
            compressed: key.serialize(),
        })
    }

    /// The 33-byte compressed point.
    pub fn compressed(&self) -> [u8; 33] {
        self.compressed
    }

    /// The underlying secp256k1 public key.
    pub fn to_secp(&self) -> SecpPublicKey {
        // The stored bytes always came from a validated key.
        SecpPublicKey::from_slice(&self.compressed).expect("stored compressed point is valid")
    }

    /// The 34-byte `fc::raw::pack` form: a `0x00` K1 tag followed by the 33
    /// compressed bytes.
    pub fn to_packed(&self) -> [u8; 34] {
        let mut out = [0u8; 34];
        out[0] = K1_TAG;
        out[1..].copy_from_slice(&self.compressed);
        out
    }

    /// Parse the 34-byte packed form (`fc::raw::unpack`).
    pub fn from_packed(bytes: &[u8]) -> Result<Self, K1Error> {
        if bytes.len() != 34 {
            return Err(K1Error::BadLength);
        }
        if bytes[0] != K1_TAG {
            return Err(K1Error::BadKeyType);
        }
        let mut compressed = [0u8; 33];
        compressed.copy_from_slice(&bytes[1..]);
        Self::from_compressed(&compressed)
    }

    /// The `PUB_K1_...` string form.
    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        format!("PUB_K1_{}", encode_b58_checked(&self.compressed, K1_SUFFIX))
    }

    /// Parse a `PUB_K1_...` string.
    pub fn from_string(s: &str) -> Result<Self, K1Error> {
        let data = s.strip_prefix("PUB_K1_").ok_or(K1Error::BadPrefix)?;
        let bytes = decode_b58_checked(data, 33, K1_SUFFIX)?;
        let mut compressed = [0u8; 33];
        compressed.copy_from_slice(&bytes);
        Self::from_compressed(&compressed)
    }
}

impl core::fmt::Display for K1PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl core::fmt::Debug for K1PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "K1PublicKey({})", self.to_string())
    }
}
