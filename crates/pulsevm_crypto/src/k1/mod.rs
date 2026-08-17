//! Pure-Rust reimplementation of the EOSIO/Antelope `K1` (secp256k1) key,
//! signature and private-key formats.
//!
//! This mirrors, byte-for-byte, the `fc::crypto` C++ implementation that the
//! `pulsevm_database` cxx bridge currently wraps. It is consensus-critical: the
//! packed and string encodings, the recovered public keys and the canonical
//! signature predicate must all match the C++ oracle exactly.
//!
//! Only the `K1` suite (secp256k1) is implemented here. `R1` (secp256r1) and
//! `WA` (WebAuthn) are intentionally out of scope; they are not reached on any
//! replay/consensus path in this workspace.

use ripemd::{
    Digest as _,
    Ripemd160,
};

mod private_key;
mod public_key;
mod signature;

pub use private_key::K1PrivateKey;
pub use public_key::K1PublicKey;
pub use signature::K1Signature;

/// Errors produced while parsing or constructing K1 crypto objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum K1Error {
    /// The string was missing the expected `PUB_K1_` / `PVT_K1_` / `SIG_K1_`
    /// (or legacy) prefix.
    BadPrefix,
    /// The base58 payload could not be decoded.
    BadBase58,
    /// The decoded payload had the wrong length for this object.
    BadLength,
    /// The 4-byte ripemd160 checksum did not match.
    BadChecksum,
    /// The packed byte blob carried an unexpected key-type tag (non-K1).
    BadKeyType,
    /// The underlying secp256k1 primitive rejected the bytes.
    Secp(secp256k1::Error),
}

impl core::fmt::Display for K1Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            K1Error::BadPrefix => write!(f, "invalid key prefix"),
            K1Error::BadBase58 => write!(f, "invalid base58 data"),
            K1Error::BadLength => write!(f, "invalid data length"),
            K1Error::BadChecksum => write!(f, "checksum mismatch"),
            K1Error::BadKeyType => write!(f, "unexpected key type tag"),
            K1Error::Secp(e) => write!(f, "secp256k1 error: {e}"),
        }
    }
}

impl std::error::Error for K1Error {}

impl From<secp256k1::Error> for K1Error {
    fn from(e: secp256k1::Error) -> Self {
        K1Error::Secp(e)
    }
}

/// The key-type tag byte fc prepends when packing the `std::variant`. K1 is
/// index 0 in every one of the public-key / signature variants.
pub(crate) const K1_TAG: u8 = 0x00;

/// The ASCII suffix fc mixes into the ripemd160 checksum for the modern
/// `*_K1_` string encodings.
pub(crate) const K1_SUFFIX: &[u8] = b"K1";

/// The first four bytes of `ripemd160(data || suffix)`, exactly the checksum fc
/// stores in `checksummed_data`.
pub(crate) fn ripemd_checksum(data: &[u8], suffix: &[u8]) -> [u8; 4] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    if !suffix.is_empty() {
        hasher.update(suffix);
    }
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// Encode `data` the way fc does: `base58(data || ripemd160(data || suffix)[..4])`.
pub(crate) fn encode_b58_checked(data: &[u8], suffix: &[u8]) -> String {
    let checksum = ripemd_checksum(data, suffix);
    let mut blob = Vec::with_capacity(data.len() + 4);
    blob.extend_from_slice(data);
    blob.extend_from_slice(&checksum);
    bs58::encode(blob).into_string()
}

/// Inverse of [`encode_b58_checked`]: decode the base58, split off and verify the
/// trailing 4-byte checksum, and return the `data_len`-byte payload.
pub(crate) fn decode_b58_checked(
    s: &str,
    data_len: usize,
    suffix: &[u8],
) -> Result<Vec<u8>, K1Error> {
    let blob = bs58::decode(s).into_vec().map_err(|_| K1Error::BadBase58)?;
    if blob.len() != data_len + 4 {
        return Err(K1Error::BadLength);
    }
    let (data, checksum) = blob.split_at(data_len);
    if ripemd_checksum(data, suffix) != checksum {
        return Err(K1Error::BadChecksum);
    }
    Ok(data.to_vec())
}
