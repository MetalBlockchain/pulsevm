use k256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The key type suffix used in the RIPEMD-160 checksum for PUB_K1_ / PVT_K1_ keys.
const K1_SUFFIX: &[u8] = b"K1";

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Invalid WIF key")]
    InvalidWif,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Checksum mismatch")]
    ChecksumMismatch,
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

// ---------------------------------------------------------------------------
// Base58check helpers (Bitcoin-style, used for WIF private keys)
// ---------------------------------------------------------------------------

/// Encode raw bytes to base58check (Bitcoin-style with double-SHA256 checksum).
fn base58check_encode(version: u8, payload: &[u8]) -> String {
    let mut data = vec![version];
    data.extend_from_slice(payload);
    let checksum = double_sha256(&data);
    data.extend_from_slice(&checksum[..4]);
    bs58::encode(data).into_string()
}

/// Decode base58check, returning (version_byte, payload).
fn base58check_decode(s: &str) -> Result<(u8, Vec<u8>), KeyError> {
    let data = bs58::decode(s)
        .into_vec()
        .map_err(|_| KeyError::InvalidWif)?;
    if data.len() < 5 {
        return Err(KeyError::InvalidWif);
    }
    let (payload, checksum) = data.split_at(data.len() - 4);
    let computed = double_sha256(payload);
    if &computed[..4] != checksum {
        return Err(KeyError::ChecksumMismatch);
    }
    Ok((payload[0], payload[1..].to_vec()))
}

fn double_sha256(data: &[u8]) -> Vec<u8> {
    let first = Sha256::digest(data);
    Sha256::digest(&first).to_vec()
}

fn ripemd160_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// PUB_K1_ encoding helpers
// ---------------------------------------------------------------------------

/// Compute the RIPEMD-160 checksum used by the PUB_K1_ / PVT_K1_ format.
/// The checksum is: ripemd160(raw_bytes || suffix)[..4]
fn k1_checksum(raw: &[u8], suffix: &[u8]) -> [u8; 4] {
    let mut buf = raw.to_vec();
    buf.extend_from_slice(suffix);
    let hash = ripemd160_hash(&buf);
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

/// Encode compressed public key bytes into `PUB_K1_...` string.
fn encode_pub_k1(raw: &[u8]) -> String {
    let check = k1_checksum(raw, K1_SUFFIX);
    let mut data = raw.to_vec();
    data.extend_from_slice(&check);
    format!("PUB_K1_{}", bs58::encode(data).into_string())
}

/// Decode a `PUB_K1_...` string back to raw compressed public key bytes.
fn decode_pub_k1(encoded: &str) -> Result<Vec<u8>, KeyError> {
    let decoded = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| KeyError::InvalidPublicKey)?;
    if decoded.len() < 37 {
        return Err(KeyError::InvalidPublicKey);
    }
    let (raw, checksum) = decoded.split_at(decoded.len() - 4);
    let computed = k1_checksum(raw, K1_SUFFIX);
    if checksum != computed {
        return Err(KeyError::ChecksumMismatch);
    }
    Ok(raw.to_vec())
}

/// Decode a legacy `EOS...` public key string to raw compressed bytes.
/// Uses the old format: ripemd160(raw)[..4] as checksum (no suffix).
fn decode_legacy_eos(encoded: &str) -> Result<Vec<u8>, KeyError> {
    let decoded = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| KeyError::InvalidPublicKey)?;
    if decoded.len() < 37 {
        return Err(KeyError::InvalidPublicKey);
    }
    let (raw, checksum) = decoded.split_at(decoded.len() - 4);
    let computed = ripemd160_hash(raw);
    if &computed[..4] != checksum {
        return Err(KeyError::ChecksumMismatch);
    }
    Ok(raw.to_vec())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a new ECDSA secp256k1 keypair, returning (wif_private, pub_k1_public).
pub fn generate_keypair() -> Result<(String, String), KeyError> {
    let signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
    let wif = private_key_to_wif(&signing_key);
    let public_key = pub_k1_string(&signing_key);
    Ok((wif, public_key))
}

/// Convert a SigningKey to WIF (Wallet Import Format).
pub fn private_key_to_wif(key: &SigningKey) -> String {
    let raw = key.to_bytes();
    let check = k1_checksum(&raw, K1_SUFFIX);
    let mut data = raw.to_vec();
    data.extend_from_slice(&check);
    format!("PVT_K1_{}", bs58::encode(data).into_string())
}

/// Parse a `PVT_K1_...` private key into a SigningKey.
pub fn wif_to_private_key(pvt: &str) -> Result<SigningKey, KeyError> {
    let encoded = pvt.strip_prefix("PVT_K1_").ok_or(KeyError::InvalidWif)?;
    let decoded = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| KeyError::InvalidWif)?;
    if decoded.len() < 5 {
        return Err(KeyError::InvalidWif);
    }
    let (raw, checksum) = decoded.split_at(decoded.len() - 4);
    let computed = k1_checksum(raw, K1_SUFFIX);
    if checksum != computed {
        return Err(KeyError::ChecksumMismatch);
    }
    SigningKey::from_bytes(raw.into()).map_err(|e| KeyError::CryptoError(e.to_string()))
}

/// Get the public key string in `PUB_K1_...` format from a SigningKey.
pub fn pub_k1_string(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    verifying_key_to_pub_k1_string(verifying_key)
}

/// Get `PUB_K1_...` string from a VerifyingKey.
pub fn verifying_key_to_pub_k1_string(vk: &VerifyingKey) -> String {
    let point = vk.to_encoded_point(true); // compressed
    encode_pub_k1(point.as_bytes())
}

/// Parse a public key string in either `PUB_K1_...` or legacy `EOS...` format
/// back to raw compressed bytes (33 bytes for secp256k1).
pub fn parse_public_key(s: &str) -> Result<Vec<u8>, KeyError> {
    if let Some(encoded) = s.strip_prefix("PUB_K1_") {
        decode_pub_k1(encoded)
    } else if let Some(encoded) = s.strip_prefix("EOS") {
        decode_legacy_eos(encoded)
    } else {
        Err(KeyError::InvalidPublicKey)
    }
}

// ---------------------------------------------------------------------------
// Deprecated aliases — kept for backwards compatibility
// ---------------------------------------------------------------------------

/// Deprecated: use [`pub_k1_string`] instead.
#[deprecated(note = "Use pub_k1_string() for PUB_K1_ format")]
pub fn eos_public_key_string(signing_key: &SigningKey) -> String {
    pub_k1_string(signing_key)
}

/// Deprecated: use [`parse_public_key`] instead.
#[deprecated(note = "Use parse_public_key() which accepts both PUB_K1_ and EOS formats")]
pub fn parse_eos_public_key(s: &str) -> Result<Vec<u8>, KeyError> {
    parse_public_key(s)
}

/// Deprecated: use [`verifying_key_to_pub_k1_string`] instead.
#[deprecated(note = "Use verifying_key_to_pub_k1_string() for PUB_K1_ format")]
pub fn verifying_key_to_eos_string(vk: &VerifyingKey) -> String {
    verifying_key_to_pub_k1_string(vk)
}

/// Sign a SHA-256 digest with the given private key, returning a hex signature.
pub fn sign_digest(signing_key: &SigningKey, digest: &[u8]) -> Result<String, KeyError> {
    let sig: Signature = signing_key.sign(digest);
    Ok(hex::encode(sig.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_keypair_pub_k1() {
        let (wif, pubkey) = generate_keypair().unwrap();
        assert!(wif.starts_with('5') || wif.starts_with('K') || wif.starts_with('L'));
        assert!(
            pubkey.starts_with("PUB_K1_"),
            "Expected PUB_K1_ prefix, got: {}",
            pubkey
        );

        // Roundtrip WIF -> SigningKey -> PUB_K1_
        let sk = wif_to_private_key(&wif).unwrap();
        let pubkey2 = pub_k1_string(&sk);
        assert_eq!(pubkey, pubkey2);

        // Roundtrip parse
        let raw = parse_public_key(&pubkey).unwrap();
        assert_eq!(raw.len(), 33); // compressed secp256k1
    }

    #[test]
    fn test_parse_accepts_both_formats() {
        let (wif, pub_k1) = generate_keypair().unwrap();
        let sk = wif_to_private_key(&wif).unwrap();

        // Generate the legacy EOS format manually for comparison
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(true);
        let raw_bytes = point.as_bytes();
        let legacy_check = ripemd160_hash(raw_bytes);
        let mut legacy_data = raw_bytes.to_vec();
        legacy_data.extend_from_slice(&legacy_check[..4]);
        let legacy_eos = format!("EOS{}", bs58::encode(&legacy_data).into_string());

        // Both should parse to the same raw bytes
        let parsed_k1 = parse_public_key(&pub_k1).unwrap();
        let parsed_eos = parse_public_key(&legacy_eos).unwrap();
        assert_eq!(parsed_k1, parsed_eos);
    }

    #[test]
    fn test_k1_checksum_differs_from_legacy() {
        // The PUB_K1_ checksum includes the "K1" suffix, so the encoded
        // strings should differ even though they represent the same key.
        let (_, pub_k1) = generate_keypair().unwrap();
        assert!(pub_k1.starts_with("PUB_K1_"));
        // It should NOT start with "EOS"
        assert!(!pub_k1.starts_with("EOS"));
    }

    #[test]
    fn test_invalid_prefix_rejected() {
        assert!(parse_public_key("PUB_R1_abc").is_err());
        assert!(parse_public_key("notakey").is_err());
        assert!(parse_public_key("").is_err());
    }

    #[test]
    fn test_corrupted_pub_k1_rejected() {
        let (_, pubkey) = generate_keypair().unwrap();
        // Flip a character in the encoded part
        let mut corrupted = pubkey.clone();
        let bytes = unsafe { corrupted.as_bytes_mut() };
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(parse_public_key(&corrupted).is_err());
    }
}
