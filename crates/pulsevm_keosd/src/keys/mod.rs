use k256::ecdsa::{SigningKey, VerifyingKey, signature::Signer, Signature};
use ripemd::Ripemd160;
use sha2::{Sha256, Digest};
use thiserror::Error;

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
    let data = bs58::decode(s).into_vec().map_err(|_| KeyError::InvalidWif)?;
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

/// Generate a new ECDSA secp256k1 keypair, returning (wif_private, eos_public).
pub fn generate_keypair() -> Result<(String, String), KeyError> {
    let signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
    let wif = private_key_to_wif(&signing_key);
    let public_key = eos_public_key_string(&signing_key);
    Ok((wif, public_key))
}

/// Convert a SigningKey to WIF (Wallet Import Format).
pub fn private_key_to_wif(key: &SigningKey) -> String {
    let secret_bytes = key.to_bytes();
    base58check_encode(0x80, &secret_bytes)
}

/// Parse a WIF-encoded private key into a SigningKey.
pub fn wif_to_private_key(wif: &str) -> Result<SigningKey, KeyError> {
    let (version, payload) = base58check_decode(wif)?;
    if version != 0x80 {
        return Err(KeyError::InvalidWif);
    }
    // Some WIF keys have a compression flag byte appended
    let key_bytes = if payload.len() == 33 && payload[32] == 0x01 {
        &payload[..32]
    } else if payload.len() == 32 {
        &payload
    } else {
        return Err(KeyError::InvalidWif);
    };
    SigningKey::from_bytes(key_bytes.into())
        .map_err(|e| KeyError::CryptoError(e.to_string()))
}

/// Get the EOS-formatted public key string (e.g. "EOS6MRy...").
pub fn eos_public_key_string(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(true); // compressed
    let raw = point.as_bytes();
    let check = ripemd160_hash(raw);
    let mut data = raw.to_vec();
    data.extend_from_slice(&check[..4]);
    format!("EOS{}", bs58::encode(data).into_string())
}

/// Parse an EOS public key string back to raw compressed bytes.
pub fn parse_eos_public_key(s: &str) -> Result<Vec<u8>, KeyError> {
    let trimmed = s.strip_prefix("EOS").ok_or(KeyError::InvalidPublicKey)?;
    let decoded = bs58::decode(trimmed).into_vec().map_err(|_| KeyError::InvalidPublicKey)?;
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

/// Get EOS public key string from a VerifyingKey.
pub fn verifying_key_to_eos_string(vk: &VerifyingKey) -> String {
    let point = vk.to_encoded_point(true);
    let raw = point.as_bytes();
    let check = ripemd160_hash(raw);
    let mut data = raw.to_vec();
    data.extend_from_slice(&check[..4]);
    format!("EOS{}", bs58::encode(data).into_string())
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
    fn test_roundtrip_keypair() {
        let (wif, pubkey) = generate_keypair().unwrap();
        assert!(wif.starts_with('5') || wif.starts_with('K') || wif.starts_with('L'));
        assert!(pubkey.starts_with("EOS"));

        // Roundtrip WIF
        let sk = wif_to_private_key(&wif).unwrap();
        let pubkey2 = eos_public_key_string(&sk);
        assert_eq!(pubkey, pubkey2);

        // Roundtrip public key parse
        let raw = parse_eos_public_key(&pubkey).unwrap();
        assert_eq!(raw.len(), 33); // compressed
    }
}