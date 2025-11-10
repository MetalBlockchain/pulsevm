use std::str::FromStr;

use secp256k1::hashes::{Hash, sha256};
use secp256k1::{Message, Secp256k1, rand};

use crate::chain::secp256k1::Signature;

use super::public_key::PublicKey;

pub struct PrivateKey(secp256k1::SecretKey);

#[derive(Debug, Clone)]
pub enum PrivateKeyError {
    InvalidFormat,
}

impl std::fmt::Display for PrivateKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivateKeyError::InvalidFormat => write!(f, "invalid format"),
        }
    }
}

impl PrivateKey {
    #[allow(dead_code)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, secp256k1::Error> {
        let secret_key = secp256k1::SecretKey::from_slice(bytes)?;
        Ok(PrivateKey(secret_key))
    }

    #[allow(dead_code)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0[..].to_vec()
    }

    #[allow(dead_code)]
    pub fn public_key(&self) -> PublicKey {
        let secp = secp256k1::Secp256k1::new();
        PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, &self.0))
    }

    #[allow(dead_code)]
    pub fn sign(&self, digest: &sha256::Hash) -> Signature {
        let secp = Secp256k1::signing_only();
        let message = Message::from_digest(digest.to_byte_array());
        let sig = secp.sign_ecdsa_recoverable(&message, &self.0);

        sig.into()
    }

    #[allow(dead_code)]
    pub fn random() -> Self {
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
        PrivateKey(secret_key)
    }
}

impl FromStr for PrivateKey {
    type Err = PrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        secp256k1::SecretKey::from_str(s)
            .map(PrivateKey)
            .map_err(|_| PrivateKeyError::InvalidFormat)
    }
}
