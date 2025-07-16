use std::str::FromStr;

use secp256k1::hashes::{Hash, sha256};
use secp256k1::{Message, Secp256k1, rand};

use crate::chain::Signature;

use super::public_key::PublicKey;

pub struct PrivateKey(pub secp256k1::SecretKey);

#[derive(Debug, Clone)]
pub enum PrivateKeyError {
    InvalidLength,
    InvalidFormat,
}

impl std::fmt::Display for PrivateKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivateKeyError::InvalidLength => write!(f, "Invalid length"),
            PrivateKeyError::InvalidFormat => write!(f, "Invalid format"),
        }
    }
}

impl PrivateKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, secp256k1::Error> {
        let secret_key = secp256k1::SecretKey::from_slice(bytes)?;
        Ok(PrivateKey(secret_key))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0[..].to_vec()
    }

    pub fn public_key(&self) -> PublicKey {
        let secp = secp256k1::Secp256k1::new();
        PublicKey(secp256k1::PublicKey::from_secret_key(&secp, &self.0))
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        let secp = Secp256k1::new();
        let digest = sha256::Hash::hash(msg);
        let message = Message::from_digest(digest.to_byte_array());
        let sig = secp.sign_ecdsa_recoverable(&message, &self.0);

        sig.into()
    }

    pub fn random() -> Self {
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
        PrivateKey(secret_key)
    }
}

impl FromStr for PrivateKey {
    type Err = PrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = bs58::decode(s)
            .as_cb58(None)
            .into_vec()
            .map_err(|_| PrivateKeyError::InvalidFormat)?;
        if value.len() != 32 {
            return Err(PrivateKeyError::InvalidLength);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&value);
        Self::from_bytes(&bytes).map_err(|_| PrivateKeyError::InvalidFormat)
    }
}
