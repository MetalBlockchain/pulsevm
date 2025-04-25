use std::str::FromStr;

use super::PublicKey;

pub struct PrivateKey(secp256k1::SecretKey);

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
}

impl FromStr for PrivateKey {
    type Err = PrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = bs58::decode(s).as_cb58(None).into_vec().map_err(|_| PrivateKeyError::InvalidFormat)?;
        if value.len() != 32 {
            return Err(PrivateKeyError::InvalidLength);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&value);
        Self::from_bytes(&bytes).map_err(|_| PrivateKeyError::InvalidFormat)
    }
}