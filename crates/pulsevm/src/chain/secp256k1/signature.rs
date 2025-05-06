use std::fmt;

use pulsevm_serialization::{Deserialize, Serialize};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use sha2::Digest;

use super::public_key::PublicKey;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SignatureError {
    InvalidSignature,
    InternalError(String),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::InvalidSignature => write!(f, "Invalid signature"),
            SignatureError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signature([u8; 65]);

impl Signature {
    pub fn new(value: [u8; 65]) -> Self {
        Self(value)
    }

    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }

    pub fn recover_public_key(&self, msg: &[u8]) -> Result<PublicKey, SignatureError> {
        let rec_id = RecoveryId::try_from(self.0[64] as i32)
            .map_err(|_| SignatureError::InternalError("invalid recovery id".to_owned()))?;
        let mut digest_data = [0u8; 32];
        let digest = sha2::Sha256::digest(msg);
        let digest = digest.as_slice();
        digest_data.copy_from_slice(digest);
        let rec_sig = RecoverableSignature::from_compact(&self.0[0..64], rec_id)
            .map_err(|e| SignatureError::InternalError(format!("{}", e)))?;
        let msg = secp256k1::Message::from_digest(digest_data);
        let pub_key = rec_sig.recover(&msg)
            .map_err(|_| SignatureError::InvalidSignature)?;
        println!("Recovered public key: {:?}", pub_key);
        Ok(PublicKey(pub_key))
    }
}

impl Serialize for Signature {
    fn serialize(
        &self,
        bytes: &mut Vec<u8>,
    ) {
        bytes.extend_from_slice(&self.0);
    }
}

impl Deserialize for Signature {
    fn deserialize(
        data: &[u8],
        pos: &mut usize
    ) -> Result<Self, pulsevm_serialization::ReadError> {
        if *pos + 65 > data.len() {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes(*pos, 65));
        }
        let mut id = [0u8; 65];
        id.copy_from_slice(&data[*pos..*pos + 65]);
        *pos += 65;
        Ok(Signature(id))
    }
}