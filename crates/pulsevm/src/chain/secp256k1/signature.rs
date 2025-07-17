use std::fmt;

use pulsevm_serialization::{Deserialize, Serialize};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::hashes::{Hash, sha256};

use super::public_key::PublicKey;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SignatureError {
    InvalidSignature,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::InvalidSignature => write!(f, "Invalid signature"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signature(RecoverableSignature);

impl Signature {
    pub fn recover_public_key(&self, digest: &sha256::Hash) -> Result<PublicKey, SignatureError> {
        let msg = secp256k1::Message::from_digest(digest.to_byte_array());
        let pub_key = self
            .0
            .recover(&msg)
            .map_err(|_| SignatureError::InvalidSignature)?;
        Ok(PublicKey(pub_key))
    }
}

impl From<RecoverableSignature> for Signature {
    fn from(sig: RecoverableSignature) -> Self {
        Signature(sig)
    }
}

impl Serialize for Signature {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        let (recovery_id, serialized) = self.0.serialize_compact();
        bytes.extend_from_slice(&serialized);
        bytes.push(recovery_id as u8);
    }
}

impl Deserialize for Signature {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        if *pos + 65 > data.len() {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes(*pos, 65));
        }
        let mut serialized = [0u8; 64];
        serialized.copy_from_slice(&data[*pos..*pos + 64]);
        *pos += 64;
        let recovery_id = data[*pos];
        *pos += 1;
        let recovery_id = RecoveryId::try_from(recovery_id as i32)
            .map_err(|_| pulsevm_serialization::ReadError::ParseError)?;
        let recoverable_signature = RecoverableSignature::from_compact(&serialized, recovery_id)
            .map_err(|_| pulsevm_serialization::ReadError::ParseError)?;
        Ok(Signature(recoverable_signature))
    }
}

#[cfg(test)]
mod tests {
    use pulsevm_serialization::{serialize, Deserialize};
    use secp256k1::hashes::{Hash, sha256};

    use crate::chain::{PrivateKey, Signature};

    #[test]
    fn test_signature_recovery() {
        let private_key = PrivateKey::random();
        let signature = private_key.sign(b"test");
        let digest = sha256::Hash::hash(b"test");
        let public_key = signature
            .recover_public_key(&digest)
            .expect("Failed to recover public key");
        assert_eq!(public_key, private_key.public_key());
        let serialized = serialize(&signature);
        let deserialized = Signature::deserialize(&serialized, &mut 0).expect("Failed to deserialize signature");
        assert_eq!(signature, deserialized);
    }
}
