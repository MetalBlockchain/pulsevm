use std::fmt;

use pulsevm_serialization::{NumBytes, Read, Write};
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

impl NumBytes for Signature {
    fn num_bytes(&self) -> usize {
        65 // 64 bytes for the signature + 1 byte for the recovery id
    }
}

impl Read for Signature {
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        if *pos + 65 > data.len() {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes);
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

impl Write for Signature {
    fn write(
        &self,
        bytes: &mut [u8],
        pos: &mut usize,
    ) -> Result<(), pulsevm_serialization::WriteError> {
        if *pos + 65 > bytes.len() {
            return Err(pulsevm_serialization::WriteError::NotEnoughSpace);
        }
        let (recovery_id, serialized) = self.0.serialize_compact();
        bytes[*pos..*pos + 64].copy_from_slice(&serialized);
        *pos += 64;
        bytes[*pos] = recovery_id as u8;
        *pos += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use pulsevm_serialization::{Read, Write};
    use secp256k1::hashes::{Hash, sha256};

    use crate::chain::{PrivateKey, Signature};

    #[test]
    fn test_signature_recovery() {
        let private_key = PrivateKey::random();
        let digest = sha256::Hash::hash(b"test");
        let signature = private_key.sign(&digest);
        let digest = sha256::Hash::hash(b"test");
        let public_key = signature
            .recover_public_key(&digest)
            .expect("Failed to recover public key");
        assert_eq!(public_key, private_key.public_key());
        let serialized = signature.pack().expect("Failed to serialize signature");
        let deserialized =
            Signature::read(&serialized, &mut 0).expect("Failed to deserialize signature");
        assert_eq!(signature, deserialized);
    }
}
