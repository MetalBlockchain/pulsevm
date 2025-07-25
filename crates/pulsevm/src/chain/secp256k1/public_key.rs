use std::str::FromStr;

use pulsevm_serialization::{NumBytes, Read, Write};
use secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey};

use crate::chain::error::ChainError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(pub secp256k1::PublicKey);

impl ToString for PublicKey {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl FromStr for PublicKey {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(PublicKey(Secp256k1PublicKey::from_str(s).map_err(|e| {
            ChainError::AuthorizationError(format!("invalid public key format: {}", e))
        })?))
    }
}

impl Read for PublicKey {
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        if *pos + 33 > data.len() {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes);
        }
        let mut id = [0u8; 33];
        id.copy_from_slice(&data[*pos..*pos + 33]);
        *pos += 33;
        let key = secp256k1::PublicKey::from_byte_array_compressed(&id)
            .map_err(|_| pulsevm_serialization::ReadError::ParseError)?;
        Ok(PublicKey(key))
    }
}

impl NumBytes for PublicKey {
    fn num_bytes(&self) -> usize {
        33 // Compressed public key size
    }
}

impl Write for PublicKey {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), pulsevm_serialization::WriteError> {
        if *pos + 33 > bytes.len() {
            return Err(pulsevm_serialization::WriteError::NotEnoughSpace);
        }
        let compressed = self.0.serialize();
        bytes[*pos..*pos + 33].copy_from_slice(&compressed);
        *pos += 33;
        Ok(())
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_byte_array(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = Secp256k1PublicKey::from_secret_key(&secp, &secret_key);
        PublicKey(public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_from_hex() {
        let hex = "030cd6c38a327849690b655003c50ca781d0f7020cc17e29428def19a342458961";
        let public_key = PublicKey::from_str(hex).unwrap();
        assert_eq!(
            public_key.to_string(),
            "030cd6c38a327849690b655003c50ca781d0f7020cc17e29428def19a342458961"
        );
    }

    #[test]
    fn test_public_key_serialize_deserialize() {
        let hex = "030cd6c38a327849690b655003c50ca781d0f7020cc17e29428def19a342458961";
        let public_key = PublicKey::from_str(hex).unwrap();

        let serialized: Vec<u8> = public_key.pack().unwrap();
        let mut pos = 0;
        let deserialized = PublicKey::read(&serialized, &mut pos).unwrap();

        assert_eq!(public_key, deserialized);
    }
}
