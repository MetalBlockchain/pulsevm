use std::str::FromStr;

use pulsevm_serialization::{Deserialize, Serialize};
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

impl Serialize for PublicKey {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.0.serialize().as_ref());
    }
}

impl Deserialize for PublicKey {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        if *pos + 33 > data.len() {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes(*pos, 33));
        }
        let mut id = [0u8; 33];
        id.copy_from_slice(&data[*pos..*pos + 33]);
        *pos += 33;
        let key = secp256k1::PublicKey::from_byte_array_compressed(&id)
            .map_err(|_| pulsevm_serialization::ReadError::ParseError)?;
        Ok(PublicKey(key))
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
    use pulsevm_serialization::Deserialize;

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

        let mut serialized: Vec<u8> = Vec::new();
        public_key.serialize(&mut serialized);

        let mut pos = 0;
        let deserialized = PublicKey::deserialize(&serialized, &mut pos).unwrap();

        assert_eq!(public_key, deserialized);
    }
}
