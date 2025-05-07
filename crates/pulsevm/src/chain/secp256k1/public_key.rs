use pulsevm_serialization::{Deserialize, Serialize};
use secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(pub secp256k1::PublicKey);

impl PublicKey {
    pub fn from_hex(hex: &str) -> Result<Self, pulsevm_serialization::ReadError> {
        let bytes = hex::decode(hex).map_err(|_| pulsevm_serialization::ReadError::ParseError)?;
        if bytes.len() != 33 {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes(0, 33));
        }
        let mut id = [0u8; 33];
        id.copy_from_slice(&bytes);
        let key = secp256k1::PublicKey::from_byte_array_compressed(&id)
            .map_err(|_| pulsevm_serialization::ReadError::ParseError)?;
        Ok(PublicKey(key))
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
