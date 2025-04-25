use pulsevm_serialization::{Deserialize, Serialize};

pub struct PublicKey(pub secp256k1::PublicKey);

impl Serialize for PublicKey {
    fn serialize(
        &self,
        bytes: &mut Vec<u8>,
    ) {
        bytes.extend_from_slice(self.0.serialize().as_ref());
    }
}

impl Deserialize for PublicKey {
    fn deserialize(
        data: &[u8],
        pos: &mut usize
    ) -> Result<Self, pulsevm_serialization::ReadError> {
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