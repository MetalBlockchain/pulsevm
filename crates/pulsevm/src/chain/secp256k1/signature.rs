use pulsevm_serialization::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signature([u8; 65]);

impl Signature {
    pub fn new(value: [u8; 65]) -> Self {
        Self(value)
    }

    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.0
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