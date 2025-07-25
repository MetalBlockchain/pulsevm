#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct NodeId(pub [u8; 20]);

impl TryFrom<&[u8]> for NodeId {
    type Error = pulsevm_serialization::ReadError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 20 {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes);
        }
        let mut id = [0u8; 20];
        id.copy_from_slice(value);
        Ok(NodeId(id))
    }
}

impl TryFrom<Vec<u8>> for NodeId {
    type Error = pulsevm_serialization::ReadError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 20 {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes);
        }
        let mut id = [0u8; 20];
        id.copy_from_slice(&value);
        Ok(NodeId(id))
    }
}

impl Into<Vec<u8>> for NodeId {
    fn into(self) -> Vec<u8> {
        self.0.to_vec()
    }
}
