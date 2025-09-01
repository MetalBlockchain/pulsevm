use pulsevm_serialization::{NumBytes, Read, ReadError};

pub enum RequestType {
    GetStatusRequestV0,
    GetBlocksRequestV0,
    GetBlocksAckRequestV0,
}

impl NumBytes for RequestType {
    fn num_bytes(&self) -> usize {
        1 // 1 byte for the request type
    }
}

impl Read for RequestType {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let id = u8::read(bytes, pos)?;
        Ok(match id {
            0 => RequestType::GetStatusRequestV0,
            1 => RequestType::GetBlocksRequestV0,
            2 => RequestType::GetBlocksAckRequestV0,
            _ => return Err(ReadError::ParseError),
        })
    }
}
