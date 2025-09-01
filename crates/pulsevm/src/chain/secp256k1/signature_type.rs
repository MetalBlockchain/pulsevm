use pulsevm_serialization::{NumBytes, Read, ReadError, Write};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureType {
    K1 = 0,
}

impl SignatureType {
    #[inline]
    fn from_u64(n: u64) -> Result<Self, &'static str> {
        match n {
            0 => Ok(SignatureType::K1),
            _ => Err("unknown signature type enum value"),
        }
    }
}

impl NumBytes for SignatureType {
    fn num_bytes(&self) -> usize {
        1
    }
}

impl Write for SignatureType {
    fn write(
        &self,
        bytes: &mut [u8],
        pos: &mut usize,
    ) -> Result<(), pulsevm_serialization::WriteError> {
        match self {
            SignatureType::K1 => u8::write(&0, bytes, pos),
        }
    }
}

impl Read for SignatureType {
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let value = u8::read(data, pos)?;
        match value {
            0 => Ok(SignatureType::K1),
            _ => Err(ReadError::ParseError),
        }
    }
}
