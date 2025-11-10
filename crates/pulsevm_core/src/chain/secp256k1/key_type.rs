use pulsevm_serialization::{NumBytes, Read, ReadError, Write};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    K1 = 0,
}

impl KeyType {
    #[inline]
    fn from_u64(n: u64) -> Result<Self, &'static str> {
        match n {
            0 => Ok(KeyType::K1),
            _ => Err("unknown key type enum value"),
        }
    }
}

impl NumBytes for KeyType {
    fn num_bytes(&self) -> usize {
        1
    }
}

impl Write for KeyType {
    fn write(
        &self,
        bytes: &mut [u8],
        pos: &mut usize,
    ) -> Result<(), pulsevm_serialization::WriteError> {
        match self {
            KeyType::K1 => u8::write(&0, bytes, pos),
        }
    }
}

impl Read for KeyType {
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let value = u8::read(data, pos)?;
        match value {
            0 => Ok(KeyType::K1),
            _ => Err(ReadError::ParseError),
        }
    }
}
