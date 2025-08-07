use pulsevm_serialization::{NumBytes, Read, Write};
use secp256k1::hashes::{sha256, Hash};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn hash(data: impl AsRef<[u8]>) -> Self {
        let hash = sha256::Hash::hash(data.as_ref());
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_ref());
        Digest(out)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl NumBytes for Digest {
    fn num_bytes(&self) -> usize {
        32
    }
}

impl Write for Digest {
    fn write(
        &self,
        bytes: &mut [u8],
        pos: &mut usize,
    ) -> Result<(), pulsevm_serialization::WriteError> {
        if *pos + 32 > bytes.len() {
            return Err(pulsevm_serialization::WriteError::NotEnoughSpace);
        }
        bytes[*pos..*pos + 32].copy_from_slice(&self.0);
        *pos += 32;
        Ok(())
    }
}

impl Read for Digest {
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        if *pos + 32 > data.len() {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&data[*pos..*pos + 32]);
        *pos += 32;
        Ok(Digest(digest))
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let hex_string = hex::encode(self.0);
        serializer.serialize_str(&hex_string)
    }
}