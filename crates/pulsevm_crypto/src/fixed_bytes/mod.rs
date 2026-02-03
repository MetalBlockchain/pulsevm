use core::fmt;

use pulsevm_serialization::{NumBytes, Read, Write};
use serde::Serialize;
use sha2::Digest;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

impl FixedBytes<32> {
    #[inline]
    pub fn hash(data: impl AsRef<[u8]>) -> Self {
        let hash = sha2::Sha256::digest(data.as_ref());
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_ref());
        FixedBytes(out)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<const N: usize> fmt::Display for FixedBytes<N> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl<const N: usize> NumBytes for FixedBytes<N> {
    #[inline]
    fn num_bytes(&self) -> usize {
        N
    }
}

impl<const N: usize> Default for FixedBytes<N> {
    #[inline]
    fn default() -> Self {
        FixedBytes([0u8; N])
    }
}

impl<const N: usize> Write for FixedBytes<N> {
    #[inline]
    fn write(
        &self,
        bytes: &mut [u8],
        pos: &mut usize,
    ) -> Result<(), pulsevm_serialization::WriteError> {
        if *pos + N > bytes.len() {
            return Err(pulsevm_serialization::WriteError::NotEnoughSpace);
        }
        bytes[*pos..*pos + N].copy_from_slice(&self.0);
        *pos += N;
        Ok(())
    }
}

impl<const N: usize> Read for FixedBytes<N> {
    #[inline]
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        if *pos + N > data.len() {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes);
        }
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(&data[*pos..*pos + N]);
        *pos += N;
        Ok(FixedBytes(bytes))
    }
}

impl<const N: usize> Serialize for FixedBytes<N> {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> TryFrom<Vec<u8>> for FixedBytes<N> {
    type Error = ();

    #[inline]
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != N {
            return Err(());
        }
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(&value);
        Ok(FixedBytes(bytes))
    }
}
