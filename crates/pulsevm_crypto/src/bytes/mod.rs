use core::fmt;

use pulsevm_serialization::{
    NumBytes,
    Read,
    ReadError,
    Write,
};
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    #[inline]
    pub fn new(data: Vec<u8>) -> Self {
        Bytes(data)
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Bytes {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::encode(self.0.as_slice()).fmt(f)
    }
}

impl Serialize for Bytes {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let hex_string = hex::encode(&self.0);
        serializer.serialize_str(&hex_string)
    }
}

impl<'de> Deserialize<'de> for Bytes {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_string = String::deserialize(deserializer)?;
        let bytes = hex::decode(hex_string).map_err(serde::de::Error::custom)?;
        Ok(Bytes(bytes))
    }
}

impl From<Vec<u8>> for Bytes {
    #[inline]
    fn from(data: Vec<u8>) -> Self {
        Bytes(data)
    }
}

impl From<&[u8]> for Bytes {
    #[inline]
    fn from(data: &[u8]) -> Self {
        Bytes(data.to_vec())
    }
}

impl NumBytes for Bytes {
    #[inline]
    fn num_bytes(&self) -> usize {
        // The length prefix is a `VarUint32` (1-5 bytes), not a fixed 4: `write`
        // below emits it through `usize::write`, and `read` consumes it through
        // `usize::read`. Hardcoding 4 made this the only length-prefixed type in
        // the workspace that disagreed with its own writer -- `[T]` and `Vec<T>`
        // both use `self.len().num_bytes()`.
        //
        // The disagreement was not inert. `Write::pack` allocates `num_bytes()`
        // zeroed bytes, writes into them, and returns the whole buffer however
        // far the writer actually got, so every `Bytes` under 128 bytes packed
        // with three trailing zeros. Above 2^28 the estimate flipped to an
        // *under*estimate and `pack()` began failing with `NotEnoughSpace`.
        self.0.len().num_bytes() + self.0.len()
    }
}

impl Read for Bytes {
    #[inline]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let len = usize::read(bytes, pos)?;

        // bounds check
        if bytes.len() < *pos + len {
            return Err(ReadError::NotEnoughBytes);
        }

        let start = *pos;
        let end = start + len;
        *pos = end;

        Ok(Bytes(bytes[start..end].to_vec()))
    }
}

impl Write for Bytes {
    #[inline]
    fn write(
        &self,
        bytes: &mut [u8],
        pos: &mut usize,
    ) -> Result<(), pulsevm_serialization::WriteError> {
        let len = self.0.len();
        usize::write(&len, bytes, pos)?;
        if bytes.len() < *pos + len {
            return Err(pulsevm_serialization::WriteError::NotEnoughSpace);
        }
        bytes[*pos..*pos + len].copy_from_slice(&self.0);
        *pos += len;
        Ok(())
    }
}

impl AsRef<[u8]> for Bytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_display() {
        let bytes = Bytes::new(vec![0x12, 0x34, 0x56, 0x78]);
        assert_eq!(bytes.to_string(), "12345678");
    }

    /// The encoding, pinned against Antelope: an `unsigned_int` (varint) length
    /// followed by the payload. Three bytes of data must pack to exactly four.
    #[test]
    fn packs_with_a_varint_length_prefix_and_no_padding() {
        let packed = Bytes::new(vec![0xAA, 0xBB, 0xCC]).pack().unwrap();
        assert_eq!(
            packed,
            vec![0x03, 0xAA, 0xBB, 0xCC],
            "expected a 1-byte varint length, not a fixed 4-byte one"
        );
    }

    /// `Write::pack` allocates `num_bytes()` and returns the whole buffer
    /// regardless of how far `write` got, so any disagreement between the two
    /// shows up directly as trailing zeros in the packed output.
    ///
    /// The lengths straddle every `VarUint32` width boundary: 1 byte below 128,
    /// 2 below 16384, 3 below 2^21.
    #[test]
    fn num_bytes_matches_what_write_actually_emits() {
        for len in [0usize, 1, 3, 127, 128, 129, 16_383, 16_384, 16_385, 100_000] {
            let bytes = Bytes::new(vec![0xAA; len]);
            let packed = bytes.pack().unwrap();

            assert_eq!(
                packed.len(),
                bytes.num_bytes(),
                "len {len}: pack() returned {} bytes but num_bytes() promised {}",
                packed.len(),
                bytes.num_bytes()
            );

            // And the writer must consume the whole buffer: a shortfall here is
            // exactly the trailing padding.
            let mut pos = 0usize;
            let mut scratch = vec![0u8; bytes.num_bytes()];
            bytes.write(&mut scratch, &mut pos).unwrap();
            assert_eq!(
                pos,
                packed.len(),
                "len {len}: write advanced {pos} of {} bytes, leaving padding",
                packed.len()
            );
        }
    }

    /// Round-tripping must consume the packed bytes exactly. Trailing padding
    /// left `pos` short of the end, which is what leaked into every digest
    /// computed over a packed `Bytes`.
    #[test]
    fn round_trip_consumes_the_entire_encoding() {
        for len in [0usize, 3, 127, 128, 16_384] {
            let original = Bytes::new((0..len).map(|i| i as u8).collect());
            let packed = original.pack().unwrap();

            let mut pos = 0usize;
            let decoded = Bytes::read(&packed, &mut pos).unwrap();

            assert_eq!(decoded, original, "len {len}: round trip changed the data");
            assert_eq!(
                pos,
                packed.len(),
                "len {len}: {} bytes left unread after decoding",
                packed.len() - pos
            );
        }
    }

    /// `Bytes` must agree with the other length-prefixed types. `Vec<u8>` and
    /// `[u8]` both size their prefix with `self.len().num_bytes()`; `Bytes` was
    /// the only one that did not.
    #[test]
    fn agrees_with_the_equivalent_vec_encoding() {
        for len in [0usize, 3, 127, 128, 16_384] {
            let raw: Vec<u8> = (0..len).map(|i| i as u8).collect();
            assert_eq!(
                Bytes::new(raw.clone()).num_bytes(),
                raw.num_bytes(),
                "len {len}: Bytes and Vec<u8> must size identically"
            );
            assert_eq!(
                Bytes::new(raw.clone()).pack().unwrap(),
                raw.pack().unwrap(),
                "len {len}: Bytes and Vec<u8> must pack identically"
            );
        }
    }
}
