//! Minimal reader/writer for the AvalancheGo wire codec.
//!
//! ICM / warp messages are *not* serialized with PulseVM's little-endian EOS
//! codec — they use AvalancheGo's `codec` (via `linearcodec`), which is
//! big-endian with a leading `uint16` version prefix and length-prefixed
//! variable fields. Getting these primitives exactly right is what lets a
//! PulseVM node verify a message a MetalGo validator signed, and vice versa.
//!
//! Layout rules we depend on (see AvalancheGo `codec/reflectcodec`):
//! * integers: big-endian, fixed width;
//! * fixed-size byte arrays (`[N]byte`): `N` raw bytes, no prefix;
//! * variable slices (`[]byte`): `uint32` big-endian length, then the bytes;
//! * interface values: a `uint32` big-endian type id, then the concrete value.

/// The codec version every warp/ICM structure is prefixed with. AvalancheGo
/// registers its warp codecs at version 0.
pub const CODEC_VERSION: u16 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// Ran out of bytes while reading.
    UnexpectedEof,
    /// A length prefix exceeded the bytes actually available.
    LengthOverflow,
    /// The 2-byte codec version prefix was not the expected value.
    BadVersion(u16),
    /// An interface type id did not correspond to a known concrete type.
    UnknownTypeId(u32),
    /// Bytes remained after a top-level decode that should have consumed all.
    TrailingBytes,
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CodecError::UnexpectedEof => write!(f, "unexpected end of buffer"),
            CodecError::LengthOverflow => write!(f, "length prefix exceeds available bytes"),
            CodecError::BadVersion(v) => write!(f, "unsupported codec version {v}"),
            CodecError::UnknownTypeId(t) => write!(f, "unknown type id {t}"),
            CodecError::TrailingBytes => write!(f, "trailing bytes after decode"),
        }
    }
}

impl std::error::Error for CodecError {}

/// Cursor-based reader over a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(n).ok_or(CodecError::LengthOverflow)?;
        if end > self.buf.len() {
            return Err(CodecError::UnexpectedEof);
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub fn read_u16(&mut self) -> Result<u16, CodecError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32, CodecError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, CodecError> {
        let b = self.take(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(u64::from_be_bytes(arr))
    }

    /// Read the leading codec version and require it to equal [`CODEC_VERSION`].
    pub fn read_version(&mut self) -> Result<(), CodecError> {
        let v = self.read_u16()?;
        if v != CODEC_VERSION {
            return Err(CodecError::BadVersion(v));
        }
        Ok(())
    }

    /// Read a fixed-size `[N]byte` array (no length prefix).
    pub fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let b = self.take(N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(b);
        Ok(arr)
    }

    /// Read a `uint32`-length-prefixed byte slice.
    pub fn read_bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        let len = self.read_u32()? as usize;
        // Guard against a length prefix that claims more than the buffer holds
        // before we attempt the (bounded) allocation.
        if self.pos + len > self.buf.len() {
            return Err(CodecError::LengthOverflow);
        }
        Ok(self.take(len)?.to_vec())
    }

    /// Number of unconsumed bytes.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Error unless the whole buffer has been consumed.
    pub fn finish(&self) -> Result<(), CodecError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

/// Growable writer producing AvalancheGo-codec bytes.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Write the leading codec version prefix.
    pub fn write_version(&mut self) {
        self.write_u16(CODEC_VERSION);
    }

    /// Write raw bytes with no length prefix (fixed-size array fields).
    pub fn write_raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Write a `uint32`-length-prefixed byte slice.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_u32(bytes.len() as u32);
        self.buf.extend_from_slice(bytes);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_endianness_is_big_endian() {
        let mut w = Writer::new();
        w.write_u32(0x01020304);
        assert_eq!(w.into_bytes(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn bytes_roundtrip() {
        let mut w = Writer::new();
        w.write_version();
        w.write_bytes(b"hello");
        let encoded = w.into_bytes();
        // 2 (version) + 4 (len) + 5 (data)
        assert_eq!(encoded.len(), 11);

        let mut r = Reader::new(&encoded);
        r.read_version().unwrap();
        assert_eq!(r.read_bytes().unwrap(), b"hello");
        r.finish().unwrap();
    }

    #[test]
    fn overlong_length_is_rejected() {
        // version + length claiming 100 bytes but only 1 present
        let bytes = [0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0xAA];
        let mut r = Reader::new(&bytes);
        r.read_version().unwrap();
        assert_eq!(r.read_bytes(), Err(CodecError::LengthOverflow));
    }

    #[test]
    fn bad_version_is_rejected() {
        let bytes = [0x00, 0x01];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_version(), Err(CodecError::BadVersion(1)));
    }
}
