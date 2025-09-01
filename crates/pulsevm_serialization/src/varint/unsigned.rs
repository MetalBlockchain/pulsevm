use serde::{Deserialize, Serialize};

use crate::{NumBytes, Read, ReadError, Write, WriteError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VarUint32(pub u32);

impl NumBytes for VarUint32 {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        let v = self.0;
        if v == 0 {
            return 1;
        }
        let bits = 32 - v.leading_zeros(); // number of significant bits
        core::cmp::min((bits as usize + 6) / 7, 5)
    }
}

impl Read for VarUint32 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let mut result: u32 = 0;
        let mut shift = 0u32;

        // u32 needs at most 5 groups of 7 bits (5 * 7 = 35; last group limited to 4 bits)
        for i in 0..5 {
            if *pos >= bytes.len() {
                return Err(ReadError::NotEnoughBytes);
            }
            let byte = bytes[*pos];
            *pos += 1;

            let low7 = (byte & 0x7F) as u32;

            // prevent shifting beyond 31 bits
            if shift >= 32 {
                return Err(ReadError::Overflow);
            }

            // for the 5th byte, only the lower 4 bits are allowed for u32 (bits 28..31)
            if i == 4 && (low7 & 0xF0) != 0 {
                return Err(ReadError::Overflow);
            }

            result |= low7 << shift;

            if (byte & 0x80) == 0 {
                // this was the last byte
                return Ok(VarUint32(result));
            }

            shift += 7;
        }

        // if we fell out of the loop, we saw 5 continuation bits -> too long for u32
        Err(ReadError::ParseError)
    }
}

impl Write for VarUint32 {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        // Preflight so we either write everything or nothing.
        let need = self.num_bytes();
        if bytes.len() < *pos + need {
            return Err(WriteError::NotEnoughSpace);
        }

        let mut v = self.0;
        loop {
            let mut b = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            } // continuation bit
            bytes[*pos] = b;
            *pos += 1;
            if v == 0 {
                break;
            }
        }
        Ok(())
    }
}

impl From<usize> for VarUint32 {
    #[allow(clippy::cast_possible_truncation)]
    fn from(v: usize) -> Self {
        Self(v as u32)
    }
}

impl From<u32> for VarUint32 {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<u16> for VarUint32 {
    fn from(v: u16) -> Self {
        Self(v.into())
    }
}

impl From<u8> for VarUint32 {
    fn from(v: u8) -> Self {
        Self(v.into())
    }
}

impl Serialize for VarUint32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for VarUint32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Ok(VarUint32(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varuint_num_bytes() {
        use core::u32;

        assert_eq!(VarUint32(0).num_bytes(), 1);
        assert_eq!(VarUint32(127).num_bytes(), 1);
        assert_eq!(VarUint32(128).num_bytes(), 2);
        assert_eq!(VarUint32(0x3FFF).num_bytes(), 2);
        assert_eq!(VarUint32(0x4000).num_bytes(), 3);
        assert_eq!(VarUint32(0x1F_FFFF).num_bytes(), 3);
        assert_eq!(VarUint32(0x20_0000).num_bytes(), 4);
        assert_eq!(VarUint32(0x0FFF_FFFF).num_bytes(), 4);
        assert_eq!(VarUint32(0x1000_0000).num_bytes(), 5);
        assert_eq!(VarUint32(u32::MAX).num_bytes(), 5);
    }

    #[test]
    fn varuint_read() {
        let mut p = 0;
        assert_eq!(VarUint32::read(&[0x00], &mut p).unwrap(), VarUint32(0));
        p = 0;
        assert_eq!(VarUint32::read(&[0x01], &mut p).unwrap(), VarUint32(1));
        p = 0;
        assert_eq!(VarUint32::read(&[0x7F], &mut p).unwrap(), VarUint32(127));
        p = 0;
        assert_eq!(
            VarUint32::read(&[0x80, 0x01], &mut p).unwrap(),
            VarUint32(128)
        );
        p = 0;
        assert_eq!(
            VarUint32::read(&[0xFF, 0x01], &mut p).unwrap(),
            VarUint32(255)
        );
        p = 0;
        assert_eq!(
            VarUint32::read(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F], &mut p).unwrap(),
            VarUint32(u32::MAX)
        );
    }

    #[test]
    fn varuint_write() {
        let mut buf = [0u8; 16];
        let mut p = 0;

        VarUint32(0).write(&mut buf, &mut p).unwrap(); // [00]
        VarUint32(1).write(&mut buf, &mut p).unwrap(); // [01]
        VarUint32(127).write(&mut buf, &mut p).unwrap(); // [7F]
        VarUint32(128).write(&mut buf, &mut p).unwrap(); // [80 01]
        VarUint32(255).write(&mut buf, &mut p).unwrap(); // [FF 01]
        assert_eq!(&buf[..p], &[0x00, 0x01, 0x7F, 0x80, 0x01, 0xFF, 0x01]);

        // u64 little-endian example
        let mut buf2 = [0u8; 8];
        let mut p2 = 0;
        (0x1122334455667788u64).write(&mut buf2, &mut p2).unwrap();
        assert_eq!(&buf2, &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]); // LE
    }
}
