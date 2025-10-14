use crate::{NumBytes, Read, ReadError, Write, WriteError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct VarInt32(pub i32);

impl NumBytes for VarInt32 {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        // simulate encoding (≤5 iterations for i32)
        let mut v = self.0 as i64;
        let mut count = 0usize;
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            let sign_bit = (byte & 0x40) != 0;
            count += 1;
            // termination rule for SLEB128
            let done = (v == 0 && !sign_bit) || (v == -1 && sign_bit);
            if done || count == 5 {
                break;
            }
        }
        count
    }
}

impl Read for VarInt32 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let mut result: i64 = 0;
        let mut shift = 0u32;

        for _ in 0..5 {
            if *pos >= bytes.len() {
                return Err(ReadError::NotEnoughBytes);
            }
            let b = bytes[*pos];
            *pos += 1;

            result |= ((b & 0x7F) as i64) << shift;

            let cont = (b & 0x80) != 0;
            let sign = (b & 0x40) != 0;

            if !cont {
                // sign-extend from the next bit if needed
                if shift < 32 && sign {
                    result |= (!0_i64) << (shift + 7);
                }
                // range check for i32
                if result < i32::MIN as i64 || result > i32::MAX as i64 {
                    return Err(ReadError::Overflow);
                }
                return Ok(VarInt32(result as i32));
            }

            shift += 7;
        }
        Err(ReadError::ParseError)
    }
}

impl Write for VarInt32 {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let need = self.num_bytes();
        if bytes.len() < *pos + need {
            return Err(WriteError::NotEnoughSpace);
        }

        let mut v = self.0 as i64;
        loop {
            let mut byte = (v & 0x7F) as u8;
            v >>= 7;
            let sign_bit = (byte & 0x40) != 0;

            // Are we done after this byte?
            let done = (v == 0 && !sign_bit) || (v == -1 && sign_bit);
            if !done {
                byte |= 0x80;
            } // continuation

            bytes[*pos] = byte;
            *pos += 1;

            if done {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_num_bytes() {
        use core::i32;

        // 1-byte window: [-64, 63]
        assert_eq!(VarInt32(0).num_bytes(), 1);
        assert_eq!(VarInt32(1).num_bytes(), 1);
        assert_eq!(VarInt32(-1).num_bytes(), 1);
        assert_eq!(VarInt32(63).num_bytes(), 1);
        assert_eq!(VarInt32(-64).num_bytes(), 1);

        // 2 bytes: just outside the 1-byte window, up to ±2^13
        assert_eq!(VarInt32(64).num_bytes(), 2);
        assert_eq!(VarInt32(-65).num_bytes(), 2);
        assert_eq!(VarInt32(8191).num_bytes(), 2);
        assert_eq!(VarInt32(-8192).num_bytes(), 2);

        // 3 bytes: up to ±2^20
        assert_eq!(VarInt32(8192).num_bytes(), 3);
        assert_eq!(VarInt32(-8193).num_bytes(), 3);
        assert_eq!(VarInt32(1_048_575).num_bytes(), 3);
        assert_eq!(VarInt32(-1_048_576).num_bytes(), 3);

        // 4 bytes: up to ±2^27
        assert_eq!(VarInt32(1_048_576).num_bytes(), 4);
        assert_eq!(VarInt32(-1_048_577).num_bytes(), 4);
        assert_eq!(VarInt32(134_217_727).num_bytes(), 4);
        assert_eq!(VarInt32(-134_217_728).num_bytes(), 4);

        // 5 bytes: full i32 range
        assert_eq!(VarInt32(i32::MAX).num_bytes(), 5);
        assert_eq!(VarInt32(i32::MIN).num_bytes(), 5);
    }

    #[test]
    fn varint_read() {
        let mut p = 0;
        assert_eq!(VarInt32::read(&[0x00], &mut p).unwrap(), VarInt32(0));
        p = 0;
        assert_eq!(VarInt32::read(&[0x01], &mut p).unwrap(), VarInt32(1));
        p = 0;
        assert_eq!(VarInt32::read(&[0x7F], &mut p).unwrap(), VarInt32(-1));
        p = 0;
        assert_eq!(VarInt32::read(&[0xC0, 0x00], &mut p).unwrap(), VarInt32(64));
        p = 0;
        assert_eq!(VarInt32::read(&[0x40], &mut p).unwrap(), VarInt32(-64));
        p = 0;
        assert_eq!(
            VarInt32::read(&[0xFF, 0x00], &mut p).unwrap(),
            VarInt32(127)
        );
        p = 0;
        assert_eq!(
            VarInt32::read(&[0x80, 0x7F], &mut p).unwrap(),
            VarInt32(-128)
        );
        p = 0;
        assert_eq!(
            VarInt32::read(&[0xFF, 0x3F], &mut p).unwrap(),
            VarInt32(8191)
        );
        p = 0;
        assert_eq!(
            VarInt32::read(&[0x80, 0x40], &mut p).unwrap(),
            VarInt32(-8192)
        );
        p = 0;
        assert_eq!(
            VarInt32::read(&[0xFF, 0xFF, 0x3F], &mut p).unwrap(),
            VarInt32(1_048_575)
        );
        p = 0;
        assert_eq!(
            VarInt32::read(&[0x80, 0x80, 0x40], &mut p).unwrap(),
            VarInt32(-1_048_576)
        );
        p = 0;
        assert_eq!(
            VarInt32::read(&[0xFF, 0xFF, 0xFF, 0x3F], &mut p).unwrap(),
            VarInt32(134_217_727)
        );
        p = 0;
        assert_eq!(
            VarInt32::read(&[0x80, 0x80, 0x80, 0x40], &mut p).unwrap(),
            VarInt32(-134_217_728)
        );
        p = 0;
        assert_eq!(
            VarInt32::read(&[0xFF, 0xFF, 0xFF, 0xFF, 0x07], &mut p).unwrap(),
            VarInt32(core::i32::MAX)
        );
        p = 0;
        assert_eq!(
            VarInt32::read(&[0x80, 0x80, 0x80, 0x80, 0x78], &mut p).unwrap(),
            VarInt32(core::i32::MIN)
        );
    }

    #[test]
    fn varint_write() {
        let mut buf = [0u8; 32];
        let mut p = 0;

        VarInt32(0).write(&mut buf, &mut p).unwrap(); // [00]
        VarInt32(1).write(&mut buf, &mut p).unwrap(); // [01]
        VarInt32(-1).write(&mut buf, &mut p).unwrap(); // [7F]
        VarInt32(64).write(&mut buf, &mut p).unwrap(); // [C0 00]
        VarInt32(-64).write(&mut buf, &mut p).unwrap(); // [40]
        VarInt32(127).write(&mut buf, &mut p).unwrap(); // [FF 00]
        VarInt32(-128).write(&mut buf, &mut p).unwrap(); // [80 7F]
        VarInt32(8191).write(&mut buf, &mut p).unwrap(); // [FF 3F]
        VarInt32(-8192).write(&mut buf, &mut p).unwrap(); // [80 40]

        assert_eq!(
            &buf[..p],
            &[
                0x00, // 0
                0x01, // 1
                0x7F, // -1
                0xC0, 0x00, // 64
                0x40, // -64
                0xFF, 0x00, // 127
                0x80, 0x7F, // -128
                0xFF, 0x3F, // 8191
                0x80, 0x40, // -8192
            ]
        );
    }
}
