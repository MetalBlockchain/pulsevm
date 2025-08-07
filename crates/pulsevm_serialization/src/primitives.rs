use std::{collections::{HashSet, VecDeque}, hash::Hash};

use crate::{NumBytes, Read, ReadError, Write, WriteError};

impl NumBytes for u8 {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        core::mem::size_of::<u8>()
    }
}

impl NumBytes for i8 {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        core::mem::size_of::<u8>()
    }
}

impl NumBytes for u16 {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        core::mem::size_of::<u16>()
    }
}

impl NumBytes for i16 {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        core::mem::size_of::<u16>()
    }
}

impl NumBytes for u32 {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        core::mem::size_of::<u32>()
    }
}

impl NumBytes for i32 {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        core::mem::size_of::<u32>()
    }
}

impl NumBytes for u64 {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        core::mem::size_of::<u64>()
    }
}

impl NumBytes for i64 {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        core::mem::size_of::<u64>()
    }
}

impl NumBytes for String {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        self.len() + 2 // 2 bytes for length prefix
    }
}

impl NumBytes for bool {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        core::mem::size_of::<u8>()
    }
}

impl<T: NumBytes> NumBytes for Vec<T> {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        let mut count = 4;
        for item in self {
            count += item.num_bytes();
        }
        count
    }
}

impl<T: NumBytes> NumBytes for VecDeque<T> {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        let mut count = 4;
        for item in self {
            count += item.num_bytes();
        }
        count
    }
}

impl<T: NumBytes> NumBytes for HashSet<T> {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        let mut count = 4;
        for item in self {
            count += item.num_bytes();
        }
        count
    }
}

impl<T1: NumBytes, T2: NumBytes> NumBytes for (T1, T2) {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        self.0.num_bytes() + self.1.num_bytes()
    }
}

impl<T1: NumBytes, T2: NumBytes, T3: NumBytes> NumBytes for (T1, T2, T3) {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        self.0.num_bytes() + self.1.num_bytes() + self.2.num_bytes()
    }
}

impl<T1: NumBytes, T2: NumBytes, T3: NumBytes, T4: NumBytes> NumBytes for (T1, T2, T3, T4) {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        self.0.num_bytes() + self.1.num_bytes() + self.2.num_bytes() + self.3.num_bytes()
    }
}

impl Read for u8 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        if bytes.len() < *pos + core::mem::size_of::<u8>() {
            return Err(ReadError::NotEnoughBytes);
        }
        let value = u8::from_be_bytes([bytes[*pos]]);
        *pos += core::mem::size_of::<u8>();
        Ok(value)
    }
}

impl Read for i8 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let result = u8::read(bytes, pos).expect("failed to read u8");
        Ok(result as i8)
    }
}

impl Read for u16 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        if bytes.len() < *pos + core::mem::size_of::<u16>() {
            return Err(ReadError::NotEnoughBytes);
        }
        let value = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]);
        *pos += core::mem::size_of::<u16>();
        Ok(value)
    }
}

impl Read for i16 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let result = u16::read(bytes, pos).expect("failed to read u16");
        Ok(result as i16)
    }
}

impl Read for u32 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        if bytes.len() < *pos + core::mem::size_of::<u32>() {
            return Err(ReadError::NotEnoughBytes);
        }
        let value = u32::from_be_bytes([
            bytes[*pos],
            bytes[*pos + 1],
            bytes[*pos + 2],
            bytes[*pos + 3],
        ]);
        *pos += core::mem::size_of::<u32>();
        Ok(value)
    }
}

impl Read for i32 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let result = u32::read(bytes, pos).expect("failed to read u32");
        Ok(result as i32)
    }
}

impl Read for u64 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        if bytes.len() < *pos + core::mem::size_of::<u64>() {
            return Err(ReadError::NotEnoughBytes);
        }
        let value = u64::from_be_bytes([
            bytes[*pos],
            bytes[*pos + 1],
            bytes[*pos + 2],
            bytes[*pos + 3],
            bytes[*pos + 4],
            bytes[*pos + 5],
            bytes[*pos + 6],
            bytes[*pos + 7],
        ]);
        *pos += core::mem::size_of::<u64>();
        Ok(value)
    }
}

impl Read for i64 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let result = u64::read(bytes, pos).expect("failed to read u64");
        Ok(result as i64)
    }
}

impl Read for String {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        // Read 2-byte length prefix (big endian)
        let len = u16::read(bytes, pos).expect("failed to read u16") as usize;

        if *pos + len > bytes.len() {
            return Err(ReadError::NotEnoughBytes);
        }

        let str_bytes = &bytes[*pos..*pos + len];
        *pos += len;

        match str::from_utf8(str_bytes) {
            Ok(s) => Ok(s.to_string()), // Into<String> in most contexts, still OK
            Err(_) => Err(ReadError::ParseError),
        }
    }
}

impl<T> Read for Vec<T>
where
    T: Read,
{
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let len = u32::read(bytes, pos)? as usize;

        if *pos + len > bytes.len() {
            return Err(ReadError::NotEnoughBytes);
        }

        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            let item = T::read(bytes, pos)?;
            vec.push(item);
        }
        Ok(vec)
    }
}

impl<T> Read for VecDeque<T>
where
    T: Read,
{
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let len = u32::read(bytes, pos)? as usize;

        if *pos + len > bytes.len() {
            return Err(ReadError::NotEnoughBytes);
        }

        let mut vec = VecDeque::with_capacity(len);
        for _ in 0..len {
            let item = T::read(bytes, pos)?;
            vec.push_back(item);
        }
        Ok(vec)
    }
}

impl<T> Read for HashSet<T>
where
    T: Read + Hash + Eq,
{
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let len = u32::read(bytes, pos)? as usize;

        if *pos + len > bytes.len() {
            return Err(ReadError::NotEnoughBytes);
        }

        let mut set = HashSet::with_capacity(len);
        for _ in 0..len {
            let item = T::read(bytes, pos)?;
            set.insert(item);
        }
        Ok(set)
    }
}

impl<T1, T2> Read for (T1, T2)
where
    T1: Read,
    T2: Read,
{
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let first = T1::read(bytes, pos)?;
        let second = T2::read(bytes, pos)?;
        Ok((first, second))
    }
}

impl<T1, T2, T3> Read for (T1, T2, T3)
where
    T1: Read,
    T2: Read,
    T3: Read,
{
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let first = T1::read(bytes, pos)?;
        let second = T2::read(bytes, pos)?;
        let third = T3::read(bytes, pos)?;
        Ok((first, second, third))
    }
}

impl<T1, T2, T3, T4> Read for (T1, T2, T3, T4)
where
    T1: Read,
    T2: Read,
    T3: Read,
    T4: Read,
{
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let first = T1::read(bytes, pos)?;
        let second = T2::read(bytes, pos)?;
        let third = T3::read(bytes, pos)?;
        let fourth = T4::read(bytes, pos)?;
        Ok((first, second, third, fourth))
    }
}

impl Read for bool {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let value = u8::read(bytes, pos).expect("failed to read u8");
        Ok(value != 0)
    }
}

impl Write for u8 {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let value = self.to_be_bytes();
        bytes[*pos] = value[0];
        *pos += value.len();
        Ok(())
    }
}

impl Write for i8 {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        (*self as u8).write(bytes, pos)
    }
}

impl Write for u16 {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let value = self.to_be_bytes();
        bytes[*pos] = value[0];
        bytes[*pos + 1] = value[1];
        *pos += value.len();
        Ok(())
    }
}

impl Write for i16 {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        (*self as u16).write(bytes, pos)
    }
}

impl Write for u32 {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let value = self.to_be_bytes();
        bytes[*pos] = value[0];
        bytes[*pos + 1] = value[1];
        bytes[*pos + 2] = value[2];
        bytes[*pos + 3] = value[3];
        *pos += core::mem::size_of::<u32>();
        Ok(())
    }
}

impl Write for i32 {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        (*self as u32).write(bytes, pos)
    }
}

impl Write for u64 {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let value = self.to_be_bytes();
        bytes[*pos] = value[0];
        bytes[*pos + 1] = value[1];
        bytes[*pos + 2] = value[2];
        bytes[*pos + 3] = value[3];
        bytes[*pos + 4] = value[4];
        bytes[*pos + 5] = value[5];
        bytes[*pos + 6] = value[6];
        bytes[*pos + 7] = value[7];
        *pos += core::mem::size_of::<u64>();
        Ok(())
    }
}

impl Write for i64 {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        (*self as u64).write(bytes, pos)
    }
}

impl<'a> Write for String {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let len = self.len() as u16;
        len.write(bytes, pos).expect("failed to write length");
        for i in 0..len {
            bytes[*pos] = self.as_bytes()[i as usize];
            *pos = pos.saturating_add(1);
        }
        Ok(())
    }
}

impl Write for bool {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let value = if *self { 1 } else { 0 };
        (value as u8).write(bytes, pos)
    }
}

impl<T: Write> Write for Vec<T> {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let len = self.len() as u32;
        len.write(bytes, pos)?;
        for item in self.iter() {
            item.write(bytes, pos)?;
        }
        Ok(())
    }
}

impl<T: Write> Write for VecDeque<T> {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let len = self.len() as u32;
        len.write(bytes, pos)?;
        for item in self.iter() {
            item.write(bytes, pos)?;
        }
        Ok(())
    }
}

impl<T: Write> Write for HashSet<T> {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let len = self.len() as u32;
        len.write(bytes, pos)?;
        for item in self.iter() {
            item.write(bytes, pos)?;
        }
        Ok(())
    }
}

impl<T1: Write, T2: Write> Write for (T1, T2) {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.0.write(bytes, pos)?;
        self.1.write(bytes, pos)?;
        Ok(())
    }
}

impl<T1: Write, T2: Write, T3: Write> Write for (T1, T2, T3) {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.0.write(bytes, pos)?;
        self.1.write(bytes, pos)?;
        self.2.write(bytes, pos)?;
        Ok(())
    }
}

impl<T1: Write, T2: Write, T3: Write, T4: Write> Write for (T1, T2, T3, T4) {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.0.write(bytes, pos)?;
        self.1.write(bytes, pos)?;
        self.2.write(bytes, pos)?;
        self.3.write(bytes, pos)?;
        Ok(())
    }
}
