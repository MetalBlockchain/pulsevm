use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    hash::Hash,
};

use crate::{NumBytes, Read, ReadError, VarUint32, Write, WriteError};

impl NumBytes for usize {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        VarUint32::from(*self).num_bytes()
    }
}

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

impl NumBytes for f32 {
    #[inline]
    fn num_bytes(&self) -> usize {
        4
    }
}

impl NumBytes for f64 {
    #[inline]
    fn num_bytes(&self) -> usize {
        8
    }
}

impl NumBytes for String {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        self.len().num_bytes() + self.len()
    }
}

impl NumBytes for bool {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        core::mem::size_of::<u8>()
    }
}

impl<T: NumBytes> NumBytes for Option<T> {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        match self {
            Some(value) => 1 + value.num_bytes(),
            None => 1,
        }
    }
}

impl<T: NumBytes> NumBytes for Vec<T> {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        let mut count = self.len().num_bytes();
        for item in self {
            count += item.num_bytes();
        }
        count
    }
}

impl<T: NumBytes> NumBytes for VecDeque<T> {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        let mut count = self.len().num_bytes();
        for item in self {
            count += item.num_bytes();
        }
        count
    }
}

impl<T: NumBytes> NumBytes for HashSet<T> {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        let mut count = self.len().num_bytes();
        for item in self {
            count += item.num_bytes();
        }
        count
    }
}

impl<K: Write + NumBytes, V: Write + NumBytes> NumBytes for BTreeMap<K, V> {
    #[inline(always)]
    fn num_bytes(&self) -> usize {
        let mut count = self.len().num_bytes();
        for (key, value) in self {
            count += key.num_bytes();
            count += value.num_bytes();
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

impl Read for usize {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        VarUint32::read(bytes, pos).map(|v| v.0 as usize)
    }
}

impl Read for u8 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        if bytes.len() < *pos + core::mem::size_of::<u8>() {
            return Err(ReadError::NotEnoughBytes);
        }
        let value = u8::from_le_bytes([bytes[*pos]]);
        *pos += core::mem::size_of::<u8>();
        Ok(value)
    }
}

impl Read for i8 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let result = u8::read(bytes, pos)?;
        Ok(result as i8)
    }
}

impl Read for u16 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        if bytes.len() < *pos + core::mem::size_of::<u16>() {
            return Err(ReadError::NotEnoughBytes);
        }
        let value = u16::from_le_bytes([bytes[*pos], bytes[*pos + 1]]);
        *pos += core::mem::size_of::<u16>();
        Ok(value)
    }
}

impl Read for i16 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let result = u16::read(bytes, pos)?;
        Ok(result as i16)
    }
}

impl Read for u32 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        if bytes.len() < *pos + core::mem::size_of::<u32>() {
            return Err(ReadError::NotEnoughBytes);
        }
        let value = u32::from_le_bytes([
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
        let result = u32::read(bytes, pos)?;
        Ok(result as i32)
    }
}

impl Read for u64 {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        if bytes.len() < *pos + core::mem::size_of::<u64>() {
            return Err(ReadError::NotEnoughBytes);
        }
        let value = u64::from_le_bytes([
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
        let result = u64::read(bytes, pos)?;
        Ok(result as i64)
    }
}

impl Read for f32 {
    #[inline]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let bits = u32::read(bytes, pos)?;
        let num = Self::from_bits(bits);
        Ok(num)
    }
}

impl Read for f64 {
    #[inline]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let bits = u64::read(bytes, pos)?;
        let num = Self::from_bits(bits);
        Ok(num)
    }
}

impl Read for String {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let len = usize::read(bytes, pos)?;

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
        let len = usize::read(bytes, pos)?;

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
        let len = usize::read(bytes, pos)?;

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
        let len = usize::read(bytes, pos)?;

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

impl<K: Read + Write + NumBytes + Ord, V: Read + Write + NumBytes> Read for BTreeMap<K, V> {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let len = usize::read(bytes, pos)?;

        if *pos + len > bytes.len() {
            return Err(ReadError::NotEnoughBytes);
        }

        let mut map = BTreeMap::new();
        for _ in 0..len {
            let key = K::read(bytes, pos)?;
            let value = V::read(bytes, pos)?;
            map.insert(key, value);
        }
        Ok(map)
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
        let value = u8::read(bytes, pos)?;
        Ok(value != 0)
    }
}

impl<T: Read> Read for Option<T> {
    #[inline(always)]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let is_some = bool::read(bytes, pos)?;
        if is_some {
            let value = T::read(bytes, pos)?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }
}

impl Write for usize {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        VarUint32(*self as u32).write(bytes, pos)
    }
}

impl Write for u8 {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let value = self.to_le_bytes();
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
        let value = self.to_le_bytes();
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
        let value = self.to_le_bytes();
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
        let value = self.to_le_bytes();
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

impl Write for f32 {
    #[inline]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.to_bits().write(bytes, pos)
    }
}

impl Write for f64 {
    #[inline]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.to_bits().write(bytes, pos)
    }
}

impl<'a> Write for String {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.len().write(bytes, pos)?;
        if *pos + self.len() > bytes.len() {
            return Err(WriteError::NotEnoughSpace);
        }
        for i in 0..self.len() {
            bytes[*pos] = self.as_bytes()[i];
            *pos += 1;
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

impl<T: Write> Write for Option<T> {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let is_some = self.is_some();
        is_some.write(bytes, pos)?;
        if let Some(value) = self {
            value.write(bytes, pos)?;
        }
        Ok(())
    }
}

impl<T: Write> Write for Vec<T> {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.len().write(bytes, pos)?;
        for item in self.iter() {
            item.write(bytes, pos)?;
        }
        Ok(())
    }
}

impl<T: Write> Write for VecDeque<T> {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.len().write(bytes, pos)?;
        for item in self.iter() {
            item.write(bytes, pos)?;
        }
        Ok(())
    }
}

impl<T: Write> Write for HashSet<T> {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.len().write(bytes, pos)?;
        for item in self.iter() {
            item.write(bytes, pos)?;
        }
        Ok(())
    }
}

impl<K: Write + NumBytes, V: Write + NumBytes> Write for BTreeMap<K, V> {
    #[inline(always)]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.len().write(bytes, pos)?;
        for (key, value) in self.iter() {
            key.write(bytes, pos)?;
            value.write(bytes, pos)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_num_bytes() {
        assert_eq!("".to_string().num_bytes(), 1);
        assert_eq!("hello".to_string().num_bytes(), 6);
    }
}