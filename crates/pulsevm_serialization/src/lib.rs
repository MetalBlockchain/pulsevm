use core::{fmt, str};
use std::{collections::HashSet, error::Error, hash::Hash, usize};

/// Error that can be returned when writing bytes.
#[derive(Debug, Clone, Copy)]
pub enum WriteError {
    /// Not enough space in the vector.
    NotEnoughSpace,
    /// Failed to parse an integer.
    TryFromIntError,
    /// Not enough bytes to read.
    NotEnoughBytes,
}

pub trait Serialize {
    fn serialize(&self, bytes: &mut Vec<u8>);
}

impl Serialize for bool {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        (*self as u8).serialize(bytes);
    }
}

impl Serialize for u8 {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        let value = self.to_be_bytes();
        bytes.extend_from_slice(&value);
    }
}

impl Serialize for u16 {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        let value = self.to_be_bytes();
        bytes.extend_from_slice(&value);
    }
}

impl Serialize for u32 {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        let value = self.to_be_bytes();
        bytes.extend_from_slice(&value);
    }
}

impl Serialize for u64 {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        let value = self.to_be_bytes();
        bytes.extend_from_slice(&value);
    }
}

impl Serialize for i64 {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        (*self as u64).serialize(bytes)
    }
}

impl Serialize for String {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        let len = self.len() as u16;
        len.serialize(bytes);
        bytes.extend_from_slice(self.as_bytes());
    }
}

impl<T: Serialize> Serialize for Vec<T> {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        let length = self.len() as u32;
        length.serialize(bytes);
        for item in self {
            item.serialize(bytes);
        }
    }
}

impl<T: Serialize> Serialize for HashSet<T> {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        let length = self.len() as u32;
        length.serialize(bytes);
        for item in self {
            item.serialize(bytes);
        }
    }
}

pub fn serialize(value: &impl Serialize) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize(&mut bytes);
    bytes
}

#[derive(Debug, Clone, Copy)]
pub enum ReadError {
    /// Not enough bytes.
    NotEnoughBytes(usize, usize),
    ParseError,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::NotEnoughBytes(len, size) => {
                write!(f, "Not enough bytes, pos {}, need {}", len, size)
            }
            ReadError::ParseError => write!(f, "Parse error"),
        }
    }
}

impl Error for ReadError {}

pub trait Deserialize: Sized {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, ReadError>;
}

impl Deserialize for bool {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let value = u8::deserialize(data, pos)?;
        Ok(value != 0)
    }
}

impl Deserialize for u8 {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        if *pos + 1 > data.len() {
            return Err(ReadError::NotEnoughBytes(*pos, 1));
        }
        let value = u8::from_be_bytes([data[*pos]]);
        *pos += 1;
        Ok(value)
    }
}

impl Deserialize for u16 {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        if *pos + 2 > data.len() {
            return Err(ReadError::NotEnoughBytes(*pos, 2));
        }
        let value = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        Ok(value)
    }
}

impl Deserialize for u32 {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        if *pos + 4 > data.len() {
            return Err(ReadError::NotEnoughBytes(*pos, 4));
        }
        let value =
            u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
        *pos += 4;
        Ok(value)
    }
}

impl Deserialize for u64 {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        if *pos + 8 > data.len() {
            return Err(ReadError::NotEnoughBytes(*pos, 8));
        }
        let value = u64::from_be_bytes([
            data[*pos],
            data[*pos + 1],
            data[*pos + 2],
            data[*pos + 3],
            data[*pos + 4],
            data[*pos + 5],
            data[*pos + 6],
            data[*pos + 7],
        ]);
        *pos += 8;
        Ok(value)
    }
}

impl Deserialize for i64 {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        u64::deserialize(data, pos).map(|v| v as i64)
    }
}

impl Deserialize for String {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        // Read 2-byte length prefix (big endian)
        let len = u16::deserialize(data, pos).unwrap() as usize;

        if *pos + len > data.len() {
            return Err(ReadError::NotEnoughBytes(*pos, len));
        }

        let str_bytes = &data[*pos..*pos + len];
        *pos += len;

        match str::from_utf8(str_bytes) {
            Ok(s) => Ok(s.to_string()), // Into<String> in most contexts, still OK
            Err(_) => Err(ReadError::ParseError),
        }
    }
}

impl<T: Deserialize> Deserialize for Vec<T> {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let length = u32::deserialize(data, pos)?;
        let mut vec = Vec::with_capacity(length as usize);
        for _ in 0..length {
            let item = T::deserialize(data, pos)?;
            vec.push(item);
        }
        Ok(vec)
    }
}

impl<T: Deserialize> Deserialize for HashSet<T>
where
    T: Hash + Eq,
{
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let length = u32::deserialize(data, pos)?;
        let mut set = HashSet::with_capacity(length as usize);
        for _ in 0..length {
            let item = T::deserialize(data, pos)?;
            set.insert(item);
        }
        Ok(set)
    }
}
