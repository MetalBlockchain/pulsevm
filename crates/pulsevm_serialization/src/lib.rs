use core::{fmt, str};
use std::{collections::HashSet, error::Error, hash::Hash, usize};

mod varint;
pub use varint::*;

mod primitives;

pub trait NumBytes {
    /// Count the number of bytes a type is expected to use.
    fn num_bytes(&self) -> usize;
}

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

impl Error for WriteError {}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::NotEnoughSpace => write!(f, "not enough space to write"),
            WriteError::TryFromIntError => write!(f, "failed to parse integer"),
            WriteError::NotEnoughBytes => write!(f, "not enough bytes to read"),
        }
    }
}

pub trait Write: Sized + NumBytes {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError>;

    #[inline(always)]
    fn pack(&self) -> Result<Vec<u8>, WriteError> {
        let num_bytes = self.num_bytes();
        let mut bytes = vec![0_u8; num_bytes];
        self.write(&mut bytes, &mut 0)?;
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ReadError {
    /// Not enough bytes.
    NotEnoughBytes,
    ParseError,
    Overflow,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::NotEnoughBytes => write!(f, "not enough bytes to read"),
            ReadError::ParseError => write!(f, "parse error"),
            ReadError::Overflow => write!(f, "integer overflow"),
        }
    }
}

impl Error for ReadError {}

pub trait Read: Sized + NumBytes {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError>;
}
