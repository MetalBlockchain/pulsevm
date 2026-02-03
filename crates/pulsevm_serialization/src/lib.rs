use core::fmt;
use std::{error::Error, usize};

mod varint;
use pulsevm_error::ChainError;
pub use varint::*;

mod primitives;

pub trait NumBytes {
    /// Count the number of bytes a type is expected to use.
    fn num_bytes(&self) -> usize;
}

/// Error that can be returned when writing bytes.
#[derive(Debug, Clone)]
pub enum WriteError {
    /// Not enough space in the vector.
    NotEnoughSpace,
    /// Failed to parse an integer.
    TryFromIntError,
    /// Not enough bytes to read.
    NotEnoughBytes,
    CustomError(String),
}

impl Error for WriteError {}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::NotEnoughSpace => write!(f, "not enough space to write"),
            WriteError::TryFromIntError => write!(f, "failed to parse integer"),
            WriteError::NotEnoughBytes => write!(f, "not enough bytes to read"),
            WriteError::CustomError(msg) => write!(f, "write error: {}", msg),
        }
    }
}

impl From<WriteError> for ChainError {
    fn from(error: WriteError) -> ChainError {
        match error {
            WriteError::NotEnoughSpace => {
                ChainError::SerializationError("not enough space to write".to_string())
            }
            WriteError::TryFromIntError => {
                ChainError::SerializationError("failed to parse integer".to_string())
            }
            WriteError::NotEnoughBytes => {
                ChainError::SerializationError("not enough bytes to read".to_string())
            }
            WriteError::CustomError(msg) => {
                ChainError::SerializationError(format!("write error: {}", msg))
            }
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

#[derive(Debug, Clone)]
pub enum ReadError {
    /// Not enough bytes.
    NotEnoughBytes,
    ParseError,
    Overflow,
    CustomError(String),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::NotEnoughBytes => write!(f, "not enough bytes to read"),
            ReadError::ParseError => write!(f, "parse error"),
            ReadError::Overflow => write!(f, "integer overflow"),
            ReadError::CustomError(msg) => write!(f, "read error: {}", msg),
        }
    }
}

impl Error for ReadError {}

impl From<ReadError> for ChainError {
    fn from(error: ReadError) -> ChainError {
        match error {
            ReadError::NotEnoughBytes => {
                ChainError::SerializationError("not enough bytes to read".to_string())
            }
            ReadError::ParseError => ChainError::SerializationError("parse error".to_string()),
            ReadError::Overflow => ChainError::SerializationError("integer overflow".to_string()),
            ReadError::CustomError(msg) => {
                ChainError::SerializationError(format!("read error: {}", msg))
            }
        }
    }
}

pub trait Read: Sized + NumBytes {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError>;
}
