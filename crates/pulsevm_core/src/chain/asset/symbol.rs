use core::fmt;
use std::str::FromStr;

use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::{Deserialize, Serialize};

use crate::chain::asset::SymbolCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolError {
    /// Found a non-uppercase ASCII letter.
    InvalidChar(char),
    /// More than 7 characters won't fit (precision already uses 1 byte).
    TooLong(usize),
    /// Failed to parse symbol code.
    ParseError,
}

impl fmt::Display for SymbolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolError::InvalidChar(c) => write!(f, "invalid character in symbol: '{}'", c),
            SymbolError::TooLong(len) => write!(f, "symbol is too long: {} characters", len),
            SymbolError::ParseError => write!(f, "failed to parse symbol code"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes, Deserialize)]
pub struct Symbol(pub u64);

impl Symbol {
    #[inline]
    #[must_use]
    pub const fn new_with_code(precision: u8, code: SymbolCode) -> Self {
        Self(symbol_from_code(precision, code.as_u64()))
    }

    #[inline]
    #[must_use]
    pub const fn precision(&self) -> u8 {
        symbol_to_precision(self.as_u64())
    }

    #[inline]
    #[must_use]
    pub const fn code(&self) -> SymbolCode {
        SymbolCode::new(symbol_to_code(self.as_u64()))
    }

    #[inline]
    #[must_use]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for Symbol {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        extern crate alloc;
        use alloc::string::ToString;
        write!(f, "{},{}", self.precision(), self.code().to_string())
    }
}

impl Serialize for Symbol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = format!("{},{}", self.precision(), self.code());
        serializer.serialize_str(&value)
    }
}

impl FromStr for Symbol {
    type Err = SymbolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(',');
        let precision_str = parts.next().ok_or(SymbolError::TooLong(0))?;
        let code_str = parts.next().ok_or(SymbolError::TooLong(0))?;
        if parts.next().is_some() {
            return Err(SymbolError::TooLong(s.len()));
        }

        let precision: u8 = precision_str
            .parse()
            .map_err(|_| SymbolError::TooLong(precision_str.len()))?;
        let code = SymbolCode::from_str(code_str).map_err(|_| SymbolError::ParseError)?;

        Ok(Symbol::new_with_code(precision, code))
    }
}

#[inline]
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub const fn symbol_to_precision(value: u64) -> u8 {
    (value & 0xFF) as u8
}

#[inline]
#[must_use]
pub const fn symbol_to_code(value: u64) -> u64 {
    value >> 8
}

#[inline]
#[must_use]
pub const fn symbol_from_code(precision: u8, code: u64) -> u64 {
    (code << 8) | (precision as u64)
}

#[inline]
#[must_use]
pub fn string_to_symbol(precision: u8, s: &str) -> Result<u64, SymbolError> {
    let bytes = s.as_bytes();

    // Max 7 letters since 1 byte is reserved for precision.
    if bytes.len() > 7 {
        return Err(SymbolError::TooLong(s.len()));
    }

    let mut result: u64 = precision as u64; // LSB = precision

    for (i, &b) in bytes.iter().enumerate() {
        if !(b'A'..=b'Z').contains(&b) {
            return Err(SymbolError::InvalidChar(b as char));
        }
        // place first char at bits 8..15, next at 16..23, etc.
        result |= (b as u64) << (8 * (i + 1));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol() {
        let symbol = Symbol::new_with_code(4, SymbolCode::new(5459781u64)); // "ERCS"
        assert_eq!(symbol.precision(), 4);
        assert_eq!(symbol.code().as_u64(), 5459781u64);
        assert_eq!(symbol.to_string(), "4,EOS");
        assert_eq!(symbol.as_u64(), 1397703940u64); // 4 << 8 | 5459781
    }
}
