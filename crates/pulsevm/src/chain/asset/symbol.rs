use core::fmt;

use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::SymbolCode;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.0.serialize(bytes);
    }
}

impl Deserialize for Symbol {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let value = u64::deserialize(data, pos)?;
        Ok(Symbol(value))
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
