use core::fmt;
use std::str::FromStr;

use pulsevm_proc_macros::{NumBytes, Write};
use pulsevm_serialization::{Read, ReadError};
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::chain::asset::SymbolCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolError {
    /// Found a non-uppercase ASCII letter.
    InvalidChar(char),
    /// More than 7 characters won't fit (precision already uses 1 byte).
    TooLong(usize),
    /// Precision field was missing, non-numeric, or above 18.
    InvalidPrecision,
    /// No comma separating precision from code.
    MissingSeparator,
    /// Failed to parse symbol code.
    ParseError,
}

impl fmt::Display for SymbolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolError::InvalidChar(c) => write!(f, "invalid character in symbol: '{}'", c),
            SymbolError::TooLong(len) => write!(f, "symbol is too long: {} characters", len),
            SymbolError::InvalidPrecision => write!(f, "invalid symbol precision"),
            SymbolError::MissingSeparator => {
                write!(f, "symbol must be formatted as '<precision>,<code>'")
            }
            SymbolError::ParseError => write!(f, "failed to parse symbol code"),
        }
    }
}

impl std::error::Error for SymbolError {}

/// Maximum decimal precision, matching nodeos. Above this, `10^precision`
/// overflows the i64 used for asset amounts.
pub const MAX_PRECISION: u8 = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Write, NumBytes)]
pub struct Symbol(pub u64);

impl Symbol {
    /// Unchecked constructor. Callers must ensure the result is valid, or use
    /// [`Symbol::try_new_with_code`].
    #[inline]
    #[must_use]
    pub const fn new_with_code(precision: u8, code: SymbolCode) -> Self {
        Self(symbol_from_code(precision, code.as_u64()))
    }

    /// Checked constructor: rejects precision above [`MAX_PRECISION`] and
    /// malformed codes.
    pub fn try_new_with_code(precision: u8, code: SymbolCode) -> Result<Self, SymbolError> {
        if precision > MAX_PRECISION {
            return Err(SymbolError::InvalidPrecision);
        }
        if !code.is_valid() {
            return Err(SymbolError::ParseError);
        }
        Ok(Self::new_with_code(precision, code))
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

    /// Mirrors nodeos `symbol::valid()`: precision within range and a
    /// well-formed code.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.precision() <= MAX_PRECISION && self.code().is_valid()
    }
}

impl fmt::Display for Symbol {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{},{}", self.precision(), self.code())
    }
}

impl Read for Symbol {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let sym = Symbol(u64::read(bytes, pos)?);
        // Deserialization must reject malformed symbols; the derived impl
        // would accept arbitrary bytes and let them reach asset arithmetic
        // and table keys.
        if !sym.is_valid() {
            return Err(ReadError::ParseError);
        }
        Ok(sym)
    }
}

impl Serialize for Symbol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Symbol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SymbolVisitor;

        impl<'de> de::Visitor<'de> for SymbolVisitor {
            type Value = Symbol;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a symbol string formatted as '<precision>,<code>'")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Symbol, E> {
                Symbol::from_str(v).map_err(de::Error::custom)
            }
        }

        // Matches the string form written by `Serialize`.
        deserializer.deserialize_str(SymbolVisitor)
    }
}

impl FromStr for Symbol {
    type Err = SymbolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(',');
        // `split` always yields at least one element, so only the second call
        // can be None — that is the missing-comma case.
        let precision_str = parts.next().unwrap_or_default();
        let code_str = parts.next().ok_or(SymbolError::MissingSeparator)?;
        if parts.next().is_some() {
            return Err(SymbolError::ParseError);
        }

        let precision: u8 = precision_str
            .parse()
            .map_err(|_| SymbolError::InvalidPrecision)?;
        let code = SymbolCode::from_str(code_str).map_err(|_| SymbolError::ParseError)?;

        Symbol::try_new_with_code(precision, code)
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

    // "EOS" packed little-endian: E=0x45, O=0x4F, S=0x53 -> 0x53_4F_45.
    const EOS_CODE: u64 = 0x53_4F_45;

    #[test]
    fn test_symbol() {
        let symbol = Symbol::new_with_code(4, SymbolCode::new(EOS_CODE));
        assert_eq!(symbol.precision(), 4);
        assert_eq!(symbol.code().as_u64(), EOS_CODE);
        assert_eq!(symbol.to_string(), "4,EOS");
        assert_eq!(symbol.as_u64(), 1397703940u64); // EOS_CODE << 8 | 4
        assert!(symbol.is_valid());
    }

    #[test]
    fn rejects_precision_above_max() {
        assert!(!Symbol::new_with_code(19, SymbolCode::new(EOS_CODE)).is_valid());
        assert_eq!(
            Symbol::try_new_with_code(19, SymbolCode::new(EOS_CODE)),
            Err(SymbolError::InvalidPrecision)
        );
        assert_eq!("19,EOS".parse::<Symbol>(), Err(SymbolError::InvalidPrecision));
    }

    #[test]
    fn rejects_embedded_nul_in_code() {
        // "EOS\0X" — displays as "EOS" but is a distinct u64. Must not
        // deserialize, or two symbols print identically and compare unequal.
        let sneaky = Symbol(((0x58u64 << 32) | EOS_CODE) << 8 | 4);
        assert!(!sneaky.is_valid());
        assert!(Symbol::read(&sneaky.as_u64().to_le_bytes(), &mut 0).is_err());
    }

    #[test]
    fn rejects_empty_code() {
        assert!(!Symbol::new_with_code(4, SymbolCode::new(0)).is_valid());
    }

    #[test]
    fn from_str_errors_are_specific() {
        assert_eq!("EOS".parse::<Symbol>(), Err(SymbolError::MissingSeparator));
        assert_eq!("x,EOS".parse::<Symbol>(), Err(SymbolError::InvalidPrecision));
        assert_eq!("4,eos".parse::<Symbol>(), Err(SymbolError::ParseError));
    }

    #[test]
    fn json_round_trip() {
        let symbol = Symbol::new_with_code(4, SymbolCode::new(EOS_CODE));
        let json = serde_json::to_string(&symbol).unwrap();
        assert_eq!(json, "\"4,EOS\"");
        assert_eq!(serde_json::from_str::<Symbol>(&json).unwrap(), symbol);
    }

    #[test]
    fn binary_round_trip() {
        use pulsevm_serialization::Write;
        let symbol = Symbol::new_with_code(4, SymbolCode::new(EOS_CODE));
        let packed = symbol.pack().unwrap();
        assert_eq!(Symbol::read(&packed, &mut 0).unwrap(), symbol);
    }
}