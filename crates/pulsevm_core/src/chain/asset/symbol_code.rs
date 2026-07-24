use std::{fmt::{self, Write}, str::FromStr};

use pulsevm_proc_macros::{NumBytes, Write};
use pulsevm_serialization::{Read, ReadError};
use serde::{Deserialize, Deserializer, Serialize, de};

/// The maximum allowed length of EOSIO symbol codes.
pub const SYMBOL_CODE_MAX_LEN: usize = 7;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ParseSymbolCodeError {
    /// The symbol is too long. Symbols must be 7 characters or less.
    TooLong,
    /// The symbol is empty. Symbols must have at least one character.
    Empty,
    /// The symbol contains an invalid character. Symbols can only contain
    /// uppercase letters A-Z.
    BadChar(u8),
}

impl fmt::Display for ParseSymbolCodeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::TooLong => write!(f, "symbol is too long, must be 7 chars or less"),
            Self::Empty => write!(f, "symbol is empty"),
            Self::BadChar(c) => write!(f, "symbol contains invalid character '{}'", char::from(c)),
        }
    }
}

impl std::error::Error for ParseSymbolCodeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Write, NumBytes)]
pub struct SymbolCode(u64);

impl SymbolCode {
    /// Unchecked constructor. Callers must ensure validity, or use
    /// [`SymbolCode::try_new`].
    #[inline]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Checked constructor: rejects empty codes, non-uppercase bytes, and
    /// trailing garbage after the code.
    pub fn try_new(value: u64) -> Result<Self, ParseSymbolCodeError> {
        let code = Self(value);
        if !code.is_valid() {
            // Report the first offending byte where possible.
            let mut sym = value;
            let mut i = 0;
            while i < SYMBOL_CODE_MAX_LEN {
                let c = (sym & 0xFF) as u8;
                if c == 0 {
                    return if i == 0 {
                        Err(ParseSymbolCodeError::Empty)
                    } else {
                        // Zero byte followed by non-zero data.
                        Err(ParseSymbolCodeError::BadChar(0))
                    };
                }
                if !c.is_ascii_uppercase() {
                    return Err(ParseSymbolCodeError::BadChar(c));
                }
                sym >>= 8;
                i += 1;
            }
            return Err(ParseSymbolCodeError::TooLong);
        }
        Ok(code)
    }

    #[inline]
    #[must_use]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Mirrors nodeos `symbol_code::valid()`: 1-7 uppercase ASCII bytes,
    /// all remaining bytes zero.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let mut sym = self.as_u64();
        let mut i = 0;
        while i < SYMBOL_CODE_MAX_LEN {
            let c = (sym & 0xFF) as u8;
            if !c.is_ascii_uppercase() {
                break;
            }
            sym >>= 8;
            i += 1;
        }
        // i > 0 rejects the empty code; sym == 0 rejects trailing garbage
        // after the letters, e.g. "EOS\0X".
        i > 0 && sym == 0
    }

    /// Number of characters in the code. Only meaningful for valid codes.
    #[must_use]
    pub fn len(&self) -> usize {
        let mut sym = self.as_u64();
        let mut n = 0;
        while sym & 0xFF != 0 && n < SYMBOL_CODE_MAX_LEN {
            sym >>= 8;
            n += 1;
        }
        n
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Display for SymbolCode {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write bytes directly rather than padding-then-trimming, so an
        // invalid code cannot masquerade as a shorter valid one.
        let mut sym = self.0;
        for _ in 0..SYMBOL_CODE_MAX_LEN {
            let c = (sym & 0xFF) as u8;
            if c == 0 {
                break;
            }
            f.write_char(char::from(c))?;
            sym >>= 8;
        }
        Ok(())
    }
}

impl Read for SymbolCode {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let code = SymbolCode(u64::read(bytes, pos)?);
        if !code.is_valid() {
            return Err(ReadError::ParseError);
        }
        Ok(code)
    }
}

impl Serialize for SymbolCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SymbolCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SymbolCodeVisitor;

        impl<'de> de::Visitor<'de> for SymbolCodeVisitor {
            type Value = SymbolCode;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a symbol code of 1-7 uppercase letters")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<SymbolCode, E> {
                SymbolCode::from_str(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(SymbolCodeVisitor)
    }
}

impl FromStr for SymbolCode {
    type Err = ParseSymbolCodeError;

    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        symbol_code_from_bytes(value.bytes()).map(SymbolCode)
    }
}

impl TryFrom<u64> for SymbolCode {
    type Error = ParseSymbolCodeError;

    #[inline]
    fn try_from(n: u64) -> Result<Self, Self::Error> {
        Self::try_new(n)
    }
}

#[inline]
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn symbol_code_to_bytes(value: u64) -> [u8; SYMBOL_CODE_MAX_LEN] {
    let mut chars = [b' '; SYMBOL_CODE_MAX_LEN];
    let mut v = value;
    for c in &mut chars {
        if v == 0 {
            break;
        }
        *c = (v & 0xFF) as u8;
        v >>= 8;
    }
    chars
}

#[inline]
pub fn symbol_code_from_bytes<I>(iter: I) -> Result<u64, ParseSymbolCodeError>
where
    I: DoubleEndedIterator<Item = u8> + ExactSizeIterator,
{
    // Check length once, up front — the previous per-index check compared a
    // reversed index against the max length, which reads as an off-by-one.
    let len = iter.len();
    if len == 0 {
        return Err(ParseSymbolCodeError::Empty);
    }
    if len > SYMBOL_CODE_MAX_LEN {
        return Err(ParseSymbolCodeError::TooLong);
    }

    let mut value = 0_u64;
    for c in iter.rev() {
        if !c.is_ascii_uppercase() {
            return Err(ParseSymbolCodeError::BadChar(c));
        }
        value <<= 8;
        value |= u64::from(c);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EOS: u64 = 0x53_4F_45; // 5459781

    #[test]
    fn test_symbol_code_from_str() {
        assert_eq!(SymbolCode::from_str("EOS").unwrap(), SymbolCode::new(EOS));
        assert_eq!(
            SymbolCode::from_str("TOOLONGS"),
            Err(ParseSymbolCodeError::TooLong)
        );
        assert_eq!(
            SymbolCode::from_str("BAD!"),
            Err(ParseSymbolCodeError::BadChar(b'!'))
        );
        assert_eq!(SymbolCode::from_str(""), Err(ParseSymbolCodeError::Empty));
        assert_eq!(
            SymbolCode::from_str("eos"),
            Err(ParseSymbolCodeError::BadChar(b'e'))
        );
    }

    #[test]
    fn test_symbol_code_to_string() {
        assert_eq!(SymbolCode::new(EOS).to_string(), "EOS");
        assert_eq!(SymbolCode::from_str("A").unwrap().to_string(), "A");
        assert_eq!(
            SymbolCode::from_str("ABCDEFG").unwrap().to_string(),
            "ABCDEFG"
        );
    }

    #[test]
    fn rejects_trailing_garbage() {
        // "EOS\0X" — must not validate, and must not display as "EOS".
        let sneaky = SymbolCode::new((0x58u64 << 32) | EOS);
        assert!(!sneaky.is_valid());
        assert!(SymbolCode::read(&sneaky.as_u64().to_le_bytes(), &mut 0).is_err());
    }

    #[test]
    fn rejects_empty_code() {
        assert!(!SymbolCode::new(0).is_valid());
        assert!(SymbolCode::read(&0u64.to_le_bytes(), &mut 0).is_err());
    }

    #[test]
    fn round_trips() {
        for s in ["A", "EOS", "ABCDEFG", "XYZ"] {
            let code = SymbolCode::from_str(s).unwrap();
            assert_eq!(code.to_string(), s);
            assert_eq!(serde_json::from_str::<SymbolCode>(&format!("\"{s}\"")).unwrap(), code);
        }
    }
}