use std::{fmt, str::FromStr};

/// The maximum allowed length of EOSIO symbol codes.
pub const SYMBOL_CODE_MAX_LEN: usize = 7;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ParseSymbolCodeError {
    /// The symbol is too long. Symbols must be 7 characters or less.
    TooLong,
    /// The symbol contains an invalid character. Symbols can only contain
    /// uppercase letters A-Z.
    BadChar(u8),
}

impl fmt::Display for ParseSymbolCodeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::TooLong => {
                write!(f, "symbol is too long, must be 7 chars or less")
            }
            Self::BadChar(c) => write!(
                f,
                "symbol contains invalid character '{}'",
                char::from(c)
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SymbolCode(u64);

impl SymbolCode {
    #[inline]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[inline]
    #[must_use]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for SymbolCode {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = symbol_code_to_bytes(self.0);
        let value = str::from_utf8(&bytes)
            .map(str::trim)
            .map_err(|_| fmt::Error)?;
        write!(f, "{}", value)
    }
}

impl FromStr for SymbolCode {
    type Err = ParseSymbolCodeError;

    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        symbol_code_from_bytes(value.bytes()).map(Into::into)
    }
}

impl From<u64> for SymbolCode {
    #[inline]
    fn from(n: u64) -> Self {
        Self(n)
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
    let mut value = 0_u64;
    for (i, c) in iter.enumerate().rev() {
        if i == SYMBOL_CODE_MAX_LEN {
            return Err(ParseSymbolCodeError::TooLong);
        } else if c < b'A' || c > b'Z' {
            return Err(ParseSymbolCodeError::BadChar(c));
        } else {
            value <<= 8;
            value |= u64::from(c);
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_code_from_str() {
        assert_eq!(
            SymbolCode::from_str("EOS").unwrap(),
            SymbolCode::new(5459781u64)
        );
        assert!(SymbolCode::from_str("TOOLONGS").is_err());
        assert!(SymbolCode::from_str("BAD!").is_err());
    }

    #[test]
    fn test_symbol_code_to_string() {
        let code = SymbolCode::new(5459781u64);
        assert_eq!(code.to_string(), "EOS");
    }
}