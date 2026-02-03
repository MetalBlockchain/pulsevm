use proc_macro2::{Literal, TokenStream};
use pulsevm_error::ChainError;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use quote::{ToTokens, TokenStreamExt};
use serde::{Deserialize, Serialize};
use std::{fmt, ops::Deref, str::FromStr};
use syn::{
    LitStr,
    parse::{Parse, ParseStream, Result as ParseResult},
};

mod utils;
pub use utils::{NAME_CHARS, NAME_MAX_LEN, name_from_bytes, name_to_bytes};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ParseNameError {
    /// The name contains a disallowed character.
    BadChar(u8),
    /// The name is over the maximum allowed length.
    TooLong,
}

impl fmt::Display for ParseNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseNameError::BadChar(c) => write!(f, "bad character in name: '{}'", *c as char),
            ParseNameError::TooLong => write!(f, "name is too long"),
        }
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Read, Write, NumBytes,
)]
pub struct Name(u64);

impl Name {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    pub const fn empty(&self) -> bool {
        self.0 == 0
    }

    pub fn as_bytes(&self) -> [u8; NAME_MAX_LEN] {
        name_to_bytes(self.0)
    }
}

impl From<u64> for Name {
    fn from(n: u64) -> Self {
        Self(n)
    }
}

impl From<Name> for u64 {
    fn from(i: Name) -> Self {
        i.0
    }
}

impl FromStr for Name {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // First try to parse as u64
        if let Ok(value) = s.parse::<u64>() {
            return Ok(value.into()); // assuming `u64: Into<YourType>`
        }

        let name = name_from_bytes(s.bytes())
            .map_err(|e| ChainError::ParseError(format!("invalid name format: {}", e)))?;
        Ok(name.into())
    }
}

impl fmt::Display for Name {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.as_bytes();
        let value = str::from_utf8(&bytes)
            .map(|s| s.trim_end_matches('.'))
            .map_err(|_| fmt::Error)?;
        write!(f, "{}", value)
    }
}

impl PartialEq<u64> for Name {
    fn eq(&self, other: &u64) -> bool {
        &self.0 == other
    }
}

impl PartialEq<Name> for u64 {
    fn eq(&self, other: &Name) -> bool {
        self == &other.0
    }
}

impl Deref for Name {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for Name {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Name::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Parse for Name {
    fn parse(input: ParseStream) -> ParseResult<Self> {
        let name = input.parse::<LitStr>()?.value();
        name_from_bytes(name.bytes())
            .map(Self)
            .map_err(|_e| input.error("failed to parse name"))
    }
}

impl ToTokens for Name {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append(Literal::u64_suffixed(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        let name = Name::new(6138663577826885632);
        assert_eq!(name.as_u64(), 6138663577826885632);
        assert_eq!(name.to_string(), "eosio");
    }

    #[test]
    fn test_name_from_str() {
        let name = Name::from_str("eosio").unwrap();
        assert_eq!(name.as_u64(), 6138663577826885632);
    }
}
