use core::{fmt, str};
use std::str::FromStr;

use pulsevm_serialization::{Deserialize, Serialize};

pub const NAME_CHARS: [u8; 32] = *b".12345abcdefghijklmnopqrstuvwxyz";
pub const NAME_MAX_LEN: usize = 13;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Name(u64);

impl Name {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
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
    type Err = ParseNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = name_from_bytes(s.bytes())?;
        Ok(name.into())
    }
}

impl fmt::Display for Name {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = name_to_bytes(self.0);
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

impl Serialize for Name {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.0.serialize(bytes);
    }
}

impl Deserialize for Name {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let value = u64::deserialize(data, pos)?;
        Ok(Name(value))
    }
}

#[derive(Debug)]
pub enum ParseNameError {
    /// The name contains a disallowed character.
    BadChar(u8),
    /// The name is over the maximum allowed length.
    TooLong,
}

pub fn name_from_bytes<I>(mut iter: I) -> Result<u64, ParseNameError>
where
    I: Iterator<Item = u8>,
{
    let mut value = 0_u64;
    let mut len = 0_u64;

    // Loop through up to 12 characters
    while let Some(c) = iter.next() {
        let v = char_to_value(c).ok_or_else(|| ParseNameError::BadChar(c))?;
        value <<= 5;
        value |= u64::from(v);
        len += 1;

        if len == 12 {
            break;
        }
    }

    if len == 0 {
        return Ok(0);
    }

    value <<= 4 + 5 * (12 - len);

    // Check if we have a 13th character
    if let Some(c) = iter.next() {
        let v = char_to_value(c).ok_or_else(|| ParseNameError::BadChar(c))?;

        // The 13th character can only be 4 bits, it has to be between letters
        // 'a' to 'j'
        if v > 0x0F {
            return Err(ParseNameError::BadChar(c));
        }

        value |= u64::from(v);

        // Check if we have more than 13 characters
        if iter.next().is_some() {
            return Err(ParseNameError::TooLong);
        }
    }

    Ok(value)
}

fn char_to_value(c: u8) -> Option<u8> {
    if c == b'.' {
        Some(0)
    } else if c >= b'1' && c <= b'5' {
        Some(c - b'1' + 1)
    } else if c >= b'a' && c <= b'z' {
        Some(c - b'a' + 6)
    } else {
        None
    }
}

#[inline]
#[must_use]
pub fn name_to_bytes(value: u64) -> [u8; NAME_MAX_LEN] {
    let mut chars = [b'.'; NAME_MAX_LEN];
    if value == 0 {
        return chars;
    }

    let mask = 0xF800_0000_0000_0000;
    let mut v = value;
    for (i, c) in chars.iter_mut().enumerate() {
        let index = (v & mask) >> (if i == 12 { 60 } else { 59 });
        let index = usize::try_from(index).unwrap_or_default();
        if let Some(v) = NAME_CHARS.get(index) {
            *c = *v;
        }
        v <<= 5;
    }
    chars
}