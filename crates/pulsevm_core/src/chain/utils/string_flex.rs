// Companion to I32Flex: EOS clients send lower_bound/upper_bound style
// parameters as either a string or a bare JSON number, so accept both and
// normalize to a string.

use core::fmt;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as DeError, Visitor},
};

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct StringFlex(pub String);

impl From<String> for StringFlex {
    fn from(v: String) -> Self {
        StringFlex(v)
    }
}
impl From<&str> for StringFlex {
    fn from(v: &str) -> Self {
        StringFlex(v.to_string())
    }
}
impl From<StringFlex> for String {
    fn from(v: StringFlex) -> Self {
        v.0
    }
}
impl fmt::Display for StringFlex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for StringFlex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0) // always serialize as a string
    }
}

impl<'de> Deserialize<'de> for StringFlex {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StringFlex;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a string or a number")
            }

            fn visit_i64<E: DeError>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StringFlex(v.to_string()))
            }
            fn visit_u64<E: DeError>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StringFlex(v.to_string()))
            }
            fn visit_u128<E: DeError>(self, v: u128) -> Result<Self::Value, E> {
                Ok(StringFlex(v.to_string()))
            }
            fn visit_i128<E: DeError>(self, v: i128) -> Result<Self::Value, E> {
                Ok(StringFlex(v.to_string()))
            }
            fn visit_f64<E: DeError>(self, v: f64) -> Result<Self::Value, E> {
                // Rust formats integer-valued floats without a trailing ".0",
                // so 100.0 becomes "100" and 1.5 stays "1.5".
                Ok(StringFlex(v.to_string()))
            }
            fn visit_str<E: DeError>(self, s: &str) -> Result<Self::Value, E> {
                Ok(StringFlex(s.to_string()))
            }
            fn visit_string<E: DeError>(self, s: String) -> Result<Self::Value, E> {
                Ok(StringFlex(s))
            }
        }
        de.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_strings_and_numbers() {
        let s: StringFlex = serde_json::from_str("\"alice\"").unwrap();
        assert_eq!(s.0, "alice");
        let n: StringFlex = serde_json::from_str("100").unwrap();
        assert_eq!(n.0, "100");
        let neg: StringFlex = serde_json::from_str("-5").unwrap();
        assert_eq!(neg.0, "-5");
        let big: StringFlex = serde_json::from_str("18446744073709551615").unwrap();
        assert_eq!(big.0, "18446744073709551615");
        let f: StringFlex = serde_json::from_str("1.5").unwrap();
        assert_eq!(f.0, "1.5");
    }

    #[test]
    fn serializes_as_string() {
        let v = StringFlex("100".to_string());
        assert_eq!(serde_json::to_string(&v).unwrap(), "\"100\"");
    }
}
