// Same story as I32Flex: Antelope clients (eosjs, proton-js, the explorer)
// send bound/key parameters as either a string or a bare JSON number —
// get_table_rows on Leap accepts both. Deserialize either into a String.

use core::fmt;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as DeError, Visitor},
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StringFlex(pub String);

impl From<String> for StringFlex {
    fn from(v: String) -> Self {
        StringFlex(v)
    }
}
impl From<StringFlex> for String {
    fn from(v: StringFlex) -> Self {
        v.0
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
            fn visit_f64<E: DeError>(self, v: f64) -> Result<Self::Value, E> {
                if v.is_finite() && v.fract() == 0.0 {
                    // bounds are table keys — integer-valued numbers only
                    Ok(StringFlex(format!("{}", v as i64)))
                } else {
                    Err(E::custom("expected an integer-valued number or a string"))
                }
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
