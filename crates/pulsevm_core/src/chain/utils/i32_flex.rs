// I really hate this code but due to EOS' fantastic code quality any idiot
// can send either a number or a string for certain numeric JSON parameter types

use core::fmt;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as DeError, Visitor},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct I32Flex(pub i32);

impl From<i32> for I32Flex {
    fn from(v: i32) -> Self {
        I32Flex(v)
    }
}
impl From<I32Flex> for i32 {
    fn from(v: I32Flex) -> Self {
        v.0
    }
}

impl Serialize for I32Flex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i32(self.0) // always serialize as a number
    }
}

impl<'de> Deserialize<'de> for I32Flex {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = I32Flex;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "an i32 as a number or a string")
            }

            fn visit_i64<E: DeError>(self, v: i64) -> Result<Self::Value, E> {
                i32::try_from(v)
                    .map(I32Flex)
                    .map_err(|_| E::custom("out of range for i32"))
            }
            fn visit_u64<E: DeError>(self, v: u64) -> Result<Self::Value, E> {
                i32::try_from(v)
                    .map(I32Flex)
                    .map_err(|_| E::custom("out of range for i32"))
            }
            fn visit_f64<E: DeError>(self, v: f64) -> Result<Self::Value, E> {
                if v.is_finite() && v.fract() == 0.0 {
                    let i = v as i64;
                    i32::try_from(i)
                        .map(I32Flex)
                        .map_err(|_| E::custom("out of range for i32"))
                } else {
                    Err(E::custom("expected an integer-valued number"))
                }
            }
            fn visit_str<E: DeError>(self, s: &str) -> Result<Self::Value, E> {
                s.trim()
                    .parse::<i32>()
                    .map(I32Flex)
                    .map_err(|_| E::custom("invalid i32 string"))
            }
            fn visit_string<E: DeError>(self, s: String) -> Result<Self::Value, E> {
                self.visit_str(&s)
            }
        }
        de.deserialize_any(V)
    }
}
