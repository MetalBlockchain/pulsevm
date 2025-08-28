use std::fmt;

use pulsevm_serialization::{NumBytes, Read, ReadError, Write, WriteError};
use serde::{de::{self, Visitor}, Deserialize, Deserializer, Serialize};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionCompression {
    None = 0,
    Zlib = 1,
}

impl TransactionCompression {
    #[inline]
    fn from_u64(n: u64) -> Result<Self, &'static str> {
        match n {
            0 => Ok(TransactionCompression::None),
            1 => Ok(TransactionCompression::Zlib),
            _ => Err("unknown compression enum value"),
        }
    }

    #[inline]
    fn from_str(s: &str) -> Result<Self, &'static str> {
        if s.eq_ignore_ascii_case("none") {
            Ok(TransactionCompression::None)
        } else if s.eq_ignore_ascii_case("zlib") {
            Ok(TransactionCompression::Zlib)
        } else if let Ok(n) = s.parse::<u64>() {
            // Accept numeric strings like "0" / "1" too (handy for some clients)
            Self::from_u64(n)
        } else {
            Err("unknown compression type")
        }
    }
}

impl Write for TransactionCompression {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        match self {
            TransactionCompression::None => u8::write(&0, bytes, pos),
            TransactionCompression::Zlib => u8::write(&1, bytes, pos),
        }
    }
}

impl NumBytes for TransactionCompression {
    fn num_bytes(&self) -> usize {
        1
    }
}

impl Read for TransactionCompression {
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let value = u8::read(data, pos)?;
        match value {
            0 => Ok(TransactionCompression::None),
            1 => Ok(TransactionCompression::Zlib),
            _ => Err(ReadError::ParseError),
        }
    }
}

impl Serialize for TransactionCompression {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let status = match self {
            TransactionCompression::None => "none",
            TransactionCompression::Zlib => "zlib",
        };
        serializer.serialize_str(status)
    }
}

impl<'de> Deserialize<'de> for TransactionCompression {
    fn deserialize<D>(deserializer: D) -> Result<TransactionCompression, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CompressionVisitor;

        impl<'de> Visitor<'de> for CompressionVisitor {
            type Value = TransactionCompression;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(r#"a string "none"/"zlib" or an integer 0/1"#)
            }

            // Handle "none"/"zlib" or numeric strings "0"/"1"
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                TransactionCompression::from_str(v).map_err(E::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&v)
            }

            // Handle numeric JSON (0/1). Support both signed/unsigned just in case.
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                TransactionCompression::from_u64(v).map_err(E::custom)
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v < 0 {
                    return Err(E::custom("compression enum must be >= 0"));
                }
                TransactionCompression::from_u64(v as u64).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(CompressionVisitor)
    }
}
