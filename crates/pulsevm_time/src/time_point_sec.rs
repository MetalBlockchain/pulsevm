use std::{fmt, str::FromStr};

use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use time::{OffsetDateTime, PrimitiveDateTime, macros::format_description};

use crate::{TimePoint, microseconds::seconds};

// Base EOS format (no 'Z')
const EOS_FMT_NOZ: &[time::format_description::FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
// Exact output format (with trailing 'Z')
const EOS_FMT_Z: &[time::format_description::FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct TimePointSec {
    utc_seconds: u32,
}

impl TimePointSec {
    #[inline]
    pub const fn new(seconds: u32) -> Self {
        Self {
            utc_seconds: seconds,
        }
    }

    #[inline]
    pub const fn maximum() -> Self {
        Self {
            utc_seconds: u32::MAX,
        }
    }

    #[inline]
    pub const fn min() -> Self {
        Self { utc_seconds: 0 }
    }

    #[inline]
    pub const fn sec_since_epoch(self) -> u32 {
        self.utc_seconds
    }

    /// Exact EOS-style string: "YYYY-MM-DDTHH:MM:SSZ"
    pub fn to_eos_string(&self) -> String {
        let dt = OffsetDateTime::from_unix_timestamp(self.utc_seconds as i64)
            .expect("valid unix timestamp");
        dt.format(EOS_FMT_Z).expect("formatting never fails")
    }
}

impl fmt::Display for TimePointSec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // IMPORTANT: don't call trait ToString::to_string(&self)
        f.write_str(&self.to_eos_string())
    }
}

impl FromStr for TimePointSec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Accept both "...SS" and "...SSZ"
        let s_noz = s.strip_suffix('Z').unwrap_or(s);
        let pdt = PrimitiveDateTime::parse(s_noz, EOS_FMT_NOZ)
            .map_err(|e| format!("invalid EOS time_point_sec: {e}"))?;
        let ts = pdt.assume_utc().unix_timestamp();
        if ts < 0 || ts > u32::MAX as i64 {
            return Err("timestamp out of range for u32".into());
        }
        Ok(TimePointSec {
            utc_seconds: ts as u32,
        })
    }
}

impl From<TimePoint> for TimePointSec {
    #[inline]
    fn from(t: TimePoint) -> Self {
        // Truncate microseconds to whole seconds
        let secs = (t.elapsed.count() / 1_000_000) as i64;
        Self {
            utc_seconds: secs as u32,
        } // C++ semantics: wrap on cast if negative/large
    }
}

impl From<TimePointSec> for TimePoint {
    #[inline]
    fn from(t: TimePointSec) -> Self {
        TimePoint::new(seconds(t.utc_seconds as i64))
    }
}

impl Serialize for TimePointSec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Write the final string directly to avoid recursion
        serializer.serialize_str(&self.to_eos_string())
    }
}

impl<'de> Deserialize<'de> for TimePointSec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TPVisitor;
        impl<'de> Visitor<'de> for TPVisitor {
            type Value = TimePointSec;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(r#"an EOS time string "YYYY-MM-DDTHH:MM:SSZ""#)
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                v.parse().map_err(E::custom)
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&v)
            }
        }
        deserializer.deserialize_str(TPVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_point_sec_serialize() {
        let time_point = TimePointSec::new(0);
        let serialized = serde_json::to_string(&time_point).unwrap();
        assert_eq!(serialized, "\"1970-01-01T00:00:00Z\"");
    }

    #[test]
    fn test_time_point_sec_deserialize() {
        let serialized = "\"1970-01-01T00:00:00Z\"";
        let time_point: TimePointSec = serde_json::from_str(serialized).unwrap();
        assert_eq!(time_point.sec_since_epoch(), 0);
    }
}
