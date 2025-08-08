use std::fmt;

use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct TimePointSec {
    utc_seconds: u32,
}

impl TimePointSec {
    #[inline]
    #[must_use]
    pub const fn new(utc_seconds: u32) -> Self {
        Self { utc_seconds }
    }

    #[inline]
    #[must_use]
    pub const fn as_u32(&self) -> u32 {
        self.utc_seconds
    }
}

impl Serialize for TimePointSec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let time = Utc.timestamp_opt(self.as_u32() as i64, 0);

        match time {
            chrono::LocalResult::Single(datetime) => {
                serializer.serialize_str(&datetime.to_rfc3339_opts(SecondsFormat::Secs, true))
            }
            chrono::LocalResult::None => Err(serde::ser::Error::custom("invalid timestamp")),
            chrono::LocalResult::Ambiguous(_, _) => {
                Err(serde::ser::Error::custom("ambiguous timestamp"))
            }
        }
    }
}

impl<'de> Deserialize<'de> for TimePointSec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TimePointSecVisitor;

        impl<'de> serde::de::Visitor<'de> for TimePointSecVisitor {
            type Value = TimePointSec;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an RFC3339-formatted timestamp string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let parsed: DateTime<Utc> = DateTime::parse_from_rfc3339(v)
                    .map_err(|e| E::custom(format!("failed to parse RFC3339: {e}")))?
                    .with_timezone(&Utc);

                let seconds = parsed.timestamp();
                if seconds < 0 || seconds > u32::MAX as i64 {
                    return Err(E::custom("timestamp out of range for TimePointSec"));
                }

                Ok(TimePointSec::new(seconds as u32))
            }
        }

        deserializer.deserialize_str(TimePointSecVisitor)
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
        assert_eq!(time_point.as_u32(), 0);
    }
}
