use core::fmt;
use std::{
    ops::{Add, AddAssign, Sub, SubAssign},
    str::FromStr,
};

use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use time::{OffsetDateTime, PrimitiveDateTime, macros::format_description};

use crate::Microseconds;

const EOS_FMT_MILLIS_NOZ: &[time::format_description::FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]");

const EOS_FMT_MILLIS_Z: &[time::format_description::FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

const EOS_FMT_SECS_NOZ: &[time::format_description::FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Read, Write, NumBytes,
)]
pub struct TimePoint {
    pub elapsed: Microseconds, // microseconds since UNIX epoch
}

impl TimePoint {
    #[inline]
    pub const fn new(elapsed: Microseconds) -> Self {
        Self { elapsed }
    }

    #[inline]
    pub const fn time_since_epoch(&self) -> Microseconds {
        self.elapsed
    }

    #[inline]
    pub const fn sec_since_epoch(&self) -> u32 {
        (self.elapsed.count() / 1_000_000) as u32
    }

    #[inline]
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let micros_u128 = dur.as_micros();

        // Clamp to i64 if your Microseconds uses i64
        let micros_i64 = if micros_u128 > i64::MAX as u128 {
            i64::MAX
        } else {
            micros_u128 as i64
        };

        TimePoint::new(Microseconds::new(micros_i64))
    }

    /// Exact EOS-style string: "YYYY-MM-DDTHH:MM:SSZ"
    pub fn to_eos_string(&self) -> String {
        let dt = OffsetDateTime::from_unix_timestamp(self.sec_since_epoch() as i64)
            .expect("valid unix timestamp");
        dt.format(EOS_FMT_MILLIS_Z).expect("formatting never fails")
    }
}

/* ---- arithmetic/relations (match C++ semantics) ---- */

impl Add<Microseconds> for TimePoint {
    type Output = TimePoint;
    #[inline]
    fn add(self, rhs: Microseconds) -> Self::Output {
        TimePoint::new(self.elapsed + rhs)
    }
}

impl Add for TimePoint {
    type Output = TimePoint;
    #[inline]
    fn add(self, rhs: TimePoint) -> Self::Output {
        TimePoint::new(self.elapsed + rhs.elapsed)
    }
}

impl Sub<Microseconds> for TimePoint {
    type Output = TimePoint;
    #[inline]
    fn sub(self, rhs: Microseconds) -> Self::Output {
        TimePoint::new(self.elapsed - rhs)
    }
}

impl Sub for TimePoint {
    type Output = Microseconds;
    #[inline]
    fn sub(self, rhs: TimePoint) -> Self::Output {
        self.elapsed - rhs.elapsed
    }
}

impl AddAssign<Microseconds> for TimePoint {
    #[inline]
    fn add_assign(&mut self, rhs: Microseconds) {
        self.elapsed += rhs;
    }
}

impl SubAssign<Microseconds> for TimePoint {
    #[inline]
    fn sub_assign(&mut self, rhs: Microseconds) {
        self.elapsed -= rhs;
    }
}

impl fmt::Display for TimePoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // IMPORTANT: don't call trait ToString::to_string(&self)
        f.write_str(&self.to_eos_string())
    }
}

impl FromStr for TimePoint {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Accept both with and without a trailing 'Z'
        let s_noz = s.trim_end().strip_suffix('Z').unwrap_or(s.trim_end());

        // Try with milliseconds first; fall back to seconds-only
        let pdt = PrimitiveDateTime::parse(s_noz, EOS_FMT_MILLIS_NOZ)
            .or_else(|_| PrimitiveDateTime::parse(s_noz, EOS_FMT_SECS_NOZ))
            .map_err(|e| format!("invalid EOS time_point: {e}"))?;

        let odt: OffsetDateTime = pdt.assume_utc();

        // Combine into *microseconds* since epoch (EOS time_point is microsecond-based)
        let secs = odt.unix_timestamp(); // i64 seconds
        let micros_of_sec = odt.time().microsecond() as i64;
        let total_us = secs
            .checked_mul(1_000_000)
            .and_then(|v| v.checked_add(micros_of_sec))
            .ok_or_else(|| "overflow while computing microseconds since epoch".to_string())?;

        Ok(TimePoint {
            elapsed: Microseconds::new(total_us),
        })
    }
}

impl Serialize for TimePoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Write the final string directly to avoid recursion
        serializer.serialize_str(&self.to_eos_string())
    }
}

impl<'de> Deserialize<'de> for TimePoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TPVisitor;
        impl<'de> Visitor<'de> for TPVisitor {
            type Value = TimePoint;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(r#"an EOS time string "YYYY-MM-DDTHH:MM:SS.sssZ""#)
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
    fn test_time_point_serialize() {
        let time_point = TimePoint::new(Microseconds::new(0));
        let serialized = serde_json::to_string(&time_point).unwrap();
        assert_eq!(serialized, "\"1970-01-01T00:00:00.000Z\"");
    }

    #[test]
    fn test_time_point_deserialize() {
        let serialized = "\"1970-01-01T00:00:00.000Z\"";
        let time_point: TimePoint = serde_json::from_str(serialized).unwrap();
        assert_eq!(time_point.sec_since_epoch(), 0);
    }
}
