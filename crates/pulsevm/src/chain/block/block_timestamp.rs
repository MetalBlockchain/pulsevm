use std::fmt;

use prost_types::Timestamp;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_time::{TimePoint, TimePointSec, milliseconds};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use time::{Duration, OffsetDateTime, PrimitiveDateTime, macros::format_description};

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Read, Write, NumBytes,
)]
pub struct BlockTimestamp {
    pub slot: u32,
}

impl BlockTimestamp {
    pub const BLOCK_INTERVAL_MS: i32 = 500;
    pub const BLOCK_TIMESTAMP_EPOCH_MS: i64 = 946_684_800_000; // 2000-01-01T00:00:00Z

    #[inline]
    pub const fn new(slot: u32) -> Self {
        Self { slot }
    }

    #[inline]
    pub const fn maximum() -> Self {
        Self { slot: 0xFFFF }
    }
    #[inline]
    pub const fn min() -> Self {
        Self { slot: 0 }
    }

    #[inline]
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let now_ms: i128 =
            (dur.as_secs() as i128) * 1_000 + (dur.subsec_nanos() as i128) / 1_000_000;

        let epoch_ms = Self::BLOCK_TIMESTAMP_EPOCH_MS as i128; // 2000-01-01T00:00:00Z
        let interval = Self::BLOCK_INTERVAL_MS as i128; // 500

        // Truncate to the lower 500ms boundary; clamp before-epoch to 0
        let delta = (now_ms - epoch_ms).max(0);
        let slot_i128 = delta / interval;

        // Saturate into u32
        let slot = if slot_i128 > u32::MAX as i128 {
            u32::MAX
        } else {
            slot_i128 as u32
        };

        BlockTimestamp { slot }
    }

    #[inline]
    pub fn next(self) -> Self {
        assert!(u32::MAX - self.slot >= 1, "block timestamp overflow");
        Self {
            slot: self.slot + 1,
        }
    }

    #[inline]
    pub fn to_time_point(self) -> TimePoint {
        self.into()
    }
}

impl From<BlockTimestamp> for TimePoint {
    #[inline]
    fn from(bt: BlockTimestamp) -> Self {
        let msec = (bt.slot as i64) * (BlockTimestamp::BLOCK_INTERVAL_MS as i64)
            + BlockTimestamp::BLOCK_TIMESTAMP_EPOCH_MS;
        TimePoint::new(milliseconds(msec))
    }
}

impl From<TimePoint> for BlockTimestamp {
    #[inline]
    fn from(t: TimePoint) -> Self {
        let micro = t.time_since_epoch().count();
        let msec = micro / 1_000;
        let slot = ((msec - BlockTimestamp::BLOCK_TIMESTAMP_EPOCH_MS)
            / (BlockTimestamp::BLOCK_INTERVAL_MS as i64)) as u32;
        BlockTimestamp { slot }
    }
}

impl From<TimePointSec> for BlockTimestamp {
    #[inline]
    fn from(t: TimePointSec) -> Self {
        let sec = t.sec_since_epoch() as i64;
        let slot = ((sec * 1_000 - BlockTimestamp::BLOCK_TIMESTAMP_EPOCH_MS)
            / (BlockTimestamp::BLOCK_INTERVAL_MS as i64)) as u32;
        BlockTimestamp { slot }
    }
}

impl From<BlockTimestamp> for Timestamp {
    fn from(bt: BlockTimestamp) -> Self {
        // total milliseconds since Unix epoch (1970-01-01T00:00:00Z)
        let total_ms = (bt.slot as i128)
            * (BlockTimestamp::BLOCK_INTERVAL_MS as i128)     // 500ms per slot
            + (BlockTimestamp::BLOCK_TIMESTAMP_EPOCH_MS as i128); // epoch = 2000-01-01

        let seconds = (total_ms / 1_000) as i64;
        let nanos = 0;

        Timestamp { seconds, nanos }
    }
}

impl Serialize for BlockTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // total ms since Unix epoch
        let total_ms =
            (self.slot as i64) * (Self::BLOCK_INTERVAL_MS as i64) + Self::BLOCK_TIMESTAMP_EPOCH_MS;

        let secs = total_ms.div_euclid(1000);
        let rem_ms = (total_ms.rem_euclid(1000)) as i64;

        let mut dt =
            OffsetDateTime::from_unix_timestamp(secs).expect("valid timestamp for BlockTimestamp");
        dt += Duration::milliseconds(rem_ms);

        // EOS uses "YYYY-MM-DDTHH:MM:SS.sss" (no 'Z')
        const FMT: &[time::format_description::FormatItem<'_>] = format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]"
        );

        let s = dt.format(FMT).expect("formatting never fails");
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for BlockTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BtVisitor;

        impl<'de> Visitor<'de> for BtVisitor {
            type Value = BlockTimestamp;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(r#"an EOS block timestamp like "YYYY-MM-DDTHH:MM:SS.sss" (optionally with a trailing 'Z')"#)
            }

            fn visit_str<E>(self, mut v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Allow optional trailing Z
                if let Some(stripped) = v.strip_suffix('Z') {
                    v = stripped;
                }

                // Try with milliseconds first, then without (assume .000)
                const FMT_MS: &[time::format_description::FormatItem<'_>] = format_description!(
                    "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]"
                );
                const FMT_SEC: &[time::format_description::FormatItem<'_>] =
                    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");

                let pdt = PrimitiveDateTime::parse(v, FMT_MS)
                    .or_else(|_| PrimitiveDateTime::parse(v, FMT_SEC))
                    .map_err(|e| E::custom(format!("invalid block timestamp: {e}")))?;

                let odt = pdt.assume_utc();
                let total_ms = odt
                    .unix_timestamp()
                    .saturating_mul(1000)
                    .saturating_add((odt.nanosecond() / 1_000_000) as i64);

                // Convert to EOS slot (500 ms from 2000-01-01T00:00:00Z)
                let delta = total_ms - BlockTimestamp::BLOCK_TIMESTAMP_EPOCH_MS;
                if delta < 0 {
                    return Err(E::custom(
                        "timestamp before EOS block timestamp epoch (2000-01-01T00:00:00Z)",
                    ));
                }
                if delta % (BlockTimestamp::BLOCK_INTERVAL_MS as i64) != 0 {
                    return Err(E::custom("timestamp not aligned to 500ms boundary"));
                }
                let slot = (delta / (BlockTimestamp::BLOCK_INTERVAL_MS as i64)) as u32;

                Ok(BlockTimestamp { slot })
            }
        }

        deserializer.deserialize_str(BtVisitor)
    }
}
