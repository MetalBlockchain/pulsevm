use chrono::{DateTime, TimeZone, Utc};
use prost_types::Timestamp;
use pulsevm_serialization::{NumBytes, Read, Write};
use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct BlockTimestamp(DateTime<Utc>);

impl BlockTimestamp {
    pub fn new(timestamp: DateTime<Utc>) -> Self {
        BlockTimestamp(timestamp)
    }

    pub fn min() -> Self {
        BlockTimestamp(Utc.timestamp_opt(0, 0).unwrap())
    }

    pub fn now() -> Self {
        BlockTimestamp(Utc::now())
    }
}

impl Read for BlockTimestamp {
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let secs = i64::read(data, pos)?;
        let nsecs = u32::read(data, pos)?;
        let timestamp = DateTime::<Utc>::from_timestamp(secs, nsecs);
        if timestamp.is_none() {
            return Err(pulsevm_serialization::ReadError::ParseError);
        }
        Ok(BlockTimestamp(timestamp.unwrap()))
    }
}

impl NumBytes for BlockTimestamp {
    fn num_bytes(&self) -> usize {
        8 + 4 // 8 bytes for seconds, 4 bytes for nanoseconds
    }
}

impl Write for BlockTimestamp {
    fn write(
        &self,
        bytes: &mut [u8],
        pos: &mut usize,
    ) -> Result<(), pulsevm_serialization::WriteError> {
        if *pos + self.num_bytes() > bytes.len() {
            return Err(pulsevm_serialization::WriteError::NotEnoughSpace);
        }
        let seconds = self.0.timestamp();
        let nanos = self.0.timestamp_subsec_nanos();
        seconds.write(bytes, pos)?;
        nanos.write(bytes, pos)?;
        Ok(())
    }
}

impl Into<Timestamp> for BlockTimestamp {
    fn into(self) -> Timestamp {
        Timestamp {
            seconds: self.0.timestamp(),
            nanos: self.0.timestamp_subsec_nanos() as i32,
        }
    }
}

impl From<DateTime<Utc>> for BlockTimestamp {
    fn from(timestamp: DateTime<Utc>) -> Self {
        BlockTimestamp(timestamp)
    }
}

impl Serialize for BlockTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Round/truncate to 500ms increments
        let millis = (self.0.timestamp_subsec_millis() / 500) * 500;

        let s = format!(
            "{}.{:03}",
            self.0.format("%Y-%m-%dT%H:%M:%S"),
            millis
        );

        serializer.serialize_str(&s)
    }
}
