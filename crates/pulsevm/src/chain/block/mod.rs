use chrono::{DateTime, Utc};
use prost_types::Timestamp;
use pulsevm_chainbase::{ChainbaseObject, SecondaryIndex, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::{NumBytes, Read, Write};
use secp256k1::hashes::{Hash, sha256};

use super::{Id, Transaction};

#[derive(Debug, Clone, Copy, Default)]
pub struct BlockTimestamp(DateTime<Utc>);
impl BlockTimestamp {
    pub fn new(timestamp: DateTime<Utc>) -> Self {
        BlockTimestamp(timestamp)
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
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), pulsevm_serialization::WriteError> {
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

#[derive(Debug, Default, Clone, Read, Write, NumBytes)]
pub struct Block {
    pub parent_id: Id,                  // ID of the parent block
    pub timestamp: BlockTimestamp,      // Timestamp of the block
    pub height: u64,                    // Height of the block in the chain
    pub transactions: Vec<Transaction>, // Transactions included in this block
}

impl Block {
    pub fn new(
        parent_id: Id,
        timestamp: BlockTimestamp,
        height: u64,
        transactions: Vec<Transaction>,
    ) -> Self {
        Block {
            parent_id,
            timestamp,
            height,
            transactions,
        }
    }

    pub fn id(&self) -> Id {
        let serialized = self.pack().unwrap();
        let hash = sha256::Hash::hash(&serialized);
        Id::from_sha256(&hash)
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = self.pack().unwrap();
        bytes
    }
}

impl ChainbaseObject for Block {
    type PrimaryKey = Id;

    fn primary_key(&self) -> Vec<u8> {
        self.id().as_bytes().to_vec()
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.0.to_vec()
    }

    fn table_name() -> &'static str {
        "block"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![SecondaryKey {
            key: BlockByHeightIndex::secondary_key_as_bytes(self.height),
            index_name: BlockByHeightIndex::index_name(),
        }]
    }
}

#[derive(Debug, Default)]
pub struct BlockByHeightIndex;

impl SecondaryIndex<Block> for BlockByHeightIndex {
    type Key = u64;
    type Object = Block;

    fn secondary_key(object: &Block) -> Vec<u8> {
        object.height.to_be_bytes().to_vec()
    }

    fn secondary_key_as_bytes(key: Self::Key) -> Vec<u8> {
        key.to_be_bytes().to_vec()
    }

    fn index_name() -> &'static str {
        "block_by_height"
    }
}
