use chrono::{DateTime, Utc};
use prost_types::Timestamp;
use pulsevm_chainbase::{ChainbaseObject, SecondaryIndex, SecondaryKey};
use pulsevm_serialization::{Deserialize, Serialize, serialize};

use super::{Id, Transaction};

#[derive(Debug, Clone, Copy, Default)]
pub struct BlockTimestamp(DateTime<Utc>);
impl BlockTimestamp {
    pub fn new(timestamp: DateTime<Utc>) -> Self {
        BlockTimestamp(timestamp)
    }
}

impl Serialize for BlockTimestamp {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.0.timestamp().serialize(bytes);
        self.0.timestamp_subsec_nanos().serialize(bytes);
    }
}

impl Deserialize for BlockTimestamp {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let secs = i64::deserialize(data, pos)?;
        let nsecs = u32::deserialize(data, pos)?;
        let timestamp = DateTime::<Utc>::from_timestamp(secs, nsecs);
        if timestamp.is_none() {
            return Err(pulsevm_serialization::ReadError::ParseError);
        }
        Ok(BlockTimestamp(timestamp.unwrap()))
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

#[derive(Debug, Default, Clone)]
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
        let serialized = serialize(self);
        Id::from_sha256(&serialized)
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.serialize(&mut bytes);
        bytes
    }
}

impl<'a> ChainbaseObject<'a> for Block {
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

impl Serialize for Block {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.parent_id.serialize(bytes);
        self.timestamp.serialize(bytes);
        self.height.serialize(bytes);
        self.transactions.serialize(bytes);
    }
}

impl Deserialize for Block {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let parent_id = Id::deserialize(data, pos)?;
        let timestamp = BlockTimestamp::deserialize(data, pos)?;
        let height = u64::deserialize(data, pos)?;
        let transactions = Vec::<Transaction>::deserialize(data, pos)?;
        Ok(Block {
            parent_id,
            timestamp,
            height,
            transactions,
        })
    }
}

#[derive(Debug, Default)]
pub struct BlockByHeightIndex;

impl<'a> SecondaryIndex<'a, Block> for BlockByHeightIndex {
    type Key = u64;

    fn secondary_key(&self, object: &Block) -> Vec<u8> {
        object.height.to_be_bytes().to_vec()
    }

    fn secondary_key_as_bytes(key: Self::Key) -> Vec<u8> {
        key.to_be_bytes().to_vec()
    }

    fn index_name() -> &'static str {
        "block_by_height"
    }
}
