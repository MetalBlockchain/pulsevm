use chrono::{DateTime, Utc};
use prost_types::Timestamp;
use pulsevm_chainbase::{ChainbaseObject, SecondaryIndex, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::{NumBytes, Read, Write};
use secp256k1::hashes::{Hash, sha256};

use crate::chain::BlockTimestamp;

use super::{Id, Transaction};

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
