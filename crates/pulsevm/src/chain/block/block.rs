use std::collections::VecDeque;

use pulsevm_chainbase::{ChainbaseObject, SecondaryIndex, SecondaryKey};
use pulsevm_crypto::Digest;
use pulsevm_proc_macros::{name, NumBytes, Read, Write};
use pulsevm_serialization::Write;
use secp256k1::hashes::{Hash, sha256};
use serde::{ser::SerializeStruct, Serialize};

use crate::chain::{BlockTimestamp, Id, Name, TransactionReceipt};

#[derive(Debug, Default, Clone, Read, Write, NumBytes)]
pub struct Block {
    pub parent_id: Id, // ID of the parent block
    pub timestamp: BlockTimestamp, // Timestamp of the block
    pub height: u64,               // Height of the block in the chain
    pub transaction_receipts: VecDeque<TransactionReceipt>, // Transactions included in this block
    pub transaction_mroot: Digest, // Merkle root of the transactions in this block
}

impl Block {
    pub fn new(
        parent_id: Id,
        timestamp: BlockTimestamp,
        height: u64,
        transaction_receipts: VecDeque<TransactionReceipt>,
        transaction_mroot: Digest,
    ) -> Self {
        Block {
            parent_id,
            timestamp,
            height,
            transaction_receipts,
            transaction_mroot,
        }
    }

    pub fn id(&self) -> Id {
        let serialized = self.pack().unwrap();
        let hash = sha256::Hash::hash(&serialized);
        Id::from_sha256(&hash)
    }

    pub fn bytes(&self) -> Vec<u8> {
        let bytes = self.pack().unwrap();
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

impl Serialize for Block {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Block", 8)?;
        state.serialize_field("timestamp", &self.timestamp)?;
        state.serialize_field("producer", &Name::from(name!("pulse")))?;
        state.serialize_field("confirmed", &0u32)?;
        state.serialize_field("previous", &self.parent_id)?;
        state.serialize_field("transaction_mroot", &self.transaction_mroot)?;
        state.serialize_field("transactions", &self.transaction_receipts)?;
        state.serialize_field("id", &self.id())?;
        state.serialize_field("block_num", &self.height)?;
        state.end()
    }
}