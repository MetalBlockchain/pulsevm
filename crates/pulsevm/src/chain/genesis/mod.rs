use core::str;
use pulsevm_proc_macros::NumBytes;
use pulsevm_proc_macros::Read;
use pulsevm_proc_macros::Write;
use pulsevm_serialization::Write;
use secp256k1::hashes::Hash;
use secp256k1::hashes::sha256;
use serde::{Deserialize, Serialize};

use crate::chain::Id;
use crate::chain::block::BlockTimestamp;
use crate::chain::error::ChainError;

use super::PublicKey;

#[derive(
    Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, Default, Read, Write, NumBytes,
)]
pub struct ChainConfig {
    pub max_block_net_usage: u64,
    pub target_block_net_usage_pct: u32,
    pub max_transaction_net_usage: u32,
    pub base_per_transaction_net_usage: u32,
    pub net_usage_leeway: u32,
    pub context_free_discount_net_usage_num: u32,
    pub context_free_discount_net_usage_den: u32,

    pub max_block_cpu_usage: u32,
    pub target_block_cpu_usage_pct: u32,
    pub max_transaction_cpu_usage: u32,
    pub min_transaction_cpu_usage: u32,

    pub max_inline_action_size: u32,
    pub max_inline_action_depth: u16,
    pub max_authority_depth: u16,
    pub max_action_return_value_size: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Read, Write, NumBytes)]
pub struct Genesis {
    initial_timestamp: BlockTimestamp,
    initial_key: PublicKey,
    initial_configuration: ChainConfig,
}

impl Genesis {
    pub fn parse(bytes: &Vec<u8>) -> Result<Self, ChainError> {
        let genesis = str::from_utf8(bytes)
            .map_err(|_| ChainError::GenesisError("invalid UTF-8".to_string()))?;
        let genesis: Genesis = serde_json::from_str(genesis)
            .map_err(|e| ChainError::GenesisError(format!("{}", e)))?;
        Ok(genesis)
    }

    pub fn validate(&self) -> Result<Self, ChainError> {
        Ok(self.clone())
    }

    pub fn compute_chain_id(&self) -> Result<Id, ChainError> {
        let packed = self
            .pack()
            .map_err(|e| ChainError::GenesisError(format!("failed to pack genesis: {}", e)))?;
        let hash = sha256::Hash::hash(&packed);
        let chain_id = Id::from_sha256(&hash);
        Ok(chain_id)
    }

    pub fn initial_timestamp(&self) -> &BlockTimestamp {
        &self.initial_timestamp
    }

    pub fn initial_key(&self) -> &PublicKey {
        &self.initial_key
    }

    pub fn initial_configuration(&self) -> &ChainConfig {
        &self.initial_configuration
    }
}
