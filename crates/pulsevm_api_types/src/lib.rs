use pulsevm_core::id::Id;
use pulsevm_time::TimePointSec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfoResponse {
    pub server_version: String,
    pub server_time: String,
    pub chain_id: String,
    pub head_block_num: u32,
    pub last_irreversible_block_num: u32,
    pub last_irreversible_block_id: String,
    pub head_block_id: String,
    pub head_block_time: String,
    pub head_block_producer: String,
    pub virtual_block_cpu_limit: u64,
    pub virtual_block_net_limit: u64,
    pub block_cpu_limit: u64,
    pub block_net_limit: u64,
    pub server_version_string: String,
    pub fork_db_head_block_num: u32,
    pub fork_db_head_block_id: String,
    pub server_full_version_string: String,
    pub total_cpu_weight: u64,
    pub total_net_weight: u64,
    pub earliest_available_block_num: u32,
    pub last_irreversible_block_time: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IssueTxResponse {
    #[serde(rename(serialize = "txID", deserialize = "txID"))]
    pub tx_id: Id,
}
