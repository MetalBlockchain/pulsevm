use pulsevm_core::{block::BlockTimestamp, id::Id, name::Name, utils::Base64Bytes};
use pulsevm_crypto::Digest;
use serde::Serialize;

#[derive(Serialize, Clone, Default)]
pub struct GetInfoResponse {
    pub server_version: String,
    pub server_time: BlockTimestamp,
    pub chain_id: Id,
    pub head_block_num: u32,
    pub last_irreversible_block_num: u32,
    pub last_irreversible_block_id: Id,
    pub head_block_id: Id,
    pub head_block_time: BlockTimestamp,
    pub head_block_producer: Name,
    pub virtual_block_cpu_limit: u64,
    pub virtual_block_net_limit: u64,
    pub block_cpu_limit: u64,
    pub block_net_limit: u64,
    pub server_version_string: String,
    pub fork_db_head_block_num: u32,
    pub fork_db_head_block_id: Id,
    pub server_full_version_string: String,
    pub total_cpu_weight: u64,
    pub total_net_weight: u64,
    pub earliest_available_block_num: u32,
    pub last_irreversible_block_time: BlockTimestamp,
}

#[derive(Serialize, Clone)]
pub struct IssueTxResponse {
    #[serde(rename(serialize = "txID"))]
    pub tx_id: Id,
}

#[derive(Serialize, Clone, Default)]
pub struct GetCodeHashResponse {
    pub account_name: Name,
    pub code_hash: Id,
}

#[derive(Serialize, Clone, Default)]
pub struct GetRawABIResponse {
    pub account_name: Name,
    pub code_hash: Id,
    pub abi_hash: Digest,
    pub abi: Base64Bytes,
}
