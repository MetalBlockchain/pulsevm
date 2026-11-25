use pulsevm_core::{
    block::BlockTimestamp,
    id::Id,
    name::Name,
    utils::Base64Bytes,
};
use pulsevm_crypto::Digest;
use serde::Serialize;

#[derive(Serialize, Clone, Default)]
pub struct GetInfoResponse {
    pub server_version: String,
    pub protocol_version: u32,
    pub supported_protocol_version: u32,
    pub protocol_upgrade_schedule_hash: String,
    pub next_protocol_upgrade: Option<ProtocolUpgradeInfo>,
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

#[derive(Serialize, Clone, Copy, Default)]
pub struct ProtocolUpgradeInfo {
    pub protocol_version: u32,
    pub activation_height: u32,
}

#[derive(Serialize, Clone)]
pub struct IssueTxResponse {
    #[serde(rename(serialize = "txID"))]
    pub tx_id: Id,
    pub status: TransactionStatus,
}

/// The latest transaction outcome known to this node. This is local telemetry,
/// not a consensus receipt or a promise that every node has observed the same
/// pending transaction.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Unknown,
    Admitted,
    Included,
    ExecutionFailed,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct GetTransactionStatusResponse {
    pub tx_id: Id,
    pub status: TransactionStatus,
    pub block_num: Option<u32>,
    pub error: Option<String>,
}

#[derive(Serialize, Clone, Default)]
pub struct GetProducersResponse {
    pub schedule_version: u32,
    pub active_producers: Vec<Name>,
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
