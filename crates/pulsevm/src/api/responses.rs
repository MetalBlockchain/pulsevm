use pulsevm_crypto::Digest;
use serde::Serialize;

use crate::chain::{AccountResourceLimit, Asset, Authority, Base64Bytes, BlockTimestamp, Id, Name};

#[derive(Serialize, Clone, Default)]
pub struct PermissionResponse {
    perm_name: Name,
    parent: Name,
    required_auth: Authority,
}

impl PermissionResponse {
    pub fn new(perm_name: Name, parent: Name, required_auth: Authority) -> Self {
        PermissionResponse {
            perm_name,
            parent,
            required_auth,
        }
    }
}

#[derive(Serialize, Clone, Default)]
pub struct AccountTotalResources {
    owner: Name,
    net_weight: Asset,
    cpu_weight: Asset,
    ram_bytes: u32,
}

#[derive(Serialize, Clone, Default)]
pub struct AccountVoterInfo {
    pub owner: Name,
    pub proxy: Name,
    pub producers: Vec<Name>,
    pub staked: u32,
    pub last_vote_weight: String,
    pub proxied_vote_weight: String,
    pub is_proxy: u8,
    pub flags1: u8,
    pub reserved2: u8,
    pub reserved3: u8,
}

#[derive(Serialize, Clone, Default)]
pub struct GetAccountResponse {
    pub account_name: Name,
    pub head_block_num: u32,
    pub head_block_time: BlockTimestamp,
    pub privileged: bool,
    pub last_code_update: BlockTimestamp,
    pub created: BlockTimestamp,
    pub ram_quota: i64,
    pub net_weight: i64,
    pub cpu_weight: i64,
    pub net_limit: AccountResourceLimit,
    pub cpu_limit: AccountResourceLimit,
    pub ram_usage: u64,
    pub permissions: Vec<PermissionResponse>,
    pub total_resources: AccountTotalResources,
    pub voter_info: AccountVoterInfo,
}

#[derive(Serialize, Clone, Default)]
pub struct GetInfoResponse {
    pub server_version: String,
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
pub struct GetTableRowsResponse {
    pub rows: Vec<serde_json::Value>,
    pub more: bool,
    pub next_key: String,
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
