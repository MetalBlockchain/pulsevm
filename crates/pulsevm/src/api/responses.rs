use std::collections::HashMap;

use serde::Serialize;

use crate::chain::{Authority, BlockTimestamp, Id, Name};

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
pub struct GetAccountResponse {
    pub account_name: Name,

    pub privileged: bool,
    pub last_code_update: BlockTimestamp,
    pub created: BlockTimestamp,

    pub ram_quota: i64,
    pub net_weight: i64,
    pub cpu_weight: i64,

    pub ram_usage: i64,

    pub permissions: Vec<PermissionResponse>,
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
    pub total_cpu_weight: u64,
    pub total_net_weight: u64,
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
