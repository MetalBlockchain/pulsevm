use std::collections::HashMap;

use serde::Serialize;

use crate::chain::{Authority, BlockTimestamp, Name};

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

#[derive(Serialize, Clone)]
pub struct IssueTxResponse {
    #[serde(rename(serialize = "txID"))]
    pub tx_id: String,
}

#[derive(Serialize, Clone, Default)]
pub struct GetTableRowsResponse {
    pub rows: Vec<serde_json::Value>,
    pub more: bool,
    pub next_key: String,
}
