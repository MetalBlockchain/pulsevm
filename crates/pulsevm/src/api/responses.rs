use serde::Serialize;

use crate::chain::{BlockTimestamp, Name, Permission};

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

    pub permissions: Vec<Permission>,
}

#[derive(Serialize, Clone)]
pub struct IssueTxResponse {
    #[serde(rename(serialize = "txID"))]
    pub tx_id: String,
}
