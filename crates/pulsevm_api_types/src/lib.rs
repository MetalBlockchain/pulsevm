use pulsevm_core::{asset::Asset, authority::Authority, block::BlockTimestamp, id::Id, name::Name};
use pulsevm_time::{TimePoint, TimePointSec};
use serde::{Deserialize, Serialize, de};

fn string_or_i64<'de, D: de::Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrInt {
        String(String),
        Int(i64),
    }

    match StringOrInt::deserialize(deserializer)? {
        StringOrInt::String(s) => s.parse::<i64>().map_err(de::Error::custom),
        StringOrInt::Int(v) => Ok(v),
    }
}

fn option_string_or_i64<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrInt {
        String(String),
        Int(i64),
    }

    let opt: Option<StringOrInt> = Option::deserialize(deserializer)?;
    match opt {
        Some(StringOrInt::String(s)) => s.parse::<i64>().map(Some).map_err(de::Error::custom),
        Some(StringOrInt::Int(v)) => Ok(Some(v)),
        None => Ok(None),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountResourceInfo {
    #[serde(deserialize_with = "string_or_i64")]
    pub used: i64,
    #[serde(deserialize_with = "string_or_i64")]
    pub available: i64,
    #[serde(deserialize_with = "string_or_i64")]
    pub max: i64,
    pub last_usage_update_time: Option<BlockTimestamp>,
    #[serde(default, deserialize_with = "option_string_or_i64")]
    pub current_used: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedAction {
    pub account: Name,
    pub action: Option<Name>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub perm_name: Name,
    pub parent: Name,
    pub required_auth: Authority,
    pub linked_actions: Option<Vec<LinkedAction>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountResponse {
    pub account_name: Name,
    pub head_block_num: u32,
    pub head_block_time: TimePoint,
    pub privileged: bool,
    pub last_code_update: TimePoint,
    pub created: TimePoint,
    pub core_liquid_balance: Option<Asset>,
    pub ram_quota: i64,
    pub net_weight: i64,
    pub cpu_weight: i64,
    pub net_limit: AccountResourceInfo,
    pub cpu_limit: AccountResourceInfo,
    pub ram_usage: i64,
    pub permissions: Vec<Permission>,
}

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
