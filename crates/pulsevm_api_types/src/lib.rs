use pulsevm_core::{
    asset::Asset,
    authority::Authority,
    block::BlockTimestamp,
    id::Id,
    name::Name,
    time::TimePoint,
};
use serde::{
    Deserialize,
    Serialize,
    de,
};

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
    #[serde(default)]
    pub protocol_version: u32,
    #[serde(default)]
    pub supported_protocol_version: u32,
    #[serde(default)]
    pub protocol_upgrade_schedule_hash: String,
    #[serde(default)]
    pub next_protocol_upgrade: Option<ProtocolUpgradeInfo>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolUpgradeInfo {
    pub protocol_version: u32,
    pub activation_height: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IssueTxResponse {
    #[serde(rename(serialize = "txID", deserialize = "txID"))]
    pub tx_id: Id,
}

#[cfg(test)]
mod tests {
    use super::ChainInfoResponse;
    use serde_json::{
        Value,
        json,
    };

    fn chain_info_payload() -> Value {
        json!({
            "server_version": "version",
            "server_time": "2026-08-18T00:00:00.000",
            "chain_id": "chain-id",
            "head_block_num": 42,
            "last_irreversible_block_num": 41,
            "last_irreversible_block_id": "lib-id",
            "head_block_id": "head-id",
            "head_block_time": "2026-08-18T00:00:00.000",
            "head_block_producer": "producer",
            "virtual_block_cpu_limit": 1,
            "virtual_block_net_limit": 2,
            "block_cpu_limit": 3,
            "block_net_limit": 4,
            "server_version_string": "version-string",
            "fork_db_head_block_num": 42,
            "fork_db_head_block_id": "fork-head-id",
            "server_full_version_string": "full-version-string",
            "total_cpu_weight": 5,
            "total_net_weight": 6,
            "earliest_available_block_num": 1,
            "last_irreversible_block_time": "2026-08-18T00:00:00.000"
        })
    }

    #[test]
    fn chain_info_defaults_protocol_versions_for_older_payloads() {
        let response: ChainInfoResponse =
            serde_json::from_value(chain_info_payload()).expect("valid older getInfo payload");

        assert_eq!(response.protocol_version, 0);
        assert_eq!(response.supported_protocol_version, 0);
        assert!(response.protocol_upgrade_schedule_hash.is_empty());
        assert_eq!(response.next_protocol_upgrade, None);
    }

    #[test]
    fn chain_info_preserves_protocol_versions() {
        let mut payload = chain_info_payload();
        let object = payload.as_object_mut().expect("payload must be an object");
        object.insert("protocol_version".to_string(), json!(7));
        object.insert("supported_protocol_version".to_string(), json!(9));
        object.insert("protocol_upgrade_schedule_hash".to_string(), json!("abcd"));
        object.insert(
            "next_protocol_upgrade".to_string(),
            json!({"protocol_version": 10, "activation_height": 123}),
        );

        let response: ChainInfoResponse =
            serde_json::from_value(payload).expect("valid current getInfo payload");

        assert_eq!(response.protocol_version, 7);
        assert_eq!(response.supported_protocol_version, 9);
        assert_eq!(response.protocol_upgrade_schedule_hash, "abcd");
        assert_eq!(
            response.next_protocol_upgrade,
            Some(super::ProtocolUpgradeInfo {
                protocol_version: 10,
                activation_height: 123,
            })
        );
    }
}
