pub use pulsevm_api_types::{
    GetTransactionStatusResponse,
    TransactionStatus,
};
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
    /// MetalGo's subnet id. Usually equal to `chain_id`; migration chains may
    /// use a pinned Antelope signing id and expose the host id separately.
    pub platform_chain_id: Id,
    /// Local snapshot offer interval. Operators must keep this identical across
    /// validators; mismatches prevent the host from finding common summary heights.
    pub state_summary_interval: u64,
    pub state_sync_enabled: bool,
    pub block_production_enabled: bool,
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
    /// Which build this node is and the on-disk and state formats it writes. Two
    /// producers that differ here cannot be expected to agree, so a fleet is
    /// checked for one value (see docs/xpr-cutover-operations.md).
    pub pulsevm_build: BuildInfo,
}

#[derive(Serialize, Clone, Default, Debug, PartialEq, Eq)]
pub struct BuildInfo {
    /// The git commit (or PULSEVM_BUILD_ID) this binary was built from.
    pub build_id: String,
    /// The write-ahead log format this build writes and accepts.
    pub wal_format: String,
    /// The format of the state hash and of the canonical export.
    pub state_hash_format: String,
}

impl BuildInfo {
    pub fn current() -> Self {
        Self {
            build_id: env!("PULSEVM_BUILD_ID").to_owned(),
            wal_format: pulsevm_core::WAL_FORMAT.to_owned(),
            state_hash_format: pulsevm_core::STATE_HASH_FORMAT.to_owned(),
        }
    }
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

#[cfg(test)]
mod build_info_tests {
    use super::BuildInfo;

    #[test]
    fn the_build_says_what_it_is_and_which_formats_it_writes() {
        let build = BuildInfo::current();
        assert!(!build.build_id.is_empty());
        assert_eq!(build.wal_format, pulsevm_core::WAL_FORMAT);
        assert_eq!(build.state_hash_format, pulsevm_core::STATE_HASH_FORMAT);
        // It is part of getInfo, under the name a fleet check reads.
        let json = serde_json::to_value(super::GetInfoResponse {
            pulsevm_build: build.clone(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(json["pulsevm_build"]["wal_format"], build.wal_format);
        assert_eq!(json["pulsevm_build"]["build_id"], build.build_id);
    }
}
