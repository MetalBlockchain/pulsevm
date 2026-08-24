//! Typed rows for the chainstate sections of a version-6 `chain_snapshot`
//! (Leap 5.0.x). Field order mirrors the writer's `FC_REFLECT` declarations —
//! it is the wire format, do not reorder.

use pulsevm_chain_types::{
    BlockTimestamp,
    ChainConfigV0,
    TimePoint,
    TimePointSec,
};
use pulsevm_crypto::{
    Bytes,
    Digest,
};
use pulsevm_name::Name;
use pulsevm_proc_macros::{
    NumBytes,
    Read,
};

use crate::types::{
    BlockSigningAuthority,
    SnapshotPublicKey,
    SnapshotSignature,
    U256Key,
};

/// The section names of a version-6 snapshot, in file order.
pub mod section_names {
    pub const CHAIN_SNAPSHOT_HEADER: &str = "eosio::chain::chain_snapshot_header";
    pub const BLOCK_STATE: &str = "eosio::chain::block_state";
    pub const ACCOUNT: &str = "eosio::chain::account_object";
    pub const ACCOUNT_METADATA: &str = "eosio::chain::account_metadata_object";
    pub const ACCOUNT_RAM_CORRECTION: &str = "eosio::chain::account_ram_correction_object";
    pub const GLOBAL_PROPERTY: &str = "eosio::chain::global_property_object";
    pub const PROTOCOL_STATE: &str = "eosio::chain::protocol_state_object";
    pub const DYNAMIC_GLOBAL_PROPERTY: &str = "eosio::chain::dynamic_global_property_object";
    pub const BLOCK_SUMMARY: &str = "eosio::chain::block_summary_object";
    pub const TRANSACTION: &str = "eosio::chain::transaction_object";
    pub const GENERATED_TRANSACTION: &str = "eosio::chain::generated_transaction_object";
    pub const CODE: &str = "eosio::chain::code_object";
    pub const CONTRACT_TABLES: &str = "contract_tables";
    pub const PERMISSION: &str = "eosio::chain::permission_object";
    pub const PERMISSION_LINK: &str = "eosio::chain::permission_link_object";
    pub const RESOURCE_LIMITS: &str = "eosio::chain::resource_limits::resource_limits_object";
    pub const RESOURCE_USAGE: &str = "eosio::chain::resource_limits::resource_usage_object";
    pub const RESOURCE_LIMITS_STATE: &str =
        "eosio::chain::resource_limits::resource_limits_state_object";
    pub const RESOURCE_LIMITS_CONFIG: &str =
        "eosio::chain::resource_limits::resource_limits_config_object";
}

/// `eosio::chain::chain_snapshot_header` — the chainstate schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct ChainSnapshotHeader {
    pub version: u32,
}

/// `eosio::chain::account_object`.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct AccountRow {
    pub name: Name,
    pub creation_date: BlockTimestamp,
    /// Packed ABI (empty for accounts without one).
    pub abi: Bytes,
}

/// `eosio::chain::account_metadata_object`.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct AccountMetadataRow {
    pub name: Name,
    pub recv_sequence: u64,
    pub auth_sequence: u64,
    pub code_sequence: u64,
    pub abi_sequence: u64,
    /// All-zero for accounts without code.
    pub code_hash: Digest,
    pub last_code_update: TimePoint,
    /// Bit 0 = privileged.
    pub flags: u32,
    pub vm_type: u8,
    pub vm_version: u8,
}

impl AccountMetadataRow {
    pub fn is_privileged(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn has_code(&self) -> bool {
        self.code_hash != Digest::default()
    }
}

/// `eosio::chain::account_ram_correction_object`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct AccountRamCorrectionRow {
    pub name: Name,
    pub ram_correction: u64,
}

/// `eosio::chain::code_object` — deduplicated contract wasm, keyed by hash.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct CodeRow {
    pub code_hash: Digest,
    pub code: Bytes,
    pub code_ref_count: u64,
    pub first_block_used: u32,
    pub vm_type: u8,
    pub vm_version: u8,
}

/// One `key_weight` inside an authority or signing authority.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct SnapshotKeyWeight {
    pub key: SnapshotPublicKey,
    pub weight: u16,
}

/// One `permission_level_weight` inside an authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct SnapshotPermissionLevelWeight {
    pub actor: Name,
    pub permission: Name,
    pub weight: u16,
}

/// One `wait_weight` inside an authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct SnapshotWaitWeight {
    pub wait_sec: u32,
    pub weight: u16,
}

/// `eosio::chain::authority`, with the full key-variant support a live chain
/// needs (K1/R1/WebAuthn) — unlike `pulsevm_chain_types::Authority`, which is
/// K1-only.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct SnapshotAuthority {
    pub threshold: u32,
    pub keys: Vec<SnapshotKeyWeight>,
    pub accounts: Vec<SnapshotPermissionLevelWeight>,
    pub waits: Vec<SnapshotWaitWeight>,
}

/// `eosio::chain::snapshot_permission_object` — the snapshot form of a
/// permission, with the parent by name and last_used folded in.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct PermissionRow {
    /// Empty for `owner` permissions (and the reserved permission 0).
    pub parent: Name,
    pub owner: Name,
    pub name: Name,
    pub last_updated: TimePoint,
    pub last_used: TimePoint,
    pub auth: SnapshotAuthority,
}

/// `eosio::chain::permission_link_object` — a `linkauth` binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct PermissionLinkRow {
    pub account: Name,
    pub code: Name,
    /// Empty name = the link applies to every action of `code`.
    pub message_type: Name,
    pub required_permission: Name,
}

/// `eosio::chain::table_id_object` inside the `contract_tables` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct TableIdRow {
    pub code: Name,
    pub scope: Name,
    pub table: Name,
    pub payer: Name,
    pub count: u32,
}

/// `eosio::chain::key_value_object`.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct KeyValueRow {
    pub primary_key: u64,
    pub payer: Name,
    pub value: Bytes,
}

/// `eosio::chain::index64_object`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct Index64Row {
    pub primary_key: u64,
    pub payer: Name,
    pub secondary_key: u64,
}

/// `eosio::chain::index128_object`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct Index128Row {
    pub primary_key: u64,
    pub payer: Name,
    pub secondary_key: u128,
}

/// `eosio::chain::index256_object`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct Index256Row {
    pub primary_key: u64,
    pub payer: Name,
    pub secondary_key: U256Key,
}

/// `eosio::chain::index_double_object`.
#[derive(Debug, Clone, Copy, PartialEq, Read, NumBytes)]
pub struct IndexDoubleRow {
    pub primary_key: u64,
    pub payer: Name,
    pub secondary_key: f64,
}

/// `eosio::chain::index_long_double_object`. The key is a binary128 long
/// double; kept as its raw little-endian bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct IndexLongDoubleRow {
    pub primary_key: u64,
    pub payer: Name,
    pub secondary_key: u128,
}

/// `eosio::chain::resource_limits::resource_limits_object` (committed rows
/// only — pending rows are never written to a snapshot). `-1` = unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct ResourceLimitsRow {
    pub owner: Name,
    pub net_weight: i64,
    pub cpu_weight: i64,
    pub ram_bytes: i64,
}

/// `eosio::chain::resource_limits::usage_accumulator` — an exponential moving
/// average window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct UsageAccumulator {
    pub last_ordinal: u32,
    pub value_ex: u64,
    pub consumed: u64,
}

/// `eosio::chain::resource_limits::resource_usage_object`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct ResourceUsageRow {
    pub owner: Name,
    pub net_usage: UsageAccumulator,
    pub cpu_usage: UsageAccumulator,
    pub ram_usage: u64,
}

/// `eosio::chain::resource_limits::resource_limits_state_object` — the elastic
/// (virtual) limit state, including the block-usage averages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct ResourceLimitsStateRow {
    pub average_block_net_usage: UsageAccumulator,
    pub average_block_cpu_usage: UsageAccumulator,
    pub pending_net_usage: u64,
    pub pending_cpu_usage: u64,
    pub total_net_weight: u64,
    pub total_cpu_weight: u64,
    pub total_ram_bytes: u64,
    pub virtual_net_limit: u64,
    pub virtual_cpu_limit: u64,
}

/// `eosio::chain::resource_limits::ratio`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct SnapshotRatio {
    pub numerator: u64,
    pub denominator: u64,
}

/// `eosio::chain::resource_limits::elastic_limit_parameters`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct SnapshotElasticLimitParameters {
    pub target: u64,
    pub max: u64,
    pub periods: u32,
    pub max_multiplier: u32,
    pub contract_rate: SnapshotRatio,
    pub expand_rate: SnapshotRatio,
}

/// `eosio::chain::resource_limits::resource_limits_config_object`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct ResourceLimitsConfigRow {
    pub cpu_limit_parameters: SnapshotElasticLimitParameters,
    pub net_limit_parameters: SnapshotElasticLimitParameters,
    pub account_cpu_usage_average_window: u32,
    pub account_net_usage_average_window: u32,
}

/// `eosio::chain::chain_config` (v1): the v0 fields plus
/// `max_action_return_value_size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct SnapshotChainConfig {
    pub base: ChainConfigV0,
    pub max_action_return_value_size: u32,
}

/// `eosio::chain::kv_database_config` (never activated; all zero in practice).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct KvDatabaseConfig {
    pub max_key_size: u32,
    pub max_value_size: u32,
    pub max_iterators: u32,
}

/// `eosio::chain::wasm_config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct WasmConfig {
    pub max_mutable_global_bytes: u32,
    pub max_table_elements: u32,
    pub max_section_elements: u32,
    pub max_linear_memory_init: u32,
    pub max_func_local_bytes: u32,
    pub max_nested_structures: u32,
    pub max_symbol_bytes: u32,
    pub max_module_bytes: u32,
    pub max_code_bytes: u32,
    pub max_pages: u32,
    pub max_call_depth: u32,
}

/// `eosio::chain::snapshot_global_property_object` — carries the chain id and
/// the active chain configuration.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct GlobalPropertyRow {
    pub proposed_schedule_block_num: Option<u32>,
    pub proposed_schedule: ProducerAuthoritySchedule,
    pub configuration: SnapshotChainConfig,
    pub chain_id: Digest,
    pub kv_configuration: KvDatabaseConfig,
    pub wasm_configuration: WasmConfig,
}

/// `eosio::chain::protocol_state_object::activated_protocol_feature`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct ActivatedProtocolFeature {
    pub feature_digest: Digest,
    pub activation_block_num: u32,
}

/// `eosio::chain::snapshot_protocol_state_object`.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct ProtocolStateRow {
    pub activated_protocol_features: Vec<ActivatedProtocolFeature>,
    pub preactivated_protocol_features: Vec<Digest>,
    pub whitelisted_intrinsics: Vec<String>,
    pub num_supported_key_types: u32,
}

/// `eosio::chain::dynamic_global_property_object`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct DynamicGlobalPropertyRow {
    pub global_action_sequence: u64,
}

/// `eosio::chain::block_summary_object` — the 64Ki-slot TAPOS ring buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct BlockSummaryRow {
    pub block_id: Digest,
}

/// `eosio::chain::transaction_object` — the input-transaction dedupe set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Read, NumBytes)]
pub struct TransactionRow {
    pub expiration: TimePointSec,
    pub trx_id: Digest,
}

/// `eosio::chain::generated_transaction_object` — pending deferred
/// transactions.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct GeneratedTransactionRow {
    pub trx_id: Digest,
    pub sender: Name,
    pub sender_id: u128,
    pub payer: Name,
    pub delay_until: TimePoint,
    pub expiration: TimePoint,
    pub published: TimePoint,
    pub packed_trx: Bytes,
}

/// `eosio::chain::block_signing_authority_v0`.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct BlockSigningAuthorityV0 {
    pub threshold: u32,
    pub keys: Vec<SnapshotKeyWeight>,
}

/// `eosio::chain::producer_authority`.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct ProducerAuthority {
    pub producer_name: Name,
    pub authority: BlockSigningAuthority,
}

/// `eosio::chain::producer_authority_schedule`.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct ProducerAuthoritySchedule {
    pub version: u32,
    pub producers: Vec<ProducerAuthority>,
}

/// `eosio::chain::legacy::producer_key` (pre-WTMsig schedules, only reachable
/// through the deprecated `new_producers` header field).
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct LegacyProducerKey {
    pub producer_name: Name,
    pub block_signing_key: SnapshotPublicKey,
}

/// `eosio::chain::legacy::producer_schedule_type`.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct LegacyProducerSchedule {
    pub version: u32,
    pub producers: Vec<LegacyProducerKey>,
}

/// `eosio::chain::incremental_merkle`.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct IncrementalMerkle {
    pub active_nodes: Vec<Digest>,
    pub node_count: u64,
}

/// `eosio::chain::signed_block_header` (header fields flattened).
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct SignedBlockHeader {
    pub timestamp: BlockTimestamp,
    pub producer: Name,
    pub confirmed: u16,
    pub previous: Digest,
    pub transaction_mroot: Digest,
    pub action_mroot: Digest,
    pub schedule_version: u32,
    pub new_producers: Option<LegacyProducerSchedule>,
    pub header_extensions: Vec<(u16, Bytes)>,
    pub producer_signature: SnapshotSignature,
}

/// `eosio::chain::detail::schedule_info`.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct ScheduleInfo {
    pub schedule_lib_num: u32,
    pub schedule_hash: Digest,
    pub schedule: ProducerAuthoritySchedule,
}

/// `eosio::chain::protocol_feature_activation_set`.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct ProtocolFeatureActivationSet {
    pub protocol_features: Vec<Digest>,
}

/// The `eosio::chain::block_state` section row: the full legacy
/// `block_header_state` of the snapshot's head block. This carries everything
/// a resumed chain needs for block-height continuity: head block num, id,
/// timestamp and the active producer schedule.
#[derive(Debug, Clone, PartialEq, Eq, Read, NumBytes)]
pub struct BlockHeaderState {
    pub block_num: u32,
    pub dpos_proposed_irreversible_blocknum: u32,
    pub dpos_irreversible_blocknum: u32,
    pub active_schedule: ProducerAuthoritySchedule,
    pub blockroot_merkle: IncrementalMerkle,
    pub producer_to_last_produced: Vec<(Name, u32)>,
    pub producer_to_last_implied_irb: Vec<(Name, u32)>,
    pub valid_block_signing_authority: BlockSigningAuthority,
    pub confirm_count: Vec<u8>,
    pub id: Digest,
    pub header: SignedBlockHeader,
    pub pending_schedule: ScheduleInfo,
    /// Packed as an fc `shared_ptr`: a presence byte, then the set.
    pub activated_protocol_features: Option<ProtocolFeatureActivationSet>,
    pub additional_signatures: Vec<SnapshotSignature>,
}

impl BlockHeaderState {
    /// The block number embedded in the head block id's first four (big
    /// endian) bytes — must equal `block_num`; a cheap self-check that the
    /// decode stayed aligned.
    pub fn block_num_from_id(&self) -> u32 {
        u32::from_be_bytes([self.id.0[0], self.id.0[1], self.id.0[2], self.id.0[3]])
    }
}
