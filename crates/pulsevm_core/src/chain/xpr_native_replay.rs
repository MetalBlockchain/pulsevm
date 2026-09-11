//! Code-hash-pinned native accelerators for historical XPR migration replay.
//!
//! These handlers are deliberately unavailable unless the replay operator opts
//! in. An account or action name is never sufficient: each handler is also
//! pinned to the SHA-256 of the deployed WASM whose semantics it implements.

use std::time::{
    Duration,
    Instant,
};

use pulsevm_billable_size::billable_size_v;
use pulsevm_crypto::Digest;
use pulsevm_database::{
    BlockTimestamp,
    Database,
    KeyValueObject,
};
use pulsevm_error::ChainError;
use pulsevm_proc_macros::{
    NumBytes,
    Read,
    Write,
};
use pulsevm_serialization::{
    CanonicalMap,
    NumBytes as SerializationNumBytes,
    Read as SerializationRead,
    Write as SerializationWrite,
};

use crate::{
    chain::{
        ACTIVE_NAME,
        apply_context::ApplyContext,
        authority::PermissionLevel,
        transaction::Action,
    },
    name::Name,
};

pub(super) const BOT: u64 = 4_409_586_985_149_136_896;
const BOTS: u64 = 4_410_009_197_614_202_880;
pub(super) const ORACLES: u64 = 11_947_074_179_527_868_416;
const DATA: u64 = 5_310_412_463_739_502_592;
pub(super) const PROCESS: u64 = 12_531_412_623_406_661_632;
const FEED: u64 = 6_527_000_089_641_091_072;
const FEEDS: u64 = 6_527_013_283_780_624_384;
const EOSIO: u64 = 6_138_663_577_826_885_632;
const ONBLOCK: u64 = 11_875_739_475_730_497_536;
const GLOBAL: u64 = 7_235_159_537_265_672_192;
const GLOBAL2: u64 = 7_235_159_538_339_414_016;
const GLOBAL3: u64 = 7_235_159_538_876_284_928;
const GLOBAL4: u64 = 7_235_159_539_413_155_840;
const GLOBALSXPR: u64 = 7_235_159_550_648_500_224;
const GLOBALSD: u64 = 7_235_159_550_301_569_024;
const PRODUCERS: u64 = 12_531_438_729_690_087_424;
pub(super) const MECHANICS: u64 = 10_561_173_457_217_781_760;
pub(super) const CPU: u64 = 5_004_625_085_915_463_680;
const NOLOSS: u64 = 11_322_977_863_340_130_304;
const TRADE: u64 = 14_829_391_500_256_739_328;
const XPR_NOLOSS_CODE_HASH: [u8; 32] = [
    0x2f, 0xe9, 0xb5, 0x19, 0x45, 0x3d, 0x07, 0xda, 0x24, 0x24, 0x79, 0x65, 0xe6, 0x2f, 0x2e, 0x50,
    0x6d, 0xd9, 0x59, 0xde, 0x15, 0x36, 0xcb, 0x4e, 0x20, 0x5f, 0x61, 0xff, 0x76, 0xa8, 0x91, 0x1e,
];
// Activated at XPR Mainnet block 141,529,683. The deployed module differs from
// the preceding version by exactly one instruction: `unique % 24` became
// `unique % 21`; its imports and every other instruction are byte-identical.
const XPR_NOLOSS_V2_CODE_HASH: [u8; 32] = [
    0xcf, 0x50, 0x04, 0x62, 0x46, 0xf6, 0xa7, 0x39, 0xa0, 0x5f, 0x63, 0xed, 0x3d, 0x8f, 0x98, 0xd7,
    0xcb, 0x13, 0x17, 0x8d, 0x32, 0x42, 0x28, 0x9d, 0x8b, 0x29, 0xb6, 0x36, 0x65, 0xca, 0x30, 0xc2,
];

pub(super) struct ReadOnlyWasmProbe {
    pub cache_hit: bool,
    code_hash: [u8; 32],
    action: u64,
    data_key: [u64; 2],
}

fn noloss_trade_data_key(receiver: u64, action: &Action, code_hash: &[u8; 32]) -> Option<[u64; 2]> {
    let unique_modulus = match *code_hash {
        XPR_NOLOSS_CODE_HASH => 24,
        XPR_NOLOSS_V2_CODE_HASH => 21,
        _ => return None,
    };
    if receiver != NOLOSS
        || action.account().as_u64() != NOLOSS
        || action.name().as_u64() != TRADE
        || action.data().len() != 16
    {
        return None;
    }
    let data = action.data();
    let user = u64::from_le_bytes(data[..8].try_into().expect("length checked"));
    let unique = u64::from_le_bytes(data[8..].try_into().expect("length checked"));
    Some([user, unique % unique_modulus])
}

/// Memoize the deployed `noloss::trade` scanner only after canonical WASM has
/// proved that a normalized invocation schedules no inline action and changes
/// none of the contracts it reads. Static bytecode audit establishes that the
/// action reads Alcor/proton.swaps state, has no time/transaction-id imports,
/// and uses `unique` only modulo a code-hash-pinned constant; any dependency
/// write invalidates the learned result before another call can bypass WASM.
pub(super) fn prepare_read_only_wasm(
    context: &ApplyContext,
    action: &Action,
    code_hash: &[u8; 32],
) -> Result<Option<ReadOnlyWasmProbe>, ChainError> {
    if !context.xpr_native_replay_enabled() || !context.is_explicitly_billed()? {
        return Ok(None);
    }
    let Some(data_key) = noloss_trade_data_key(context.receiver().as_u64(), action, code_hash)
    else {
        return Ok(None);
    };
    let cache_hit =
        context.xpr_read_only_wasm_cache_probe(*code_hash, action.name().as_u64(), data_key);
    super::replay_profile::record_read_only_wasm_probe(cache_hit);
    if cache_hit {
        context.require_authorization(&Name::new(data_key[0]), None)?;
    }
    Ok(Some(ReadOnlyWasmProbe {
        cache_hit,
        code_hash: *code_hash,
        action: action.name().as_u64(),
        data_key,
    }))
}

pub(super) fn finish_read_only_wasm(
    context: &ApplyContext,
    probe: ReadOnlyWasmProbe,
) -> Result<(), ChainError> {
    let scheduled_inline = context.has_scheduled_inline_actions()?;
    let promoted = if scheduled_inline {
        false
    } else {
        context.xpr_promote_read_only_wasm_cache(probe.code_hash, probe.action, probe.data_key)
    };
    super::replay_profile::record_read_only_wasm_finish(promoted, scheduled_inline);
    Ok(())
}

pub(super) fn cancel_read_only_wasm(context: &ApplyContext) {
    context.xpr_cancel_read_only_wasm_capture();
}

// XPRNetwork/proton.contracts commit 4c31f5f5d5d7d36cd752f3e498075fe9f87aa23b.
const XPR_SYSTEM_CODE_HASH: [u8; 32] = [
    0x94, 0xe7, 0x62, 0x3e, 0xf2, 0x69, 0x8a, 0x9e, 0x20, 0xa2, 0x8e, 0x65, 0x03, 0xc2, 0x62, 0x12,
    0x35, 0xc8, 0x68, 0xc1, 0x91, 0x9f, 0x7e, 0xdf, 0x3a, 0x8f, 0x52, 0xc7, 0x29, 0x26, 0xac, 0x95,
];

// XPRNetwork/proton.contracts commit 8b36e6f9a243fbcc5924b3be0d6e9adeaef2bc0d.
// The onblock body, singleton constructor/destructor, and serialized rows are
// unchanged from XPR_SYSTEM_CODE_HASH.
const XPR_SYSTEM_V2_CODE_HASH: [u8; 32] = [
    0x25, 0x90, 0x8c, 0xf2, 0x71, 0xdc, 0xa6, 0x3e, 0x66, 0xb0, 0x6d, 0x21, 0x3b, 0xfd, 0xb3, 0x45,
    0x83, 0xc7, 0x79, 0x43, 0xe3, 0x8c, 0x8a, 0x69, 0x5c, 0x19, 0x1e, 0x6c, 0xe7, 0xfc, 0xc5, 0xa5,
];

// XPRNetwork/proton.contracts commit b9244e14d4da3567e9ae96bd0eaebbbbe76839c0,
// first used at Mainnet block 58,975,412. The onblock implementation and the
// six rows it reads/mutates are byte-for-byte unchanged from V2. This revision
// adds a seventh `globalram` singleton to the constructor/destructor, but its
// value is unchanged by onblock; offline replay has SHiP disabled and therefore
// need not reproduce that no-op rewrite.
const XPR_SYSTEM_V3_CODE_HASH: [u8; 32] = [
    0xe8, 0x5a, 0xcb, 0x33, 0x49, 0x52, 0x3d, 0xbf, 0x50, 0x8b, 0x3d, 0xf4, 0x56, 0x66, 0x91, 0x18,
    0x00, 0x04, 0x33, 0x81, 0x09, 0xb3, 0x89, 0x5e, 0xa4, 0xb8, 0x12, 0x8e, 0xd9, 0x60, 0xdc, 0xea,
];

// XPRNetwork/proton.contracts commit 4315f5bf60b5aef1bbe0e550d4fece873e52250c,
// first used at Mainnet block 112,900,241. Its onblock body and singleton
// constructor/destructor are unchanged from V3; changes are confined to other
// system actions.
const XPR_SYSTEM_V4_CODE_HASH: [u8; 32] = [
    0x42, 0xaf, 0x59, 0xee, 0x2e, 0x22, 0x5e, 0x58, 0x39, 0x5d, 0xf4, 0x14, 0xfd, 0x88, 0x56, 0x38,
    0x24, 0x7c, 0xbe, 0x85, 0x2d, 0x2c, 0x5b, 0xaf, 0x20, 0xbb, 0x1e, 0x69, 0x5d, 0x68, 0xe3, 0x94,
];

fn is_supported_system_code_hash(code_hash: &[u8; 32]) -> bool {
    *code_hash == XPR_SYSTEM_CODE_HASH
        || *code_hash == XPR_SYSTEM_V2_CODE_HASH
        || *code_hash == XPR_SYSTEM_V3_CODE_HASH
        || *code_hash == XPR_SYSTEM_V4_CODE_HASH
}

// Deployed `mechanics` bytecode at the audited Mainnet checkpoint. Its empty
// `cpu` action requires authorization from the receiver and runs a fixed,
// side-effect-free prime-number loop solely to consume CPU. Accepted-block
// replay uses the producer-recorded CPU bill, so repeating that loop cannot
// affect state or receipts.
pub(super) const XPR_MECHANICS_CODE_HASH: [u8; 32] = [
    0x6b, 0x7a, 0xa8, 0xa8, 0x40, 0xbf, 0xf3, 0xae, 0xa9, 0xda, 0x1a, 0x40, 0x13, 0x13, 0x31, 0xeb,
    0xab, 0xe9, 0xf4, 0x61, 0xfb, 0xfa, 0x6e, 0xd1, 0x92, 0x8c, 0xb0, 0x35, 0x89, 0xb6, 0xdb, 0x6d,
];

// XPRNetwork/proton-bots commit 44457b697c9c7dd91abc610332bc20e9ecfa4866.
const XPR_BOT_CODE_HASH: [u8; 32] = [
    0x8e, 0x7d, 0x40, 0xff, 0x68, 0x07, 0xab, 0x49, 0x07, 0xdd, 0x30, 0x05, 0x33, 0x18, 0xea, 0x3b,
    0x38, 0xef, 0x71, 0xea, 0x56, 0xb0, 0x52, 0xa0, 0xe6, 0x0d, 0x3c, 0xbe, 0x34, 0x17, 0xa1, 0xbb,
];

// XPRNetwork/proton-bots commit 6ea2b229ee10efe867e770a930ea502e80ca6683.
const XPR_BOT_V2_CODE_HASH: [u8; 32] = [
    0x2b, 0x2a, 0x55, 0xf6, 0x5b, 0x19, 0xb2, 0x52, 0x44, 0x49, 0xdb, 0x9f, 0x01, 0xdd, 0x10, 0x15,
    0xb7, 0x37, 0x17, 0x83, 0x5b, 0x2b, 0xaf, 0xd7, 0x61, 0x25, 0xf8, 0x90, 0x8f, 0x15, 0x5e, 0x7b,
];

// Transitional build immediately before proton-bots 1b5cb36. The only
// bytecode difference is process2 authorization; process is unchanged.
const XPR_BOT_V3_CODE_HASH: [u8; 32] = [
    0xd1, 0xf0, 0x4e, 0xac, 0xb6, 0x1a, 0x04, 0xc9, 0x8a, 0x18, 0x1c, 0x5d, 0xcd, 0x6a, 0x4e, 0xfb,
    0x87, 0x02, 0x89, 0xa1, 0x4f, 0x88, 0x67, 0xc1, 0xa9, 0x37, 0x09, 0x21, 0x70, 0xb2, 0xd9, 0xd5,
];

// XPRNetwork/proton-bots commit 1b5cb36. This adds process2 while retaining
// process's payload and transition from XPR_BOT_V2_CODE_HASH.
const XPR_BOT_V4_CODE_HASH: [u8; 32] = [
    0x4c, 0xdd, 0xdc, 0x3d, 0x3b, 0x97, 0x09, 0xb1, 0x24, 0x45, 0xe2, 0x2d, 0x3f, 0xc0, 0x46, 0x0a,
    0xca, 0x25, 0xa3, 0x20, 0x19, 0x17, 0x06, 0xa3, 0x21, 0x94, 0x1b, 0xe4, 0xea, 0x88, 0x7e, 0xa8,
];

const XPR_ORACLES_CODE_HASH: [u8; 32] = [
    0xcc, 0x1e, 0x51, 0x38, 0x47, 0xcc, 0x95, 0x92, 0xed, 0x2e, 0x4b, 0xb1, 0x85, 0xdb, 0x5e, 0x65,
    0x32, 0x8d, 0x7a, 0x18, 0x0b, 0x1c, 0x34, 0x87, 0x71, 0x8d, 0x97, 0x51, 0x29, 0x3b, 0xca, 0xf2,
];

// XPRNetwork/proton-oracle commit 05740967447423277336a985f19b88099382120f.
const XPR_ORACLES_V2_CODE_HASH: [u8; 32] = [
    0x56, 0xef, 0x21, 0xbe, 0x74, 0xbf, 0xa0, 0xf1, 0x44, 0xd7, 0x69, 0x7a, 0x32, 0xd2, 0xa4, 0x2e,
    0x38, 0x2b, 0x60, 0xa5, 0xea, 0x0c, 0x6c, 0x5a, 0xf0, 0x3b, 0x90, 0x15, 0xfe, 0x7e, 0x61, 0xa2,
];

// XPRNetwork/proton-oracle commit 5189f15557f958c0284dd40e5507fdd5725b19d3.
// This deployment adds a new aggregate mode; the feed transition and existing
// mean aggregation used by the replay workload are unchanged.
const XPR_ORACLES_V3_CODE_HASH: [u8; 32] = [
    0xc5, 0x5c, 0x64, 0x89, 0x5c, 0x77, 0xfb, 0x9c, 0xcc, 0x24, 0xb3, 0xa7, 0xe6, 0xdf, 0x66, 0x3c,
    0xa6, 0x1e, 0xc6, 0xe2, 0xd6, 0xca, 0xba, 0x9e, 0x74, 0xe2, 0x2b, 0x8a, 0xc3, 0x5d, 0xfa, 0x16,
];
// XPRNetwork/proton-oracle 1a74df5. The feed transition is unchanged from V3;
// this deployment changes feed management, multisig, and aggregation behavior.
const XPR_ORACLES_V4_CODE_HASH: [u8; 32] = [
    0x50, 0xc6, 0x51, 0x50, 0x27, 0x6a, 0x3a, 0xea, 0x95, 0xeb, 0xfe, 0x5e, 0x34, 0x47, 0x50, 0xa4,
    0xe0, 0x3d, 0x68, 0x2a, 0x34, 0xe3, 0xb0, 0x3e, 0x1a, 0x0a, 0x90, 0xa6, 0xfa, 0x31, 0x1f, 0xa6,
];
// Transitional mainnet build between 1a74df5 and 960e5b3. Its bytecode diff
// changes only setfeed's config key/error strings; feed semantics are unchanged.
const XPR_ORACLES_V5_CODE_HASH: [u8; 32] = [
    0x10, 0x09, 0xad, 0x45, 0x91, 0x11, 0xf2, 0xf8, 0xcc, 0xc5, 0x9b, 0xcb, 0xb9, 0xde, 0xcc, 0xa0,
    0x0e, 0xd2, 0x48, 0xda, 0xc3, 0x1f, 0xe6, 0xdc, 0xc7, 0xf1, 0xc2, 0x07, 0x50, 0xcb, 0x5a, 0xf4,
];
// XPRNetwork/proton-oracle 960e5b34993fbba92710d7949fd95c7f34242b4c.
const XPR_ORACLES_V6_CODE_HASH: [u8; 32] = [
    0x83, 0x7b, 0xeb, 0x74, 0x12, 0x7e, 0xd8, 0x62, 0xb3, 0x74, 0x5a, 0x75, 0x68, 0x84, 0x8e, 0x25,
    0xfa, 0x7e, 0x08, 0xf8, 0x8b, 0xca, 0x1a, 0xf3, 0xdd, 0x79, 0x10, 0xbb, 0x87, 0x1f, 0x4c, 0xbc,
];
// XPRNetwork/proton-oracle 6d2480ac38872aa0e5708979de13aa0076e4a067.
// The only contract-source change from V6 fixes and cleans up executemsig;
// feed and its serialized state transitions are unchanged. Mainnet installed
// it through eosio.msig::exec in block 52,926,343; code-object bookkeeping
// records first_block_used 52,926,344.
const XPR_ORACLES_V7_CODE_HASH: [u8; 32] = [
    0xe6, 0x92, 0x19, 0x81, 0x94, 0xa7, 0x9a, 0x51, 0xd7, 0xfb, 0xd5, 0x37, 0x62, 0xa8, 0xc9, 0x4a,
    0xd0, 0x28, 0x35, 0x34, 0x01, 0xd7, 0x4d, 0x08, 0x8f, 0x90, 0x5e, 0x57, 0xf0, 0x6d, 0x5c, 0xef,
];
// XPRNetwork/proton-oracle db253012559cee4deec7202d693143f043ce0374.
// The feed action, its row layouts, and mean aggregation are unchanged from
// V7. This revision changes only mode aggregation and setfeed validation, while
// the native path remains restricted to mean/double feeds.
const XPR_ORACLES_V8_CODE_HASH: [u8; 32] = [
    0x22, 0x17, 0x4c, 0x4e, 0x9b, 0xde, 0x31, 0xf1, 0x20, 0x15, 0x94, 0x33, 0x7b, 0x73, 0x24, 0x00,
    0xf6, 0x57, 0xe9, 0x35, 0x09, 0x55, 0xee, 0x59, 0xb3, 0xf3, 0xce, 0x20, 0x2e, 0x7f, 0x08, 0xda,
];

fn bot_uses_v2_layout(code_hash: &[u8; 32]) -> bool {
    *code_hash == XPR_BOT_V2_CODE_HASH
        || *code_hash == XPR_BOT_V3_CODE_HASH
        || *code_hash == XPR_BOT_V4_CODE_HASH
}

fn is_supported_bot_code_hash(code_hash: &[u8; 32]) -> bool {
    *code_hash == XPR_BOT_CODE_HASH || bot_uses_v2_layout(code_hash)
}

fn oracle_uses_v2_layout(code_hash: &[u8; 32]) -> bool {
    *code_hash == XPR_ORACLES_V2_CODE_HASH
        || *code_hash == XPR_ORACLES_V3_CODE_HASH
        || *code_hash == XPR_ORACLES_V4_CODE_HASH
        || *code_hash == XPR_ORACLES_V5_CODE_HASH
        || *code_hash == XPR_ORACLES_V6_CODE_HASH
        || *code_hash == XPR_ORACLES_V7_CODE_HASH
        || *code_hash == XPR_ORACLES_V8_CODE_HASH
}

fn is_supported_oracle_code_hash(code_hash: &[u8; 32]) -> bool {
    *code_hash == XPR_ORACLES_CODE_HASH || oracle_uses_v2_layout(code_hash)
}

fn oracle_supports_mean_median(code_hash: &[u8; 32]) -> bool {
    *code_hash == XPR_ORACLES_V8_CODE_HASH
}

#[derive(Clone, Debug, PartialEq, Read, Write, NumBytes)]
struct DataVariant {
    d_string: Option<String>,
    d_uint64: Option<u64>,
    d_double: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Read, Write, NumBytes)]
struct BotEntry {
    bot_index: u64,
    data: DataVariant,
}

#[derive(Clone, Debug, PartialEq, Read, Write, NumBytes)]
struct Process {
    account: u64,
    entries: Vec<BotEntry>,
    nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Read, Write, NumBytes)]
struct ProcessV2 {
    account: u64,
    entries: Vec<BotEntry>,
    nonce: u64,
    oracle_index: u64,
}

#[derive(Clone, Debug, PartialEq, Read, Write, NumBytes)]
struct Tx {
    id: Digest,
    time: i64,
    data: DataVariant,
}

#[derive(Clone, Debug, PartialEq, Read, Write, NumBytes)]
struct BotRow {
    index: u64,
    account: u64,
    description: String,
    oracle_contract: u64,
    feed_index: u64,
    tx_count_by_utc_hour: CanonicalMap<u8, u64>,
    max_history: u8,
    history: Vec<Tx>,
}

#[derive(Clone, Debug, PartialEq, Read, Write, NumBytes)]
struct ProviderPoint {
    provider: u64,
    time: i64,
    data: DataVariant,
}

#[derive(Clone, Debug, PartialEq, Read, Write, NumBytes)]
struct FeedRow {
    index: u64,
    name: String,
    description: String,
    aggregate_function: String,
    data_type: String,
    config: CanonicalMap<String, u64>,
    providers: CanonicalMap<u64, i64>,
}

#[derive(Clone, Debug, PartialEq, Read, Write, NumBytes)]
struct DataRow {
    feed_index: u64,
    aggregate: DataVariant,
    points: Vec<ProviderPoint>,
}

#[derive(Clone)]
struct CachedContractRow<T> {
    payer: u64,
    packed_len: usize,
    value: T,
}

#[derive(Clone, Copy)]
pub(super) struct CachedActionMetadata {
    pub privileged: bool,
    pub code_hash: [u8; 32],
    pub code_sequence: u64,
    pub abi_sequence: u64,
}

/// Typed, block-local state for the hot bot/oracle rows. Keeping this cache in
/// the controller's `execute_block` frame makes rollback automatic: a rejected
/// block drops it, while canonical fallback first flushes it in deterministic
/// key order. It is never shared with normal VM execution.
#[derive(Clone, Default)]
pub(super) struct DirectBotOracleCache {
    bots: Vec<(u64, CachedContractRow<BotRow>)>,
    feeds: Vec<(u64, CachedContractRow<FeedRow>)>,
    data: Vec<(u64, CachedContractRow<DataRow>)>,
    admission: Option<((u64, u64, u64), CachedActionMetadata, CachedActionMetadata)>,
    permission_usages: Vec<(u64, u64)>,
}

impl DirectBotOracleCache {
    fn import_bot_from(
        &mut self,
        source: &Self,
        db: &Database,
        primary: u64,
    ) -> Result<(), ChainError> {
        if self.bots.iter().any(|(key, _)| *key == primary) {
            return Ok(());
        }
        if let Some((_, row)) = source.bots.iter().find(|(key, _)| *key == primary) {
            self.bots.push((primary, row.clone()));
        } else {
            self.bot(db, primary)?;
        }
        Ok(())
    }

    fn import_feed_from(
        &mut self,
        source: &Self,
        db: &Database,
        primary: u64,
    ) -> Result<(), ChainError> {
        if self.feeds.iter().any(|(key, _)| *key == primary) {
            return Ok(());
        }
        if let Some((_, row)) = source.feeds.iter().find(|(key, _)| *key == primary) {
            self.feeds.push((primary, row.clone()));
        } else {
            self.feed(db, primary)?;
        }
        Ok(())
    }

    fn import_data_from(
        &mut self,
        source: &Self,
        db: &Database,
        primary: u64,
    ) -> Result<(), ChainError> {
        if self.data.iter().any(|(key, _)| *key == primary) {
            return Ok(());
        }
        if let Some((_, row)) = source.data.iter().find(|(key, _)| *key == primary) {
            self.data.push((primary, row.clone()));
        } else {
            self.data(db, primary)?;
        }
        Ok(())
    }

    fn merge_rows(&mut self, working: Self) {
        for (primary, row) in working.bots {
            if let Some((_, current)) = self.bots.iter_mut().find(|(key, _)| *key == primary) {
                *current = row;
            } else {
                self.bots.push((primary, row));
            }
        }
        for (primary, row) in working.feeds {
            if let Some((_, current)) = self.feeds.iter_mut().find(|(key, _)| *key == primary) {
                *current = row;
            } else {
                self.feeds.push((primary, row));
            }
        }
        for (primary, row) in working.data {
            if let Some((_, current)) = self.data.iter_mut().find(|(key, _)| *key == primary) {
                *current = row;
            } else {
                self.data.push((primary, row));
            }
        }
    }

    fn bot(
        &mut self,
        db: &Database,
        primary: u64,
    ) -> Result<CachedContractRow<BotRow>, ChainError> {
        if let Some((_, row)) = self.bots.iter().find(|(key, _)| *key == primary) {
            return Ok(row.clone());
        }
        let (payer, packed) = db
            .arena_kv_row(BOT, BOT, BOTS, primary)
            .ok_or_else(|| ChainError::ApplyError("bot not found".into()))?;
        let row = CachedContractRow {
            payer,
            packed_len: packed.len(),
            value: read_exact(&packed, "bot row")?,
        };
        self.bots.push((primary, row.clone()));
        Ok(row)
    }

    fn feed(
        &mut self,
        db: &Database,
        primary: u64,
    ) -> Result<CachedContractRow<FeedRow>, ChainError> {
        if let Some((_, row)) = self.feeds.iter().find(|(key, _)| *key == primary) {
            return Ok(row.clone());
        }
        let (payer, packed) = db
            .arena_kv_row(ORACLES, ORACLES, FEEDS, primary)
            .ok_or_else(|| ChainError::ApplyError("feed not found".into()))?;
        let row = CachedContractRow {
            payer,
            packed_len: packed.len(),
            value: read_exact(&packed, "oracles feed row")?,
        };
        self.feeds.push((primary, row.clone()));
        Ok(row)
    }

    fn data(
        &mut self,
        db: &Database,
        primary: u64,
    ) -> Result<CachedContractRow<DataRow>, ChainError> {
        if let Some((_, row)) = self.data.iter().find(|(key, _)| *key == primary) {
            return Ok(row.clone());
        }
        let (payer, packed) = db
            .arena_kv_row(ORACLES, ORACLES, DATA, primary)
            .ok_or_else(|| ChainError::ApplyError("data not found".into()))?;
        let row = CachedContractRow {
            payer,
            packed_len: packed.len(),
            value: read_exact(&packed, "oracles data row")?,
        };
        self.data.push((primary, row.clone()));
        Ok(row)
    }

    fn replace_bot(&mut self, primary: u64, row: CachedContractRow<BotRow>) {
        self.bots
            .iter_mut()
            .find(|(key, _)| *key == primary)
            .expect("bot cache entry was loaded")
            .1 = row;
    }

    fn replace_feed(&mut self, primary: u64, row: CachedContractRow<FeedRow>) {
        self.feeds
            .iter_mut()
            .find(|(key, _)| *key == primary)
            .expect("feed cache entry was loaded")
            .1 = row;
    }

    fn replace_data(&mut self, primary: u64, row: CachedContractRow<DataRow>) {
        self.data
            .iter_mut()
            .find(|(key, _)| *key == primary)
            .expect("data cache entry was loaded")
            .1 = row;
    }

    pub(super) fn admission(
        &self,
        key: (u64, u64, u64),
    ) -> Option<(CachedActionMetadata, CachedActionMetadata)> {
        self.admission
            .filter(|(cached, _, _)| *cached == key)
            .map(|(_, parent, oracle)| (parent, oracle))
    }

    pub(super) fn cache_admission(
        &mut self,
        key: (u64, u64, u64),
        parent: CachedActionMetadata,
        oracle: CachedActionMetadata,
    ) {
        self.admission = Some((key, parent, oracle));
    }

    pub(super) fn record_permission_usage(&mut self, actor: u64, permission: u64) {
        if !self.permission_usages.contains(&(actor, permission)) {
            self.permission_usages.push((actor, permission));
        }
    }

    pub(super) fn flush(
        &mut self,
        db: &mut Database,
        pending: BlockTimestamp,
    ) -> Result<(), ChainError> {
        self.bots.sort_unstable_by_key(|(key, _)| *key);
        self.feeds.sort_unstable_by_key(|(key, _)| *key);
        self.data.sort_unstable_by_key(|(key, _)| *key);
        for (primary, row) in self.bots.drain(..) {
            db.xpr_native_update_key_value(BOT, BOT, BOTS, primary, row.payer, &row.value.pack()?)?;
        }
        for (primary, row) in self.feeds.drain(..) {
            db.xpr_native_update_key_value(
                ORACLES,
                ORACLES,
                FEEDS,
                primary,
                row.payer,
                &row.value.pack()?,
            )?;
        }
        for (primary, row) in self.data.drain(..) {
            db.xpr_native_update_key_value(
                ORACLES,
                ORACLES,
                DATA,
                primary,
                row.payer,
                &row.value.pack()?,
            )?;
        }
        let pending_time = pending.to_time_point();
        self.permission_usages.sort_unstable();
        for (actor, permission) in self.permission_usages.drain(..) {
            db.update_permission_usage(actor, permission, &pending_time)?;
        }
        self.admission = None;
        Ok(())
    }
}

fn serialized_length_delta(old: usize, new: usize) -> Result<i64, ChainError> {
    let old = i64::try_from(old)
        .map_err(|_| ChainError::InternalError("XPR row length exceeds i64".into()))?;
    let new = i64::try_from(new)
        .map_err(|_| ChainError::InternalError("XPR row length exceeds i64".into()))?;
    Ok(new - old)
}

fn enforce_same_provider_limit(points: &mut Vec<ProviderPoint>, limit: u64) {
    let mut point_counts: Vec<(u64, u8)> = Vec::new();
    let mut index = 0;
    while index < points.len() {
        let provider = points[index].provider;
        let count = if let Some(position) = point_counts
            .iter()
            .position(|(candidate, _)| *candidate == provider)
        {
            &mut point_counts[position].1
        } else {
            point_counts.push((provider, 0));
            &mut point_counts.last_mut().unwrap().1
        };
        *count = count.wrapping_add(1);
        if u64::from(*count) > limit {
            points.remove(index);
        }
        index += 1;
    }
}

fn read_exact<T: SerializationRead>(bytes: &[u8], label: &str) -> Result<T, ChainError> {
    let mut pos = 0;
    let value = T::read(bytes, &mut pos)?;
    if pos != bytes.len() {
        return Err(ChainError::SerializationError(format!(
            "XPR native {label} has {} trailing bytes",
            bytes.len() - pos
        )));
    }
    Ok(value)
}

/// Apply an exact historical contract transition without entering Wasmer.
/// `None` means the canonical WASM path must run.
pub(super) fn try_apply(
    context: &mut ApplyContext,
    action: &Action,
    code_hash: &[u8; 32],
) -> Result<Option<u64>, ChainError> {
    if !context.xpr_native_replay_enabled() || !context.is_explicitly_billed()? {
        return Ok(None);
    }

    let applied = if is_supported_system_code_hash(code_hash)
        && context.receiver().as_u64() == EOSIO
        && action.account().as_u64() == EOSIO
        && action.name().as_u64() == ONBLOCK
        && context.is_implicit()?
    {
        apply_system_onblock(context, action)?
    } else if is_supported_bot_code_hash(code_hash)
        && context.receiver().as_u64() == BOT
        && action.account().as_u64() == BOT
        && action.name().as_u64() == PROCESS
    {
        apply_bot_process(context, action, bot_uses_v2_layout(code_hash))?;
        true
    } else if is_supported_oracle_code_hash(code_hash)
        && context.receiver().as_u64() == ORACLES
        && action.account().as_u64() == ORACLES
        && action.name().as_u64() == FEED
    {
        apply_oracles_feed(
            context,
            action,
            oracle_uses_v2_layout(code_hash),
            oracle_supports_mean_median(code_hash),
        )?
    } else if *code_hash == XPR_MECHANICS_CODE_HASH
        && context.receiver().as_u64() == MECHANICS
        && action.account().as_u64() == MECHANICS
        && action.name().as_u64() == CPU
        && action.data().is_empty()
    {
        context.require_authorization(&Name::new(MECHANICS), None)?;
        true
    } else {
        false
    };
    if !applied {
        // A deployed-WASM fallback must observe every native transition that
        // preceded it in this block. Materialize the coalesced overlay before
        // handing control to Wasmer.
        context.flush_xpr_native_rows()?;
        return Ok(None);
    }

    // Accepted-block migration replay uses the producer-recorded CPU bill.
    // Native work therefore contributes no synthetic WASM points here.
    Ok(Some(0))
}

/// Execute the common pinned XPR `eosio::onblock` transition without building
/// an implicit transaction/action-trace graph. The controller still constructs
/// and hashes the canonical action receipt and falls back to the full path at
/// every election/reward boundary or layout mismatch.
pub(super) fn try_apply_system_onblock_direct(
    db: &mut Database,
    pending: BlockTimestamp,
    action: &Action,
    code_hash: &[u8; 32],
) -> Result<bool, ChainError> {
    if !db.xpr_native_replay_enabled()
        || !is_supported_system_code_hash(code_hash)
        || action.account().as_u64() != EOSIO
        || action.name().as_u64() != ONBLOCK
        || action.authorization().len() != 1
        || action.authorization()[0].actor != EOSIO
        || action.authorization()[0].permission != ACTIVE_NAME.as_u64()
    {
        return Ok(false);
    }
    apply_system_onblock(&mut DirectSystemOnblockContext { db, pending }, action)
}

const GLOBAL_LAST_SCHEDULE_OFFSET: usize = 92;
const GLOBAL_LAST_PERVOTE_FILL_OFFSET: usize = 96;
const GLOBAL_TOTAL_UNPAID_OFFSET: usize = 120;
const GLOBAL_ACTIVATION_TIME_OFFSET: usize = 132;
const GLOBAL_ROW_SIZE: usize = 154;
const GLOBAL2_LAST_BLOCK_OFFSET: usize = 6;
const GLOBAL2_ROW_SIZE: usize = 19;
const GLOBAL3_ROW_SIZE: usize = 16;
const GLOBAL4_ROW_SIZE: usize = 24;
const GLOBALSXPR_PROCESS_INTERVAL_OFFSET: usize = 32;
const GLOBALSXPR_ROW_SIZE: usize = 64;
const GLOBALSD_PROCESS_TIME_OFFSET: usize = 40;
const GLOBALSD_PROCESS_TIME_UPDATE_OFFSET: usize = 48;
const GLOBALSD_IS_PROCESSING_OFFSET: usize = 56;
const GLOBALSD_ROW_SIZE: usize = 105;

trait BotOracleContext {
    fn transaction_id(&self) -> [u8; 32];
    fn pending_block_timestamp(&self) -> BlockTimestamp;
    fn contract_row(
        &self,
        code: u64,
        table: u64,
        primary: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, ChainError>;
    fn require_authorization(&self, action: &Action, account: u64) -> Result<(), ChainError>;
    fn execute_inline(&mut self, action: Action) -> Result<(), ChainError>;
    fn update_contract_row(
        &mut self,
        code: u64,
        table: u64,
        primary: u64,
        old_payer: u64,
        old_value_len: usize,
        payer: u64,
        value: Vec<u8>,
    ) -> Result<(), ChainError>;
}

impl BotOracleContext for ApplyContext {
    fn transaction_id(&self) -> [u8; 32] {
        self.get_packed_transaction().id().0.0
    }

    fn pending_block_timestamp(&self) -> BlockTimestamp {
        *self.pending_block_timestamp()
    }

    fn contract_row(
        &self,
        code: u64,
        table: u64,
        primary: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, ChainError> {
        self.xpr_native_kv_row(code, code, table, primary)
    }

    fn require_authorization(&self, _action: &Action, account: u64) -> Result<(), ChainError> {
        self.require_authorization(&Name::new(account), None)
    }

    fn execute_inline(&mut self, action: Action) -> Result<(), ChainError> {
        self.execute_inline(&action)
    }

    fn update_contract_row(
        &mut self,
        code: u64,
        table: u64,
        primary: u64,
        old_payer: u64,
        old_value_len: usize,
        payer: u64,
        value: Vec<u8>,
    ) -> Result<(), ChainError> {
        self.xpr_native_update_kv(
            code,
            code,
            table,
            primary,
            old_payer,
            old_value_len,
            payer,
            value,
        )
    }
}

struct DirectBotOracleContext<'a> {
    db: &'a mut Database,
    pending: BlockTimestamp,
    transaction_id: [u8; 32],
    inline_actions: Vec<Action>,
    ram_deltas: Vec<(u64, i64)>,
}

impl BotOracleContext for DirectBotOracleContext<'_> {
    fn transaction_id(&self) -> [u8; 32] {
        self.transaction_id
    }

    fn pending_block_timestamp(&self) -> BlockTimestamp {
        self.pending
    }

    fn contract_row(
        &self,
        code: u64,
        table: u64,
        primary: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, ChainError> {
        Ok(self.db.arena_kv_row(code, code, table, primary))
    }

    fn require_authorization(&self, action: &Action, account: u64) -> Result<(), ChainError> {
        if action
            .authorization()
            .iter()
            .any(|authorization| authorization.actor == account)
        {
            Ok(())
        } else {
            Err(ChainError::MissingAuthError(format!(
                "missing authority of {}",
                Name::new(account)
            )))
        }
    }

    fn execute_inline(&mut self, action: Action) -> Result<(), ChainError> {
        self.inline_actions.push(action);
        Ok(())
    }

    fn update_contract_row(
        &mut self,
        code: u64,
        table: u64,
        primary: u64,
        old_payer: u64,
        old_value_len: usize,
        payer: u64,
        value: Vec<u8>,
    ) -> Result<(), ChainError> {
        let new_payer = if payer == 0 { old_payer } else { payer };
        if old_payer != code || new_payer != code {
            return Err(ChainError::ApplyError(
                "direct XPR bot/oracle path requires receiver-paid rows".into(),
            ));
        }
        self.db
            .xpr_native_update_key_value(code, code, table, primary, new_payer, &value)?;
        let overhead = billable_size_v::<KeyValueObject>() as i64;
        let old_size = i64::try_from(old_value_len)
            .map_err(|_| ChainError::InternalError("XPR row length exceeds i64".into()))?
            + overhead;
        let new_size = i64::try_from(value.len())
            .map_err(|_| ChainError::InternalError("XPR row length exceeds i64".into()))?
            + overhead;
        if old_size != new_size {
            self.ram_deltas.push((code, new_size - old_size));
        }
        Ok(())
    }
}

pub(super) struct DirectBotOracleResult {
    pub inline_actions: Vec<Action>,
    pub ram_deltas: Vec<(u64, i64)>,
    pub profile: super::replay_profile::NativeBotTiming,
}

/// Execute the code-hash-pinned bot/oracle pair without allocating the nested
/// ApplyContext graph. The caller remains responsible for inline authorization,
/// action receipts/sequences, resource billing, and an undo session on decline.
pub(super) fn try_apply_bot_transaction_direct(
    db: &mut Database,
    pending: BlockTimestamp,
    transaction_id: [u8; 32],
    action: &Action,
    bot_code_hash: &[u8; 32],
    oracle_code_hash: &[u8; 32],
) -> Result<Option<DirectBotOracleResult>, ChainError> {
    let bot_v2 = bot_uses_v2_layout(bot_code_hash);
    let bot_supported = is_supported_bot_code_hash(bot_code_hash);
    let oracle_v2 = oracle_uses_v2_layout(oracle_code_hash);
    let oracle_mean_median = oracle_supports_mean_median(oracle_code_hash);
    let oracle_supported = is_supported_oracle_code_hash(oracle_code_hash);
    if !db.xpr_native_replay_enabled()
        || !bot_supported
        || !oracle_supported
        || action.account().as_u64() != BOT
        || action.name().as_u64() != PROCESS
    {
        super::replay_profile::record_native_decline("unsupported_code_or_action");
        super::replay_profile::record_native_code_decline(*bot_code_hash, *oracle_code_hash);
        return Ok(None);
    }

    let mut context = DirectBotOracleContext {
        db,
        pending,
        transaction_id,
        inline_actions: Vec::new(),
        ram_deltas: Vec::with_capacity(2),
    };
    apply_bot_process(&mut context, action, bot_v2)?;
    let inline_actions = context.inline_actions.clone();
    for inline in &inline_actions {
        if inline.account().as_u64() != ORACLES
            || inline.name().as_u64() != FEED
            || !apply_oracles_feed(&mut context, inline, oracle_v2, oracle_mean_median)?
        {
            return Ok(None);
        }
    }
    Ok(Some(DirectBotOracleResult {
        inline_actions: context.inline_actions,
        ram_deltas: context.ram_deltas,
        profile: super::replay_profile::NativeBotTiming::default(),
    }))
}

/// Block-batched variant of the direct bot/oracle transition. Rows remain as
/// decoded Rust values across consecutive pinned transactions and are encoded
/// once at the canonical fallback or block boundary. A private cache clone is
/// promoted only after the complete transition succeeds, so `None` is a true
/// no-mutation decline just like the ordinary direct path's undo layer.
pub(super) fn try_apply_bot_transaction_direct_cached(
    db: &Database,
    cache: &mut DirectBotOracleCache,
    pending: BlockTimestamp,
    transaction_id: [u8; 32],
    action: &Action,
    bot_code_hash: &[u8; 32],
    oracle_code_hash: &[u8; 32],
) -> Result<Option<DirectBotOracleResult>, ChainError> {
    let profiling = super::replay_profile::enabled();
    let mut profile = super::replay_profile::NativeBotTiming::default();
    let decode_started = profiling.then(Instant::now);
    let bot_v2 = bot_uses_v2_layout(bot_code_hash);
    let bot_supported = is_supported_bot_code_hash(bot_code_hash);
    let oracle_v2 = oracle_uses_v2_layout(oracle_code_hash);
    let oracle_mean_median = oracle_supports_mean_median(oracle_code_hash);
    let oracle_supported = is_supported_oracle_code_hash(oracle_code_hash);
    if !db.xpr_native_replay_enabled()
        || !bot_supported
        || !oracle_supported
        || action.account().as_u64() != BOT
        || action.name().as_u64() != PROCESS
    {
        return Ok(None);
    }

    let action_data = action.data();
    let (account, entries, oracle_index) = if bot_v2 {
        let process: ProcessV2 = match read_exact(action_data.as_ref(), "bot::process v2 action") {
            Ok(process) => process,
            Err(_) => {
                super::replay_profile::record_native_decline("process_v2_decode");
                return Ok(None);
            }
        };
        (process.account, process.entries, Some(process.oracle_index))
    } else {
        let process: Process = match read_exact(action_data.as_ref(), "bot::process action") {
            Ok(process) => process,
            Err(_) => {
                super::replay_profile::record_native_decline("process_v1_decode");
                return Ok(None);
            }
        };
        (process.account, process.entries, None)
    };
    if !action
        .authorization()
        .iter()
        .any(|authorization| authorization.actor == account)
    {
        return Err(ChainError::MissingAuthError(format!(
            "missing authority of {}",
            Name::new(account)
        )));
    }
    profile.decode = decode_started.map_or(Duration::ZERO, |started| started.elapsed());

    let clone_started = profiling.then(Instant::now);
    // Clone only rows this transaction can touch. A decline drops this private
    // working set, while success merges it into the block cache. This retains
    // the no-mutation-on-decline guarantee without repeatedly copying every
    // hot row accumulated earlier in a large block.
    let mut working = DirectBotOracleCache::default();
    for entry in &entries {
        working.import_bot_from(cache, db, entry.bot_index)?;
    }
    profile.cache_clone = clone_started.map_or(Duration::ZERO, |started| started.elapsed());
    let mut inline_actions = Vec::with_capacity(entries.len());
    let mut ram_deltas = Vec::with_capacity(entries.len() * 3);
    let now = pending.to_time_point().time_since_epoch().count();
    let utc_hour = ((now / 1_000_000) % 86_400 / 3_600) as u8;
    let utc_hour_to_erase = (utc_hour + 1) % 24;
    let bot_rows_started = profiling.then(Instant::now);
    for entry in entries {
        let mut cached_bot = working.bot(db, entry.bot_index)?;
        if cached_bot.payer != BOT {
            return Err(ChainError::ApplyError(
                "direct XPR bot/oracle path requires receiver-paid rows".into(),
            ));
        }
        let bot = &mut cached_bot.value;
        if account != bot.account {
            return Err(ChainError::ApplyError("account mismatch".into()));
        }
        let feed_index = oracle_index.unwrap_or(bot.feed_index);
        let feed_action = FeedActionData {
            account,
            feed_index,
            data: entry.data.clone(),
        };
        inline_actions.push(Action::new(
            Name::new(bot.oracle_contract),
            Name::new(FEED),
            feed_action.pack()?,
            vec![PermissionLevel::new(account, ACTIVE_NAME.as_u64())],
        ));

        let count = bot.tx_count_by_utc_hour.entry(utc_hour).or_insert(0);
        *count = count.wrapping_add(1);
        bot.tx_count_by_utc_hour.insert(utc_hour_to_erase, 0);
        bot.history.insert(
            0,
            Tx {
                id: Digest(transaction_id),
                time: now,
                data: entry.data,
            },
        );
        if bot.history.len() > usize::from(bot.max_history) {
            bot.history.pop();
        }
        let new_len = bot.num_bytes();
        if new_len != cached_bot.packed_len {
            ram_deltas.push((
                BOT,
                serialized_length_delta(cached_bot.packed_len, new_len)?,
            ));
        }
        cached_bot.packed_len = new_len;
        working.replace_bot(entry.bot_index, cached_bot);
    }
    profile.bot_rows = bot_rows_started.map_or(Duration::ZERO, |started| started.elapsed());

    // Leap schedules every inline action while executing bot::process, then
    // executes those ordinals in order after the parent returns. Keep that
    // two-phase ordering even though the rows are held as typed values.
    let oracle_rows_started = profiling.then(Instant::now);
    for inline in &inline_actions {
        if inline.account().as_u64() != ORACLES || inline.name().as_u64() != FEED {
            super::replay_profile::record_native_decline("inline_action_shape");
            return Ok(None);
        }
        let feed_action: FeedActionData =
            match read_exact(inline.data().as_ref(), "oracles::feed action") {
                Ok(action) => action,
                Err(_) => {
                    super::replay_profile::record_native_decline("feed_decode");
                    return Ok(None);
                }
            };
        let feed_index = feed_action.feed_index;
        working.import_feed_from(cache, db, feed_index)?;
        working.import_data_from(cache, db, feed_index)?;
        let mut cached_feed = working.feed(db, feed_index)?;
        let mut cached_data = working.data(db, feed_index)?;
        if cached_feed.payer != ORACLES || cached_data.payer != ORACLES {
            return Err(ChainError::ApplyError(
                "direct XPR bot/oracle path requires receiver-paid rows".into(),
            ));
        }
        let feed = &mut cached_feed.value;
        if !update_oracle_feed(
            feed,
            &mut cached_data.value,
            &feed_action,
            now,
            oracle_v2,
            oracle_mean_median,
        )? {
            super::replay_profile::record_native_decline("feed_configuration");
            return Ok(None);
        }

        let new_data_len = cached_data.value.num_bytes();
        if new_data_len != cached_data.packed_len {
            ram_deltas.push((
                ORACLES,
                serialized_length_delta(cached_data.packed_len, new_data_len)?,
            ));
        }
        cached_data.packed_len = new_data_len;
        working.replace_data(feed_index, cached_data);

        let new_feed_len = feed.num_bytes();
        if new_feed_len != cached_feed.packed_len {
            ram_deltas.push((
                ORACLES,
                serialized_length_delta(cached_feed.packed_len, new_feed_len)?,
            ));
        }
        cached_feed.packed_len = new_feed_len;
        working.replace_feed(feed_index, cached_feed);
    }
    profile.oracle_rows = oracle_rows_started.map_or(Duration::ZERO, |started| started.elapsed());

    let commit_started = profiling.then(Instant::now);
    cache.merge_rows(working);
    profile.cache_commit = commit_started.map_or(Duration::ZERO, |started| started.elapsed());
    Ok(Some(DirectBotOracleResult {
        inline_actions,
        ram_deltas,
        profile,
    }))
}

fn read_contract_row(
    context: &impl BotOracleContext,
    code: u64,
    table: u64,
    primary: u64,
) -> Result<Option<(u64, Vec<u8>)>, ChainError> {
    context.contract_row(code, table, primary)
}

trait SystemOnblockContext {
    fn pending_block_timestamp(&self) -> BlockTimestamp;
    fn contract_row(&self, table: u64, primary: u64) -> Result<Option<(u64, Vec<u8>)>, ChainError>;
    fn require_system_authorization(&mut self) -> Result<(), ChainError>;
    fn update_contract_row(
        &mut self,
        table: u64,
        primary: u64,
        old_payer: u64,
        old_value_len: usize,
        payer: u64,
        value: Vec<u8>,
    ) -> Result<(), ChainError>;
}

impl SystemOnblockContext for ApplyContext {
    fn pending_block_timestamp(&self) -> BlockTimestamp {
        *self.pending_block_timestamp()
    }

    fn contract_row(&self, table: u64, primary: u64) -> Result<Option<(u64, Vec<u8>)>, ChainError> {
        read_contract_row(self, EOSIO, table, primary)
    }

    fn require_system_authorization(&mut self) -> Result<(), ChainError> {
        self.require_authorization(&Name::new(EOSIO), None)
    }

    fn update_contract_row(
        &mut self,
        table: u64,
        primary: u64,
        old_payer: u64,
        old_value_len: usize,
        payer: u64,
        value: Vec<u8>,
    ) -> Result<(), ChainError> {
        self.xpr_native_update_kv(
            EOSIO,
            EOSIO,
            table,
            primary,
            old_payer,
            old_value_len,
            payer,
            value,
        )
    }
}

struct DirectSystemOnblockContext<'a> {
    db: &'a mut Database,
    pending: BlockTimestamp,
}

impl SystemOnblockContext for DirectSystemOnblockContext<'_> {
    fn pending_block_timestamp(&self) -> BlockTimestamp {
        self.pending
    }

    fn contract_row(&self, table: u64, primary: u64) -> Result<Option<(u64, Vec<u8>)>, ChainError> {
        Ok(self.db.arena_kv_row(EOSIO, EOSIO, table, primary))
    }

    fn require_system_authorization(&mut self) -> Result<(), ChainError> {
        Ok(())
    }

    fn update_contract_row(
        &mut self,
        table: u64,
        primary: u64,
        old_payer: u64,
        old_value_len: usize,
        payer: u64,
        value: Vec<u8>,
    ) -> Result<(), ChainError> {
        let new_payer = if payer == 0 { old_payer } else { payer };
        self.db
            .xpr_native_update_key_value(EOSIO, EOSIO, table, primary, new_payer, &value)?;
        let overhead = billable_size_v::<KeyValueObject>() as i64;
        let old_size = i64::try_from(old_value_len)
            .map_err(|_| ChainError::InternalError("XPR row length exceeds i64".into()))?
            + overhead;
        let new_size = i64::try_from(value.len())
            .map_err(|_| ChainError::InternalError("XPR row length exceeds i64".into()))?
            + overhead;
        if old_payer != new_payer {
            self.db.add_pending_ram_usage(old_payer, -old_size)?;
            self.db.add_pending_ram_usage(new_payer, new_size)?;
        } else if old_size != new_size {
            self.db
                .add_pending_ram_usage(new_payer, new_size - old_size)?;
        }
        Ok(())
    }
}

fn get_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn get_i64(bytes: &[u8], offset: usize) -> Option<i64> {
    Some(i64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn get_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Option<()> {
    bytes
        .get_mut(offset..offset + 4)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

fn put_i64(bytes: &mut [u8], offset: usize, value: i64) -> Option<()> {
    bytes
        .get_mut(offset..offset + 8)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

fn producer_unpaid_offset(row: &[u8]) -> Option<usize> {
    // owner + total_votes + variant-tagged K1/R1 public key + is_active.
    let mut pos = 16;
    let key_variant = *row.get(pos)?;
    if key_variant > 1 {
        return None;
    }
    pos += 1 + 33 + 1;

    // The historical URL length is a canonical varuint32.
    let mut url_len = 0usize;
    let mut shift = 0u32;
    loop {
        let byte = *row.get(pos)?;
        pos += 1;
        url_len |= usize::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 32 {
            return None;
        }
    }
    pos = pos.checked_add(url_len)?;
    row.get(pos..pos + 4)?;
    Some(pos)
}

/// Fast path for the common block in the pinned 2020 XPR system contract.
/// Minute-boundary producer-election work and due voter-reward batches fall
/// back to the canonical WASM. The remaining path performs exactly onblock's
/// timestamp and unpaid-block mutations without paying its per-block ABI and
/// singleton serialization overhead.
fn apply_system_onblock<C: SystemOnblockContext>(
    context: &mut C,
    action: &Action,
) -> Result<bool, ChainError> {
    let action_data = action.data();
    let data = action_data.as_ref();
    let Some(action_slot) = get_u32(data, 0) else {
        return Ok(false);
    };
    let Some(producer) = data
        .get(4..12)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
    else {
        return Ok(false);
    };
    let pending = context.pending_block_timestamp();
    // Antelope's implicit onblock payload is the parent header while
    // current_time_point observes the block being applied. Reject a malformed
    // or non-parent-like payload rather than interpreting it natively.
    if action_slot >= pending.slot() {
        return Ok(false);
    }

    let Some((global_payer, mut global)) = context.contract_row(GLOBAL, GLOBAL)? else {
        return Ok(false);
    };
    let Some((global2_payer, mut global2)) = context.contract_row(GLOBAL2, GLOBAL2)? else {
        return Ok(false);
    };
    let Some((global3_payer, global3)) = context.contract_row(GLOBAL3, GLOBAL3)? else {
        return Ok(false);
    };
    let Some((global4_payer, global4)) = context.contract_row(GLOBAL4, GLOBAL4)? else {
        return Ok(false);
    };
    let Some((globalsxpr_payer, globalsxpr)) = context.contract_row(GLOBALSXPR, GLOBALSXPR)? else {
        return Ok(false);
    };
    let Some((globalsd_payer, globalsd)) = context.contract_row(GLOBALSD, GLOBALSD)? else {
        return Ok(false);
    };
    if global.len() != GLOBAL_ROW_SIZE
        || global2.len() != GLOBAL2_ROW_SIZE
        || global3.len() != GLOBAL3_ROW_SIZE
        || global4.len() != GLOBAL4_ROW_SIZE
        || globalsxpr.len() != GLOBALSXPR_ROW_SIZE
        || globalsd.len() != GLOBALSD_ROW_SIZE
    {
        return Ok(false);
    }

    let Some(activation_time) = get_i64(&global, GLOBAL_ACTIVATION_TIME_OFFSET) else {
        return Ok(false);
    };
    let mut producer_row = None;
    if activation_time != 0 {
        let Some(last_schedule) = get_u32(&global, GLOBAL_LAST_SCHEDULE_OFFSET) else {
            return Ok(false);
        };
        if action_slot.wrapping_sub(last_schedule) > 120 {
            return Ok(false);
        }

        let now = pending.to_time_point().time_since_epoch().count() / 1_000_000;
        let is_processing = globalsd[GLOBALSD_IS_PROCESSING_OFFSET] != 0;
        let sharing_due = if is_processing {
            let Some(updated) = get_i64(&globalsd, GLOBALSD_PROCESS_TIME_UPDATE_OFFSET) else {
                return Ok(false);
            };
            let Some(elapsed) = now.checked_sub(updated) else {
                return Ok(false);
            };
            elapsed > 0
        } else {
            let Some(started) = get_i64(&globalsd, GLOBALSD_PROCESS_TIME_OFFSET) else {
                return Ok(false);
            };
            let Some(interval) = get_u64(&globalsxpr, GLOBALSXPR_PROCESS_INTERVAL_OFFSET) else {
                return Ok(false);
            };
            let Some(elapsed) = now
                .checked_sub(started)
                .and_then(|value| u64::try_from(value).ok())
            else {
                return Ok(false);
            };
            elapsed >= interval
        };
        if sharing_due {
            return Ok(false);
        }

        if let Some((payer, mut row)) = context.contract_row(PRODUCERS, producer)? {
            let Some(unpaid_offset) = producer_unpaid_offset(&row) else {
                return Ok(false);
            };
            let Some(unpaid) = get_u32(&row, unpaid_offset) else {
                return Ok(false);
            };
            put_u32(&mut row, unpaid_offset, unpaid.wrapping_add(1)).unwrap();
            producer_row = Some((payer, row));
        }
    }

    context.require_system_authorization()?;
    put_u32(&mut global2, GLOBAL2_LAST_BLOCK_OFFSET, action_slot).unwrap();
    if activation_time != 0 {
        if get_i64(&global, GLOBAL_LAST_PERVOTE_FILL_OFFSET) == Some(0) {
            put_i64(
                &mut global,
                GLOBAL_LAST_PERVOTE_FILL_OFFSET,
                pending.to_time_point().time_since_epoch().count(),
            )
            .unwrap();
        }
        if producer_row.is_some() {
            let unpaid = get_u32(&global, GLOBAL_TOTAL_UNPAID_OFFSET).unwrap();
            put_u32(
                &mut global,
                GLOBAL_TOTAL_UNPAID_OFFSET,
                unpaid.wrapping_add(1),
            )
            .unwrap();
        }
    }

    // Match the contract's mutation order: the producer row is changed in the
    // action body, then all six singleton rows are written by its destructor.
    // Rewriting unchanged singleton bytes is intentional because SHiP exposes
    // the touched-row set as well as the resulting state.
    if let Some((payer, row)) = producer_row {
        context.update_contract_row(PRODUCERS, producer, payer, row.len(), 0, row)?;
    }
    context.update_contract_row(GLOBAL, GLOBAL, global_payer, global.len(), EOSIO, global)?;
    context.update_contract_row(
        GLOBAL2,
        GLOBAL2,
        global2_payer,
        global2.len(),
        EOSIO,
        global2,
    )?;
    // The deployed singleton destructors rewrite all rows, but with SHiP
    // deliberately disabled those writes have no observable effect when both
    // bytes and payer are already canonical. Avoid routing four unchanged rows
    // through the replay overlay on every ordinary block; a non-canonical payer
    // still takes the exact billed update path.
    if global3_payer != EOSIO {
        context.update_contract_row(
            GLOBAL3,
            GLOBAL3,
            global3_payer,
            global3.len(),
            EOSIO,
            global3,
        )?;
    }
    if global4_payer != EOSIO {
        context.update_contract_row(
            GLOBAL4,
            GLOBAL4,
            global4_payer,
            global4.len(),
            EOSIO,
            global4,
        )?;
    }
    if globalsxpr_payer != EOSIO {
        context.update_contract_row(
            GLOBALSXPR,
            GLOBALSXPR,
            globalsxpr_payer,
            globalsxpr.len(),
            EOSIO,
            globalsxpr,
        )?;
    }
    if globalsd_payer != EOSIO {
        context.update_contract_row(
            GLOBALSD,
            GLOBALSD,
            globalsd_payer,
            globalsd.len(),
            EOSIO,
            globalsd,
        )?;
    }
    Ok(true)
}

fn apply_oracles_feed(
    context: &mut impl BotOracleContext,
    action: &Action,
    v2: bool,
    mean_median: bool,
) -> Result<bool, ChainError> {
    let feed_action: FeedActionData =
        match read_exact(action.data().as_ref(), "oracles::feed action") {
            Ok(action) => action,
            Err(_) => return Ok(false),
        };
    let Some((feed_payer, packed_feed)) =
        read_contract_row(context, ORACLES, FEEDS, feed_action.feed_index)?
    else {
        return Err(ChainError::ApplyError("feed not found".into()));
    };
    let Some((data_payer, packed_data)) =
        read_contract_row(context, ORACLES, DATA, feed_action.feed_index)?
    else {
        return Err(ChainError::ApplyError("data not found".into()));
    };
    let mut feed: FeedRow = read_exact(&packed_feed, "oracles feed row")?;

    context.require_authorization(action, feed_action.account)?;

    let mut data: DataRow = read_exact(&packed_data, "oracles data row")?;
    let now = context
        .pending_block_timestamp()
        .to_time_point()
        .time_since_epoch()
        .count();
    if !update_oracle_feed(&mut feed, &mut data, &feed_action, now, v2, mean_median)? {
        return Ok(false);
    }

    context.update_contract_row(
        ORACLES,
        DATA,
        feed_action.feed_index,
        data_payer,
        packed_data.len(),
        ORACLES,
        data.pack()?,
    )?;
    context.update_contract_row(
        ORACLES,
        FEEDS,
        feed_action.feed_index,
        feed_payer,
        packed_feed.len(),
        ORACLES,
        feed.pack()?,
    )?;
    Ok(true)
}

fn update_oracle_feed(
    feed: &mut FeedRow,
    data: &mut DataRow,
    action: &FeedActionData,
    now: i64,
    v2: bool,
    mean_median: bool,
) -> Result<bool, ChainError> {
    let same_provider_limit = feed
        .config
        .get("data_same_provider_limit")
        .copied()
        .unwrap_or(0);
    let window_size = feed.config.get("data_window_size").copied().unwrap_or(0);
    let freshness_sec = feed.config.get("data_freshness_sec").copied().unwrap_or(0);
    let min_wait_sec = feed
        .config
        .get("min_provider_wait_sec")
        .copied()
        .unwrap_or(0);
    let supported_aggregate = feed.aggregate_function == "mean"
        || (mean_median && feed.aggregate_function == "mean_median");
    let legacy_shape = window_size == 20 && freshness_sec == 0 && min_wait_sec == 0;
    let supported = supported_aggregate
        && feed.data_type == "double"
        && (mean_median || legacy_shape)
        // The pinned v2 source fixed the provider-limit loop's upper bound.
        // The older binary is safe only when the loop is disabled.
        && (same_provider_limit == 0 || (v2 && same_provider_limit <= u64::from(u8::MAX)))
        && action.data.d_string.is_none()
        && action.data.d_uint64.is_none()
        && action.data.d_double.is_some();
    if !supported {
        return Ok(false);
    }

    let Some(last_update) = feed.providers.get(&action.account).copied() else {
        return Err(ChainError::ApplyError("not a registered provider".into()));
    };
    if min_wait_sec > 0 {
        let seconds_ago = now.div_euclid(1_000_000) - last_update.div_euclid(1_000_000);
        if seconds_ago < 0 || (seconds_ago as u64) < min_wait_sec {
            return Err(ChainError::ApplyError(
                "wait time too short between inserting data".into(),
            ));
        }
    }

    data.points.insert(
        0,
        ProviderPoint {
            provider: action.account,
            time: now,
            data: action.data.clone(),
        },
    );
    while data.points.last().is_some_and(|point| {
        (window_size > 0 && data.points.len() as u64 > window_size)
            || (freshness_sec > 0
                && (now.div_euclid(1_000_000) - point.time.div_euclid(1_000_000))
                    > freshness_sec as i64)
    }) {
        data.points.pop();
    }
    if same_provider_limit > 0 {
        // Reproduce the deployed C++ for-loop exactly: after erasing an
        // over-limit point, the loop increments and therefore skips the point
        // that shifted into the erased index.
        enforce_same_provider_limit(&mut data.points, same_provider_limit);
    }

    let aggregate = if feed.aggregate_function == "mean" {
        mean_double(&data.points)
    } else {
        mean_median_double(&data.points)
    };
    let Some(aggregate) = aggregate else {
        return Ok(false);
    };
    data.aggregate = DataVariant {
        d_string: None,
        d_uint64: None,
        d_double: Some(aggregate),
    };
    feed.providers.insert(action.account, now);
    Ok(true)
}

fn mean_double(points: &[ProviderPoint]) -> Option<f64> {
    let mut total = 0.0;
    for point in points {
        let Some(value) = point.data.d_double else {
            return None;
        };
        if !value.is_finite() {
            return None;
        }
        total += value;
    }
    Some(total / points.len() as f64)
}

fn mean_median_double(points: &[ProviderPoint]) -> Option<f64> {
    let mut by_provider: CanonicalMap<u64, Vec<ProviderPoint>> = CanonicalMap::new();
    for point in points {
        by_provider
            .entry(point.provider)
            .or_default()
            .push(point.clone());
    }
    let mut means = Vec::with_capacity(by_provider.len());
    for provider_points in by_provider.values() {
        let Some(mean) = mean_double(provider_points) else {
            return None;
        };
        means.push(mean);
    }
    means.sort_by(|left, right| left.total_cmp(right));
    let middle = means.len() / 2;
    let median = if means.len() % 2 == 0 {
        (means[middle - 1] + means[middle]) / 2.0
    } else {
        means[middle]
    };
    Some(median)
}

fn apply_bot_process(
    context: &mut impl BotOracleContext,
    action: &Action,
    v2: bool,
) -> Result<(), ChainError> {
    let action_data = action.data();
    let (account, entries, oracle_index) = if v2 {
        let process: ProcessV2 = read_exact(action_data.as_ref(), "bot::process v2 action")?;
        (process.account, process.entries, Some(process.oracle_index))
    } else {
        let process: Process = read_exact(action_data.as_ref(), "bot::process action")?;
        (process.account, process.entries, None)
    };
    let transaction_id = context.transaction_id();
    let now = context
        .pending_block_timestamp()
        .to_time_point()
        .time_since_epoch()
        .count();
    let utc_hour = ((now / 1_000_000) % 86_400 / 3_600) as u8;
    let utc_hour_to_erase = (utc_hour + 1) % 24;

    for entry in entries {
        let Some((payer, packed_row)) = read_contract_row(context, BOT, BOTS, entry.bot_index)?
        else {
            return Err(ChainError::ApplyError("bot not found".into()));
        };
        let mut bot: BotRow = read_exact(&packed_row, "bot row")?;
        if account != bot.account {
            return Err(ChainError::ApplyError("account mismatch".into()));
        }

        let feed_data = FeedActionData {
            account,
            feed_index: oracle_index.unwrap_or(bot.feed_index),
            data: entry.data.clone(),
        }
        .pack()?;
        context.execute_inline(Action::new(
            Name::new(bot.oracle_contract),
            Name::new(FEED),
            feed_data,
            vec![PermissionLevel::new(account, ACTIVE_NAME.as_u64())],
        ))?;

        let count = bot.tx_count_by_utc_hour.entry(utc_hour).or_insert(0);
        *count = count.wrapping_add(1);
        bot.tx_count_by_utc_hour.insert(utc_hour_to_erase, 0);
        bot.history.insert(
            0,
            Tx {
                id: Digest(transaction_id),
                time: now,
                data: entry.data,
            },
        );
        if bot.history.len() > usize::from(bot.max_history) {
            bot.history.pop();
        }
        context.update_contract_row(
            BOT,
            BOTS,
            entry.bot_index,
            payer,
            packed_row.len(),
            BOT,
            bot.pack()?,
        )?;
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Read, Write, NumBytes)]
struct FeedActionData {
    account: u64,
    feed_index: u64,
    data: DataVariant,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn audited_oracle_v7_uses_the_existing_feed_layout() {
        assert!(is_supported_oracle_code_hash(&XPR_ORACLES_V7_CODE_HASH));
        assert!(oracle_uses_v2_layout(&XPR_ORACLES_V7_CODE_HASH));
        assert!(is_supported_oracle_code_hash(&XPR_ORACLES_V8_CODE_HASH));
        assert!(oracle_uses_v2_layout(&XPR_ORACLES_V8_CODE_HASH));
        assert!(!is_supported_oracle_code_hash(&[0; 32]));
    }

    #[test]
    fn noloss_trade_cache_key_preserves_user_and_normalizes_unique() {
        let user = Name::from_str("jamestaggart").unwrap();
        let make_action = |unique: u64| {
            let mut data = user.as_u64().to_le_bytes().to_vec();
            data.extend_from_slice(&unique.to_le_bytes());
            Action::new(
                Name::new(NOLOSS),
                Name::new(TRADE),
                data,
                vec![PermissionLevel::new(user.as_u64(), ACTIVE_NAME.as_u64())],
            )
        };

        assert_eq!(Name::from_str("noloss").unwrap().as_u64(), NOLOSS);
        assert_eq!(Name::from_str("trade").unwrap().as_u64(), TRADE);
        assert_eq!(
            noloss_trade_data_key(NOLOSS, &make_action(49), &XPR_NOLOSS_CODE_HASH),
            Some([user.as_u64(), 1])
        );
        assert_eq!(
            noloss_trade_data_key(NOLOSS, &make_action(73), &XPR_NOLOSS_CODE_HASH),
            Some([user.as_u64(), 1])
        );
        assert_eq!(
            noloss_trade_data_key(NOLOSS, &make_action(43), &XPR_NOLOSS_V2_CODE_HASH),
            Some([user.as_u64(), 1])
        );
        assert_eq!(
            noloss_trade_data_key(NOLOSS, &make_action(64), &XPR_NOLOSS_V2_CODE_HASH),
            Some([user.as_u64(), 1])
        );
        assert!(noloss_trade_data_key(NOLOSS, &make_action(49), &[0; 32]).is_none());
    }

    #[test]
    fn oracle_v8_mean_median_transition_matches_provider_grouping() {
        let point = |provider, value| ProviderPoint {
            provider,
            time: 0,
            data: DataVariant {
                d_string: None,
                d_uint64: None,
                d_double: Some(value),
            },
        };
        let mut config = CanonicalMap::new();
        config.insert("data_same_provider_limit".into(), 2);
        config.insert("data_window_size".into(), 4);
        config.insert("min_provider_wait_sec".into(), 60);
        let mut providers = CanonicalMap::new();
        providers.insert(1, 0);
        let mut feed = FeedRow {
            index: 3,
            name: "XPR/USD".into(),
            description: String::new(),
            aggregate_function: "mean_median".into(),
            data_type: "double".into(),
            config,
            providers,
        };
        let mut data = DataRow {
            feed_index: 3,
            aggregate: DataVariant {
                d_string: None,
                d_uint64: None,
                d_double: Some(0.0),
            },
            points: vec![
                point(1, 10.0),
                point(2, 20.0),
                point(1, 14.0),
                point(2, 40.0),
            ],
        };
        let action = FeedActionData {
            account: 1,
            feed_index: 3,
            data: DataVariant {
                d_string: None,
                d_uint64: None,
                d_double: Some(18.0),
            },
        };

        assert!(
            update_oracle_feed(&mut feed, &mut data, &action, 100_000_000, true, true).unwrap()
        );
        assert_eq!(data.points.len(), 3);
        assert_eq!(data.aggregate.d_double, Some(17.0));
        assert_eq!(feed.providers.get(&1), Some(&100_000_000));
    }

    #[test]
    fn observed_process_payload_round_trips_byte_exactly() {
        // block 40,006,000: one bot entry carrying a double oracle value.
        let bytes =
            hex::decode("000000000040323d0103000000000000000000018fc2f5280cf3d1405427000000000000")
                .unwrap();
        let process: Process = read_exact(&bytes, "fixture").unwrap();
        assert_eq!(process.entries.len(), 1);
        assert_eq!(process.entries[0].bot_index, 3);
        assert_eq!(process.pack().unwrap(), bytes);
    }

    #[test]
    fn upgraded_process_payload_carries_the_audited_oracle_index() {
        // First observed v2 bot::process payload after the block 40,312,427
        // deployment. The final uint64 selects oracle feed 1.
        let bytes = hex::decode(
            "000000000040323d010300000000000000000001d7a3703deae1d1404e250100000000000100000000000000",
        )
        .unwrap();
        let process: ProcessV2 = read_exact(&bytes, "fixture").unwrap();
        assert_eq!(process.oracle_index, 1);
        assert_eq!(process.entries.len(), 1);
        assert_eq!(process.pack().unwrap(), bytes);
    }

    #[test]
    fn provider_limit_matches_deployed_erase_and_increment_loop() {
        let mut points = (0..7)
            .map(|time| ProviderPoint {
                provider: 42,
                time,
                data: DataVariant {
                    d_string: None,
                    d_uint64: None,
                    d_double: Some(time as f64),
                },
            })
            .collect::<Vec<_>>();

        enforce_same_provider_limit(&mut points, 5);

        // The sixth point is erased, then the seventh shifts into its position
        // and is skipped by the for-loop increment in the deployed contract.
        assert_eq!(points.len(), 6);
        assert_eq!(
            points.iter().map(|point| point.time).collect::<Vec<_>>(),
            [0, 1, 2, 3, 4, 6]
        );
    }

    #[test]
    fn bot_row_codec_preserves_canonical_map_order() {
        let mut counts = CanonicalMap::new();
        counts.insert(23, 4);
        counts.insert(1, 7);
        let row = BotRow {
            index: 3,
            account: 42,
            description: "oracle".into(),
            oracle_contract: 99,
            feed_index: 8,
            tx_count_by_utc_hour: counts,
            max_history: 2,
            history: Vec::new(),
        };
        let packed = row.pack().unwrap();
        let decoded: BotRow = read_exact(&packed, "fixture").unwrap();
        assert_eq!(decoded, row);
        assert_eq!(
            decoded
                .tx_count_by_utc_hour
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![1, 23]
        );
    }

    #[test]
    fn pinned_system_rows_have_the_audited_onblock_layout() {
        assert!(is_supported_system_code_hash(&XPR_SYSTEM_CODE_HASH));
        assert!(is_supported_system_code_hash(&XPR_SYSTEM_V2_CODE_HASH));
        assert!(is_supported_system_code_hash(&XPR_SYSTEM_V3_CODE_HASH));
        assert!(is_supported_system_code_hash(&XPR_SYSTEM_V4_CODE_HASH));
        // Raw rows from the Arena checkpoint at XPR block 40,000,000, whose
        // eosio code hash is XPR_SYSTEM_CODE_HASH. These assertions make every
        // offset used by the native path fail closed if the layout drifts.
        let global = hex::decode(
            "0000100000000000e8030000000008000c000000f40100001400000064000000\
             400d0300c4090000f049020064000000100e00005802000080533b0000100000\
             06000600000000000400000008414e0e000000001bfc7108000000008605c94e\
             809cf7e215b605005b484559000000001806627301000000f88742000028278f\
             66010000c0eeecc008a4050015000192cce5ab52124400000000",
        )
        .unwrap();
        let global2 = hex::decode("0000f9dec84ef505c94e708266e88a3a0b4501").unwrap();
        let global3 = hex::decode("60387f4316b60500666e70657a591144").unwrap();
        let global4 = hex::decode("eac7f23e06fba83fa861000000000000409c000000000000").unwrap();
        let globalsxpr = hex::decode(
            "0400000000000000040000000000000000751200000000003200000000000000\
             c0a8000000000000805101000000000000000000000000000000000000000000",
        )
        .unwrap();
        let globalsd = hex::decode(
            "7f30cbb732020000c48f2ebb2e0200005301000000000000573d84a301000000\
             499ce15700000000e11ed15f0000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000",
        )
        .unwrap();
        let producer = hex::decode(
            "0000000018ac3155e7e55a67528ed8430003427eddab0fdd30b8563670b5e109\
             9970641720a184827fed56c4bf75e2eb2b83011e68747470733a2f2f62702e65\
             6f737573612e6e6577732f70726f746f6e2f0a1c000080cc6e1f05b6050048\
             030001000000010003427eddab0fdd30b8563670b5e1099970641720a184827f\
             ed56c4bf75e2eb2b830100",
        )
        .unwrap();

        assert_eq!(global.len(), GLOBAL_ROW_SIZE);
        assert_eq!(global2.len(), GLOBAL2_ROW_SIZE);
        assert_eq!(global3.len(), GLOBAL3_ROW_SIZE);
        assert_eq!(global4.len(), GLOBAL4_ROW_SIZE);
        assert_eq!(globalsxpr.len(), GLOBALSXPR_ROW_SIZE);
        assert_eq!(globalsd.len(), GLOBALSD_ROW_SIZE);
        assert_eq!(
            get_u32(&global, GLOBAL_LAST_SCHEDULE_OFFSET),
            Some(1_321_796_998)
        );
        assert_eq!(
            get_i64(&global, GLOBAL_LAST_PERVOTE_FILL_OFFSET),
            Some(1_607_580_002_000_000)
        );
        assert_eq!(
            get_u32(&global, GLOBAL_TOTAL_UNPAID_OFFSET),
            Some(4_360_184)
        );
        assert_eq!(
            get_i64(&global, GLOBAL_ACTIVATION_TIME_OFFSET),
            Some(1_587_732_387_000_000)
        );
        assert_eq!(
            get_u64(&globalsxpr, GLOBALSXPR_PROCESS_INTERVAL_OFFSET),
            Some(43_200)
        );
        assert_eq!(
            get_i64(&globalsd, GLOBALSD_PROCESS_TIME_OFFSET),
            Some(1_607_540_449)
        );
        assert_eq!(
            get_i64(&globalsd, GLOBALSD_PROCESS_TIME_UPDATE_OFFSET),
            Some(0)
        );
        assert_eq!(globalsd[GLOBALSD_IS_PROCESSING_OFFSET], 0);
        let unpaid_offset = producer_unpaid_offset(&producer).unwrap();
        assert_eq!(unpaid_offset, 82);
        assert_eq!(get_u32(&producer, unpaid_offset), Some(7_178));
    }

    #[test]
    fn producer_unpaid_parser_rejects_unknown_key_variants_and_bad_lengths() {
        let mut row = vec![0; 64];
        row[16] = 2;
        assert_eq!(producer_unpaid_offset(&row), None);
        row.truncate(52);
        row[16] = 0;
        row[51] = 0x80;
        assert_eq!(producer_unpaid_offset(&row), None);
    }
}
