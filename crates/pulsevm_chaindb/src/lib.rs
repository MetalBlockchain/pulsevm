//! Native `pulsevm_arena`-backed chain database — the pure-Rust replacement for
//! the C++ chainbase FFI. It defines every chain table (accounts, permissions,
//! resource limits, contract tables, …) as an [`pulsevm_arena::ArenaObject`] and
//! implements the create/modify/remove and read/positioning surface over them.
//!
//! It is consumed by `pulsevm_ffi` (re-exported there as `crate::shadow`) under
//! the `arena-shadow` feature, where — while the cutover is in progress — it runs
//! as a mirror alongside chainbase: every ported mutation is replayed here so a
//! per-block state root can be pulled off the arena and compared as tables come
//! online one at a time. Once the cutover completes it becomes the sole backend.
//! Being a standalone crate, it also builds and is unit-tested without the C++
//! toolchain.
//!
//! The mirror lives in the `Database` wrapper (not in the controller) so that
//! every `Database` clone — and there is one per apply/transaction context —
//! shares the same arena through an `Arc`, and writes reach it with no change at
//! the call sites. The arena is single-threaded (`Db: !Sync`); the `Mutex`
//! serialises the mirror calls, which loses no concurrency because chainbase
//! access is already serialised by its own lock. Never hold the guard across an
//! `.await`.

use std::sync::{
    Arc,
    Mutex,
};

use pulsevm_arena::{
    ArenaObject,
    BlobRef,
    Db,
    DbError,
    IndexedBy,
    ObjectId,
    SecondaryIndex,
    key_index,
};
use zerocopy::{
    FromBytes,
    Immutable,
    IntoBytes,
    KnownLayout,
};

/// Arena mirror of chainbase `account_metadata_object` — the first table ported.
/// The trailing padding keeps the row free of implicit padding bytes so it
/// round-trips through the arena's zero-copy layout.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout, ArenaObject)]
#[arena(type_id = 1)]
struct AccountMetaRow {
    id: ObjectId<AccountMetaRow>,
    // Point-queried only (account lookups by name), never scanned in order, and
    // grows with the account count — so a hash index beats the ordered one at
    // scale. Reads go through `find_by_hash`.
    #[arena(hash_index)]
    name: u64,
    recv_sequence: u64,
    auth_sequence: u64,
    code_sequence: u64,
    abi_sequence: u64,
    last_code_update: i64,
    code_hash: [u8; 32],
    flags: u32, // bit 0 = privileged, matching chainbase
    vm_type: u8,
    vm_version: u8,
    _pad: [u8; 2],
}

/// Arena mirror of chainbase `account_object`. `abi` is a `shared_blob`, so it
/// lives in the table's blob arena and the row keeps only a `BlobRef`.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout, ArenaObject)]
#[arena(type_id = 2)]
struct AccountRow {
    id: ObjectId<AccountRow>,
    #[arena(index)]
    name: u64,
    creation_date: u32,
    _pad: u32,
    abi: BlobRef,
}

/// `config::rate_limiting_precision` — the fixed-point scale the usage
/// accumulators pre-multiply by.
const RATE_LIMITING_PRECISION: u64 = 1_000_000;

/// `num` divided by `den`, rounded up — chainbase's `integer_divide_ceil`.
fn integer_divide_ceil(num: u128, den: u128) -> u128 {
    (num / den) + if num % den > 0 { 1 } else { 0 }
}

/// Parses a 20-byte canonical usage accumulator (value_ex u64 LE, consumed u64
/// LE, last_ordinal u32 LE) — the inverse of the serializers' `put_acc`.
fn read_acc(b: &[u8]) -> UsageAccumulator {
    UsageAccumulator {
        value_ex: u64::from_le_bytes(b[0..8].try_into().unwrap()),
        consumed: u64::from_le_bytes(b[8..16].try_into().unwrap()),
        last_ordinal: u32::from_le_bytes(b[16..20].try_into().unwrap()),
        _pad: 0,
    }
}

/// Port of chainbase `exponential_moving_average_accumulator` (the
/// `usage_accumulator` used for net/cpu). The field order differs from the C++
/// struct to keep the row free of implicit padding for the zero-copy layout, but
/// the arithmetic in `add` matches bit for bit, so a mirrored accumulator tracks
/// chainbase exactly given the same units/ordinal/window inputs. The C++ range
/// asserts are omitted: chainbase enforces them before the mirror runs, so any
/// input reaching here already passed them.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq)]
struct UsageAccumulator {
    value_ex: u64,
    consumed: u64,
    last_ordinal: u32,
    _pad: u32,
}

impl UsageAccumulator {
    fn average(&self) -> u64 {
        integer_divide_ceil(self.value_ex as u128, RATE_LIMITING_PRECISION as u128) as u64
    }

    fn add(&mut self, units: u64, ordinal: u32, window_size: u32) {
        let value_ex_contrib = integer_divide_ceil(
            units as u128 * RATE_LIMITING_PRECISION as u128,
            window_size as u128,
        ) as u64;

        if self.last_ordinal != ordinal {
            if self.last_ordinal as u64 + window_size as u64 > ordinal as u64 {
                let delta = ordinal - self.last_ordinal; // 0 < delta < window_size
                let num = (window_size - delta) as u128;
                let den = window_size as u128;
                self.value_ex = ((self.value_ex as u128 * num) / den) as u64;
            } else {
                self.value_ex = 0;
            }
            self.last_ordinal = ordinal;
            self.consumed = self.average();
        }

        self.consumed += units;
        self.value_ex += value_ex_contrib;
    }
}

/// Arena mirror of chainbase `resource_limits::resource_usage_object`. `ram_usage`
/// accumulates every delta handed to `add_pending_ram_usage` — the same
/// externally-computed deltas chainbase applies, so no billing logic is
/// duplicated. `net_usage`/`cpu_usage` are the windowed-average accumulators,
/// advanced by `add_transaction_usage`/`update_account_usage` with the window
/// pulled from chainbase config so the decay matches.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout, ArenaObject)]
#[arena(type_id = 16)]
struct ResourceUsageRow {
    id: ObjectId<ResourceUsageRow>,
    #[arena(index)]
    owner: u64,
    ram_usage: u64,
    net_usage: UsageAccumulator,
    cpu_usage: UsageAccumulator,
}

/// Arena mirror of chainbase `resource_limits::resource_limits_object`. Chainbase
/// keeps two rows per account keyed by `(pending, owner)`: the committed limits
/// (`pending = false`) and, while a change is staged, a pending copy. -1 means
/// unlimited. The global total-weight bookkeeping that `process_account_limit_
/// updates` also touches lives in a separate object not mirrored here yet.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct ResourceLimitsRow {
    id: ObjectId<ResourceLimitsRow>,
    owner: u64,
    ram_bytes: i64,
    net_weight: i64,
    cpu_weight: i64,
    pending: u8,
    _pad: [u8; 7],
}

struct LimitsByOwner;
impl IndexedBy<ResourceLimitsRow> for LimitsByOwner {
    type Key = (u8, u64);
    fn key(o: &ResourceLimitsRow) -> Self::Key {
        (o.pending, o.owner)
    }
}
impl ArenaObject for ResourceLimitsRow {
    const TYPE_ID: u16 = 17;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![key_index::<Self, LimitsByOwner>()]
    }
}

/// Chainbase `elastic_limit_parameters` for one resource, as plain values pulled
/// from config so the mirror can run `update_elastic_limit` itself.
#[derive(Clone, Copy)]
pub struct ElasticParams {
    pub target: u64,
    pub max: u64,
    pub periods: u32,
    pub max_multiplier: u32,
    pub contract: (u64, u64),
    pub expand: (u64, u64),
}

/// Canonical serialization of a `resource_limits_config` (elastic cpu/net params
/// plus averaging windows), little endian. Shared by the arena mirror and the
/// chainbase side of the cross-impl root so both serialise identically.
pub fn serialize_resource_config(
    cpu: &ElasticParams,
    net: &ElasticParams,
    cpu_window: u32,
    net_window: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    for v in [
        cpu.target,
        cpu.max,
        cpu.contract.0,
        cpu.contract.1,
        cpu.expand.0,
        cpu.expand.1,
        net.target,
        net.max,
        net.contract.0,
        net.contract.1,
        net.expand.0,
        net.expand.1,
    ] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for v in [
        cpu.periods,
        cpu.max_multiplier,
        net.periods,
        net.max_multiplier,
        cpu_window,
        net_window,
    ] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

/// Port of chainbase `update_elastic_limit`: contract the limit when average
/// usage is over target, expand it otherwise, then clamp to `[max, max *
/// max_multiplier]`. The ratio multiply matches the C++ `value * ratio` (u64
/// `(value * num) / den`); a u128 intermediate gives the same result in every
/// non-overflowing case, which is the only case chainbase does not abort on.
fn update_elastic_limit(current: u64, average: u64, p: &ElasticParams) -> u64 {
    let (num, den) = if average > p.target {
        p.contract
    } else {
        p.expand
    };
    let result = ((current as u128 * num as u128) / den as u128) as u64;
    result.max(p.max).min(p.max * p.max_multiplier as u64)
}

/// Arena mirror of chainbase `resource_limits::resource_limits_state_object` — a
/// singleton. `average_block_{net,cpu}_usage` are windowed accumulators; the
/// virtual limits are the elastic rate-limit ceilings recomputed each block by
/// `process_block_usage`. The total_* weights are only moved by
/// `process_account_limit_updates` (which the mirror does not touch on the state
/// object yet), so they stay at chainbase's genesis values in the default flow.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout, ArenaObject)]
#[arena(type_id = 18)]
struct ResourceStateRow {
    id: ObjectId<ResourceStateRow>,
    average_block_net_usage: UsageAccumulator,
    average_block_cpu_usage: UsageAccumulator,
    pending_net_usage: u64,
    pending_cpu_usage: u64,
    total_net_weight: u64,
    total_cpu_weight: u64,
    total_ram_bytes: u64,
    virtual_net_limit: u64,
    virtual_cpu_limit: u64,
}

/// Arena mirror of chainbase `permission_object`. `auth` (a `shared_authority`)
/// is variable-length, so it is encoded into the blob arena; the row holds the
/// `BlobRef`. The three secondary indices reproduce chainbase's key ordering
/// exactly: `by_parent` = `(parent, id)`, `by_owner` = `(owner, perm_name)`,
/// `by_name` = `(perm_name, id)`.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct PermissionRow {
    id: ObjectId<PermissionRow>,
    // The chainbase `permission_object` id this row mirrors. The arena's own
    // `id` is assigned in (owner, name) hydration order and does NOT track
    // chainbase's creation-order ids, so parent links (which are chainbase ids)
    // are navigated through `cb_id`, not `id`.
    cb_id: i64,
    usage_id: i64,
    parent: i64,
    owner: u64,
    perm_name: u64,
    last_updated: i64,
    auth: BlobRef,
}

struct PermByParent;
impl IndexedBy<PermissionRow> for PermByParent {
    type Key = (i64, i64);
    fn key(o: &PermissionRow) -> Self::Key {
        (o.parent, o.cb_id)
    }
}
struct PermByOwner;
impl IndexedBy<PermissionRow> for PermByOwner {
    type Key = (u64, u64);
    fn key(o: &PermissionRow) -> Self::Key {
        (o.owner, o.perm_name)
    }
}
struct PermByName;
impl IndexedBy<PermissionRow> for PermByName {
    type Key = (u64, i64);
    fn key(o: &PermissionRow) -> Self::Key {
        (o.perm_name, o.cb_id)
    }
}
struct PermByCbId;
impl IndexedBy<PermissionRow> for PermByCbId {
    type Key = i64;
    fn key(o: &PermissionRow) -> Self::Key {
        o.cb_id
    }
}
impl ArenaObject for PermissionRow {
    const TYPE_ID: u16 = 3;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, PermByParent>(),
            key_index::<Self, PermByOwner>(),
            key_index::<Self, PermByName>(),
            key_index::<Self, PermByCbId>(),
        ]
    }
}

/// Arena mirror of chainbase `permission_usage_object`. It has no secondary
/// index and no dedicated mutation entry point; it is created, touched and
/// removed only alongside a `permission_object`.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout, ArenaObject)]
#[arena(type_id = 4)]
struct PermissionUsageRow {
    id: ObjectId<PermissionUsageRow>,
    last_used: i64,
}

/// Arena mirror of chainbase `permission_link_object`. Secondary indices match
/// chainbase: `by_action_name` = `(account, code, message_type)`,
/// `by_permission_name` = `(account, required_permission, id)`.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct PermissionLinkRow {
    id: ObjectId<PermissionLinkRow>,
    account: u64,
    code: u64,
    message_type: u64,
    required_permission: u64,
}

struct LinkByActionName;
impl IndexedBy<PermissionLinkRow> for LinkByActionName {
    type Key = (u64, u64, u64);
    fn key(o: &PermissionLinkRow) -> Self::Key {
        (o.account, o.code, o.message_type)
    }
}
struct LinkByPermissionName;
impl IndexedBy<PermissionLinkRow> for LinkByPermissionName {
    type Key = (u64, u64, i64);
    fn key(o: &PermissionLinkRow) -> Self::Key {
        (o.account, o.required_permission, o.id.raw())
    }
}
impl ArenaObject for PermissionLinkRow {
    const TYPE_ID: u16 = 5;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, LinkByActionName>(),
            key_index::<Self, LinkByPermissionName>(),
        ]
    }
}

/// Arena mirror of chainbase `code_object`. `code` is a `shared_blob`. The
/// `by_code_hash` index is composite `(code_hash, vm_type, vm_version)`, the
/// same ordering chainbase uses.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct CodeRow {
    id: ObjectId<CodeRow>,
    code_ref_count: u64,
    code: BlobRef,
    first_block_used: u32,
    vm_type: u8,
    vm_version: u8,
    _pad: [u8; 2],
    code_hash: [u8; 32],
}

struct CodeByHash;
impl IndexedBy<CodeRow> for CodeByHash {
    type Key = ([u8; 32], u8, u8);
    fn key(o: &CodeRow) -> Self::Key {
        (o.code_hash, o.vm_type, o.vm_version)
    }
}
impl ArenaObject for CodeRow {
    const TYPE_ID: u16 = 6;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![key_index::<Self, CodeByHash>()]
    }
}

/// Arena mirror of chainbase `dynamic_global_property_object` — a singleton
/// carrying the monotonically increasing global action sequence. Genesis creates
/// the chainbase row on the C++ side, which the mirror never observes, so the
/// mirror creates its own row lazily the first time a sequence is drawn.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout, ArenaObject)]
#[arena(type_id = 14)]
struct DynGlobalPropertyRow {
    id: ObjectId<DynGlobalPropertyRow>,
    global_action_sequence: u64,
}

/// Arena-internal bookkeeping — NOT part of any consensus state and never
/// serialized into a `*_state_bytes` root. Holds the next permission id the
/// arena will assign, replicating chainbase's per-index `undo_index::_next_id`
/// for the permission table. It lives in its own undo-tracked singleton table so
/// the Db's session machinery snapshots and restores it on undo/squash/commit
/// exactly as chainbase restores `old_next_id`, keeping the arena's authored id
/// in lockstep with chainbase's across forks. Seeded after permission hydration
/// to `max(cb_id) + 1` (chainbase reserves permission id 0 and numbers genesis
/// permissions contiguously) and advanced on every `create_permission`. type_id
/// 200 is out of chainbase's object-type range to flag that it mirrors none.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout, ArenaObject)]
#[arena(type_id = 200)]
struct PermSeqRow {
    id: ObjectId<PermSeqRow>,
    next_id: i64,
}

/// Arena mirror of the STATIC chainbase `global_property_object`, holding the
/// active `chain_config` (blockchain parameters). Genesis creates the chainbase
/// row in C++, out of reach of the per-write hooks, so the mirror is seeded once
/// from chainbase at init and then updated in lockstep by `set_global_properties`
/// (the `setparams` intrinsic). Only the fields chainbase exposes and the
/// `chain_config` wire format carries are stored: `deferred_trx_expiration_window`
/// (no chainbase getter, always 0 in this build) and `max_action_return_value_size`
/// (not carried by the params intrinsic) are deliberately omitted so the mirror and
/// chainbase serialise identically. Field order matches `ChainConfigV0`.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout, ArenaObject)]
#[arena(type_id = 19)]
struct GlobalPropertyRow {
    id: ObjectId<GlobalPropertyRow>,
    max_block_net_usage: u64,
    target_block_net_usage_pct: u32,
    max_transaction_net_usage: u32,
    base_per_transaction_net_usage: u32,
    net_usage_leeway: u32,
    context_free_discount_net_usage_num: u32,
    context_free_discount_net_usage_den: u32,
    max_block_cpu_usage: u32,
    target_block_cpu_usage_pct: u32,
    max_transaction_cpu_usage: u32,
    min_transaction_cpu_usage: u32,
    max_transaction_lifetime: u32,
    max_transaction_delay: u32,
    max_inline_action_size: u32,
    max_inline_action_depth: u16,
    max_authority_depth: u16,
}

/// Arena mirror of the chainbase `resource_limits_config_object` singleton: the
/// elastic cpu/net limit parameters plus the account usage averaging windows.
/// Genesis creates the chainbase row in C++; the mirror is seeded once from
/// chainbase and the elastic params are updated by `set_block_parameters`
/// (end-of-block). Storing them lets the arena compute virtual limits without
/// re-reading chainbase.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout, ArenaObject)]
#[arena(type_id = 20)]
struct ResourceConfigRow {
    id: ObjectId<ResourceConfigRow>,
    cpu_target: u64,
    cpu_max: u64,
    cpu_contract_num: u64,
    cpu_contract_den: u64,
    cpu_expand_num: u64,
    cpu_expand_den: u64,
    net_target: u64,
    net_max: u64,
    net_contract_num: u64,
    net_contract_den: u64,
    net_expand_num: u64,
    net_expand_den: u64,
    cpu_periods: u32,
    cpu_max_multiplier: u32,
    net_periods: u32,
    net_max_multiplier: u32,
    account_cpu_usage_average_window: u32,
    account_net_usage_average_window: u32,
}

/// The subset of `chain_config` the mirror tracks, passed from the FFI seam into
/// [`ArenaShadow::set_global_properties`]. Mirrors [`GlobalPropertyRow`]'s fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChainConfigParams {
    pub max_block_net_usage: u64,
    pub target_block_net_usage_pct: u32,
    pub max_transaction_net_usage: u32,
    pub base_per_transaction_net_usage: u32,
    pub net_usage_leeway: u32,
    pub context_free_discount_net_usage_num: u32,
    pub context_free_discount_net_usage_den: u32,
    pub max_block_cpu_usage: u32,
    pub target_block_cpu_usage_pct: u32,
    pub max_transaction_cpu_usage: u32,
    pub min_transaction_cpu_usage: u32,
    pub max_transaction_lifetime: u32,
    pub max_transaction_delay: u32,
    pub max_inline_action_size: u32,
    pub max_inline_action_depth: u16,
    pub max_authority_depth: u16,
}

impl ChainConfigParams {
    /// Canonical serialization shared by the arena mirror and the chainbase side
    /// of the cross-impl root: 16 fields, little endian, `ChainConfigV0` order.
    pub fn to_state_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.max_block_net_usage.to_le_bytes());
        out.extend_from_slice(&self.target_block_net_usage_pct.to_le_bytes());
        out.extend_from_slice(&self.max_transaction_net_usage.to_le_bytes());
        out.extend_from_slice(&self.base_per_transaction_net_usage.to_le_bytes());
        out.extend_from_slice(&self.net_usage_leeway.to_le_bytes());
        out.extend_from_slice(&self.context_free_discount_net_usage_num.to_le_bytes());
        out.extend_from_slice(&self.context_free_discount_net_usage_den.to_le_bytes());
        out.extend_from_slice(&self.max_block_cpu_usage.to_le_bytes());
        out.extend_from_slice(&self.target_block_cpu_usage_pct.to_le_bytes());
        out.extend_from_slice(&self.max_transaction_cpu_usage.to_le_bytes());
        out.extend_from_slice(&self.min_transaction_cpu_usage.to_le_bytes());
        out.extend_from_slice(&self.max_transaction_lifetime.to_le_bytes());
        out.extend_from_slice(&self.max_transaction_delay.to_le_bytes());
        out.extend_from_slice(&self.max_inline_action_size.to_le_bytes());
        out.extend_from_slice(&self.max_inline_action_depth.to_le_bytes());
        out.extend_from_slice(&self.max_authority_depth.to_le_bytes());
        out
    }
}

impl GlobalPropertyRow {
    fn params(&self) -> ChainConfigParams {
        ChainConfigParams {
            max_block_net_usage: self.max_block_net_usage,
            target_block_net_usage_pct: self.target_block_net_usage_pct,
            max_transaction_net_usage: self.max_transaction_net_usage,
            base_per_transaction_net_usage: self.base_per_transaction_net_usage,
            net_usage_leeway: self.net_usage_leeway,
            context_free_discount_net_usage_num: self.context_free_discount_net_usage_num,
            context_free_discount_net_usage_den: self.context_free_discount_net_usage_den,
            max_block_cpu_usage: self.max_block_cpu_usage,
            target_block_cpu_usage_pct: self.target_block_cpu_usage_pct,
            max_transaction_cpu_usage: self.max_transaction_cpu_usage,
            min_transaction_cpu_usage: self.min_transaction_cpu_usage,
            max_transaction_lifetime: self.max_transaction_lifetime,
            max_transaction_delay: self.max_transaction_delay,
            max_inline_action_size: self.max_inline_action_size,
            max_inline_action_depth: self.max_inline_action_depth,
            max_authority_depth: self.max_authority_depth,
        }
    }
}

/// Arena mirror of chainbase `transaction_object`, the per-block duplicate-trx
/// dedupe set. Secondary indices reproduce chainbase's ordering: `by_trx_id` =
/// `trx_id`, `by_expiration` = `(expiration, id)`.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct TransactionRow {
    id: ObjectId<TransactionRow>,
    expiration: u32,
    _pad: u32,
    trx_id: [u8; 32],
}

struct TxByTrxId;
impl IndexedBy<TransactionRow> for TxByTrxId {
    type Key = [u8; 32];
    fn key(o: &TransactionRow) -> Self::Key {
        o.trx_id
    }
}
struct TxByExpiration;
impl IndexedBy<TransactionRow> for TxByExpiration {
    type Key = (u32, i64);
    fn key(o: &TransactionRow) -> Self::Key {
        (o.expiration, o.id.raw())
    }
}
impl ArenaObject for TransactionRow {
    const TYPE_ID: u16 = 15;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, TxByTrxId>(),
            key_index::<Self, TxByExpiration>(),
        ]
    }
}

// ----- contract tables + secondary indices ------------------------------
//
// These mirror chainbase's `table_id_object`, `key_value_object` and the five
// `secondary_index<...>` tables. The row shapes and index orderings are copied
// from the proven definitions in `pulsevm_contractdb`, so the arena's key
// ordering matches chainbase's `boost::multi_index` comparators exactly. The
// only additions here are the `payer` field on every row (chainbase carries it;
// contractdb dropped it) and the `index_long_double` table, which contractdb
// does not model.
//
// `t_id` is the mirror's own `table_id` row id (an `i64` oid), assigned when the
// table is first seen — it is not chainbase's oid, but every child row keys off
// the same local value, so `(t_id, primary_key)` locates a row unambiguously.

/// Mirror of `table_id_object`. `count` tracks the number of child rows
/// (primary + every secondary), matching chainbase, which increments it on each
/// child create and decrements it on each child remove, deleting the table when
/// it reaches zero. `payer` is sampled at creation only; chainbase can reassign
/// it internally with no FFI hook, so the mirror does not track that drift.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct ContractTableRow {
    id: ObjectId<ContractTableRow>,
    code: u64,
    scope: u64,
    table: u64,
    payer: u64,
    count: u32,
    _pad: u32,
}

struct ContractTableByCodeScopeTable;
impl IndexedBy<ContractTableRow> for ContractTableByCodeScopeTable {
    type Key = (u64, u64, u64);
    fn key(o: &ContractTableRow) -> Self::Key {
        (o.code, o.scope, o.table)
    }
}
impl ArenaObject for ContractTableRow {
    const TYPE_ID: u16 = 7;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![key_index::<Self, ContractTableByCodeScopeTable>()]
    }
}

/// Mirror of `key_value_object`. `value` is a `shared_blob`, so it lives in the
/// blob arena and the row keeps a `BlobRef`. Ordered by `(t_id, primary_key)`.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct ContractKeyValueRow {
    id: ObjectId<ContractKeyValueRow>,
    t_id: i64,
    primary_key: u64,
    payer: u64,
    value: BlobRef,
}

struct ContractKvByScopePrimary;
impl IndexedBy<ContractKeyValueRow> for ContractKvByScopePrimary {
    type Key = (i64, u64);
    fn key(o: &ContractKeyValueRow) -> Self::Key {
        (o.t_id, o.primary_key)
    }
}
impl ArenaObject for ContractKeyValueRow {
    const TYPE_ID: u16 = 8;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![key_index::<Self, ContractKvByScopePrimary>()]
    }
}

/// Mirror of `index64_object` — a `uint64` secondary key, ordered by
/// `(t_id, secondary_key, primary_key)`, plus a `by_primary` index.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct ContractIndex64Row {
    id: ObjectId<ContractIndex64Row>,
    t_id: i64,
    primary_key: u64,
    secondary_key: u64,
    payer: u64,
}

struct ContractIdx64ByPrimary;
impl IndexedBy<ContractIndex64Row> for ContractIdx64ByPrimary {
    type Key = (i64, u64);
    fn key(o: &ContractIndex64Row) -> Self::Key {
        (o.t_id, o.primary_key)
    }
}
struct ContractIdx64BySecondary;
impl IndexedBy<ContractIndex64Row> for ContractIdx64BySecondary {
    type Key = (i64, u64, u64);
    fn key(o: &ContractIndex64Row) -> Self::Key {
        (o.t_id, o.secondary_key, o.primary_key)
    }
}
impl ArenaObject for ContractIndex64Row {
    const TYPE_ID: u16 = 9;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, ContractIdx64ByPrimary>(),
            key_index::<Self, ContractIdx64BySecondary>(),
        ]
    }
}

/// Mirror of `index128_object`. The `uint128` key is split into two `u64` words
/// so the row stays 8-byte aligned (a real `u128` would force 16-byte alignment
/// and thus padding, which `IntoBytes` rejects); the comparator rejoins them.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct ContractIndex128Row {
    id: ObjectId<ContractIndex128Row>,
    t_id: i64,
    primary_key: u64,
    sec_lo: u64,
    sec_hi: u64,
    payer: u64,
}

impl ContractIndex128Row {
    fn secondary_key(&self) -> u128 {
        join_u128(self.sec_lo, self.sec_hi)
    }
}

struct ContractIdx128ByPrimary;
impl IndexedBy<ContractIndex128Row> for ContractIdx128ByPrimary {
    type Key = (i64, u64);
    fn key(o: &ContractIndex128Row) -> Self::Key {
        (o.t_id, o.primary_key)
    }
}
struct ContractIdx128BySecondary;
impl IndexedBy<ContractIndex128Row> for ContractIdx128BySecondary {
    type Key = (i64, u128, u64);
    fn key(o: &ContractIndex128Row) -> Self::Key {
        (o.t_id, o.secondary_key(), o.primary_key)
    }
}
impl ArenaObject for ContractIndex128Row {
    const TYPE_ID: u16 = 10;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, ContractIdx128ByPrimary>(),
            key_index::<Self, ContractIdx128BySecondary>(),
        ]
    }
}

/// Mirror of `index256_object` — a `key256_t` (`std::array<uint128_t, 2>`) key.
/// The 32 bytes are stored verbatim; chainbase orders the array with the default
/// `operator<` (lexicographic over the two words, element `[0]` most
/// significant). The words are the two little-endian `uint128` halves of the
/// buffer, so the comparator reads word `[0]` from bytes `0..16` and word `[1]`
/// from `16..32` and compares `(word0, word1)`.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct ContractIndex256Row {
    id: ObjectId<ContractIndex256Row>,
    t_id: i64,
    primary_key: u64,
    payer: u64,
    secondary_key: [u8; 32],
}

impl ContractIndex256Row {
    fn secondary_words(&self) -> (u128, u128) {
        let mut w0 = [0u8; 16];
        let mut w1 = [0u8; 16];
        w0.copy_from_slice(&self.secondary_key[0..16]);
        w1.copy_from_slice(&self.secondary_key[16..32]);
        (u128::from_le_bytes(w0), u128::from_le_bytes(w1))
    }
}

struct ContractIdx256ByPrimary;
impl IndexedBy<ContractIndex256Row> for ContractIdx256ByPrimary {
    type Key = (i64, u64);
    fn key(o: &ContractIndex256Row) -> Self::Key {
        (o.t_id, o.primary_key)
    }
}
struct ContractIdx256BySecondary;
impl IndexedBy<ContractIndex256Row> for ContractIdx256BySecondary {
    type Key = (i64, u128, u128, u64);
    fn key(o: &ContractIndex256Row) -> Self::Key {
        let (w0, w1) = o.secondary_words();
        (o.t_id, w0, w1, o.primary_key)
    }
}
impl ArenaObject for ContractIndex256Row {
    const TYPE_ID: u16 = 11;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, ContractIdx256ByPrimary>(),
            key_index::<Self, ContractIdx256BySecondary>(),
        ]
    }
}

/// Total order over the idx_double key matching chainbase `soft_double_less`
/// (`f64_lt`): numeric order with `-0.0` and `+0.0` equal. Chainbase asserts the
/// key is not NaN before it reaches the index, so a well-formed caller never
/// inserts one; folding `-0.0` onto `+0.0` and leaning on `total_cmp` reproduces
/// `f64_lt` on every non-NaN input and still yields a valid total order if a NaN
/// ever slips through, rather than corrupting the BTree.
#[derive(Clone, Copy)]
struct DoubleKey(f64);

impl DoubleKey {
    fn canonical(self) -> f64 {
        if self.0 == 0.0 { 0.0 } else { self.0 }
    }
}
impl PartialEq for DoubleKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}
impl Eq for DoubleKey {}
impl PartialOrd for DoubleKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for DoubleKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.canonical().total_cmp(&other.canonical())
    }
}

/// Mirror of `index_double_object` — an IEEE-754 `double`, ordered by
/// [`DoubleKey`] to match chainbase's software-float comparison.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct ContractIndexDoubleRow {
    id: ObjectId<ContractIndexDoubleRow>,
    t_id: i64,
    primary_key: u64,
    secondary_key: f64,
    payer: u64,
}

struct ContractIdxDoubleByPrimary;
impl IndexedBy<ContractIndexDoubleRow> for ContractIdxDoubleByPrimary {
    type Key = (i64, u64);
    fn key(o: &ContractIndexDoubleRow) -> Self::Key {
        (o.t_id, o.primary_key)
    }
}
struct ContractIdxDoubleBySecondary;
impl IndexedBy<ContractIndexDoubleRow> for ContractIdxDoubleBySecondary {
    type Key = (i64, DoubleKey, u64);
    fn key(o: &ContractIndexDoubleRow) -> Self::Key {
        (o.t_id, DoubleKey(o.secondary_key), o.primary_key)
    }
}
impl ArenaObject for ContractIndexDoubleRow {
    const TYPE_ID: u16 = 12;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, ContractIdxDoubleByPrimary>(),
            key_index::<Self, ContractIdxDoubleBySecondary>(),
        ]
    }
}

/// Total order over the idx_long_double key matching chainbase
/// `soft_long_double_less` (`f128_lt`): the IEEE binary128 numeric order, again
/// with `-0.0` and `+0.0` folded together. Rather than call softfloat (not
/// reachable from a BTree comparator), this reproduces IEEE-754 total ordering
/// on the 128-bit pattern the same way `f64::total_cmp` does for 64-bit: flip
/// the sign bit for positives, flip all bits for negatives, then compare as a
/// signed integer. That equals `f128_lt` on every non-NaN, non-`-0.0` input.
#[derive(Clone, Copy)]
struct LongDoubleKey {
    lo: u64,
    hi: u64,
}

impl LongDoubleKey {
    fn ordering_key(self) -> i128 {
        let bits: u128 = ((self.hi as u128) << 64) | self.lo as u128;
        let sign_mask: u128 = 1u128 << 127;
        // Fold both zeros (exponent and mantissa all zero, either sign) onto
        // `+0.0` so they compare equal, as `f128_lt` treats them.
        let bits = if bits & !sign_mask == 0 { 0 } else { bits };
        let mut key = bits as i128;
        key ^= (((key >> 127) as u128) >> 1) as i128;
        key
    }
}
impl PartialEq for LongDoubleKey {
    fn eq(&self, other: &Self) -> bool {
        self.ordering_key() == other.ordering_key()
    }
}
impl Eq for LongDoubleKey {}
impl PartialOrd for LongDoubleKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for LongDoubleKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ordering_key().cmp(&other.ordering_key())
    }
}

/// Mirror of `index_long_double_object` — a `float128_t`, stored as two `u64`
/// words and ordered by [`LongDoubleKey`].
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct ContractIndexLongDoubleRow {
    id: ObjectId<ContractIndexLongDoubleRow>,
    t_id: i64,
    primary_key: u64,
    sec_lo: u64,
    sec_hi: u64,
    payer: u64,
}

struct ContractIdxLongDoubleByPrimary;
impl IndexedBy<ContractIndexLongDoubleRow> for ContractIdxLongDoubleByPrimary {
    type Key = (i64, u64);
    fn key(o: &ContractIndexLongDoubleRow) -> Self::Key {
        (o.t_id, o.primary_key)
    }
}
struct ContractIdxLongDoubleBySecondary;
impl IndexedBy<ContractIndexLongDoubleRow> for ContractIdxLongDoubleBySecondary {
    type Key = (i64, LongDoubleKey, u64);
    fn key(o: &ContractIndexLongDoubleRow) -> Self::Key {
        (
            o.t_id,
            LongDoubleKey {
                lo: o.sec_lo,
                hi: o.sec_hi,
            },
            o.primary_key,
        )
    }
}
impl ArenaObject for ContractIndexLongDoubleRow {
    const TYPE_ID: u16 = 13;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, ContractIdxLongDoubleByPrimary>(),
            key_index::<Self, ContractIdxLongDoubleBySecondary>(),
        ]
    }
}

/// Rejoins `(low, high)` `u64` words into a `u128`.
fn join_u128(lo: u64, hi: u64) -> u128 {
    ((hi as u128) << 64) | lo as u128
}

/// Resolves the mirror-local `table_id` for `(code, scope, table)`, creating the
/// table row (with `count == 0`) the first time it is seen. Matches chainbase's
/// implicit `find_or_create_table` inside the child-store paths.
fn contract_table_oid(
    db: &mut Db,
    code: u64,
    scope: u64,
    table: u64,
    payer: u64,
) -> Result<i64, DbError> {
    if let Some(id) = db
        .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
        .map(|t| t.id().raw())
    {
        return Ok(id);
    }
    let id = db
        .create::<ContractTableRow>(|t| {
            t.code = code;
            t.scope = scope;
            t.table = table;
            t.payer = payer;
            t.count = 0;
        })?
        .id()
        .raw();
    Ok(id)
}

/// Bumps a table's child-row count, mirroring the `++t.count` chainbase does on
/// every primary/secondary create.
fn contract_table_incr(db: &mut Db, t_id: i64) -> Result<(), DbError> {
    db.modify::<ContractTableRow>(ObjectId::new(t_id), |t| t.count += 1)
}

/// Drops a table's child-row count and removes the table when it hits zero,
/// mirroring the `--t.count` / `remove_table` chainbase does on every remove.
fn contract_table_decr(db: &mut Db, t_id: i64) -> Result<(), DbError> {
    db.modify::<ContractTableRow>(ObjectId::new(t_id), |t| t.count = t.count.saturating_sub(1))?;
    if db.get::<ContractTableRow>(ObjectId::new(t_id))?.count == 0 {
        db.remove::<ContractTableRow>(ObjectId::new(t_id))?;
    }
    Ok(())
}

/// A cheaply cloned, `Send + Sync` handle to the shadow arena, held by
/// `Database` and shared across its clones.
#[derive(Clone)]
pub struct ArenaShadow {
    inner: Arc<Mutex<Db>>,
    // Inline read cross-check tallies: every contract read the node serves
    // (db_get_i64) is answered a second time by the arena and compared. Shared
    // across Database clones so the totals are chain-wide. See `crosscheck_kv`.
    read_ok: Arc<std::sync::atomic::AtomicU64>,
    read_fail: Arc<std::sync::atomic::AtomicU64>,
    // Iterator-positioning cross-check tallies (db_next/previous/lower/upper): the
    // arena computes where the cursor lands and it's compared to chainbase.
    pos_ok: Arc<std::sync::atomic::AtomicU64>,
    pos_fail: Arc<std::sync::atomic::AtomicU64>,
    // Non-contract read cross-check tallies (accounts/permissions the node reads
    // during authorization and dispatch): the arena answers the same lookup.
    nc_ok: Arc<std::sync::atomic::AtomicU64>,
    nc_fail: Arc<std::sync::atomic::AtomicU64>,
    // When set, the node serves contract reads FROM the arena instead of
    // chainbase. Shared across clones. On by default: the cutover is complete, so
    // the arena is the primary read backend and chainbase runs only as the
    // mirrored comparison oracle. A `PULSEVM_ARENA_READS` set to a falsey value is
    // an explicit kill switch that reverts to serving from chainbase.
    reads_enabled: Arc<std::sync::atomic::AtomicBool>,
}

/// Whether the arena serves execution reads. Default on (the arena is primary);
/// an explicit falsey `PULSEVM_ARENA_READS` (`0`, `false`, `off`, `no`) is the
/// kill switch that falls back to chainbase. Any other value, or unset, is on.
fn arena_reads_default() -> bool {
    match std::env::var("PULSEVM_ARENA_READS") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}

/// Builds an empty `Db` with every mirrored table registered. Shared by
/// `ArenaShadow::new` and the restart path so both agree on the table set.
fn build_registered_db() -> Result<Db, DbError> {
    let mut db = Db::new();
    db.add_table::<AccountMetaRow>()?;
    db.add_table::<AccountRow>()?;
    db.add_table::<PermissionRow>()?;
    db.add_table::<PermissionUsageRow>()?;
    db.add_table::<PermissionLinkRow>()?;
    db.add_table::<CodeRow>()?;
    db.add_table::<DynGlobalPropertyRow>()?;
    db.add_table::<PermSeqRow>()?;
    db.add_table::<GlobalPropertyRow>()?;
    db.add_table::<ResourceConfigRow>()?;
    db.add_table::<TransactionRow>()?;
    db.add_table::<ContractTableRow>()?;
    db.add_table::<ContractKeyValueRow>()?;
    db.add_table::<ContractIndex64Row>()?;
    db.add_table::<ContractIndex128Row>()?;
    db.add_table::<ContractIndex256Row>()?;
    db.add_table::<ContractIndexDoubleRow>()?;
    db.add_table::<ContractIndexLongDoubleRow>()?;
    db.add_table::<ResourceUsageRow>()?;
    db.add_table::<ResourceLimitsRow>()?;
    db.add_table::<ResourceStateRow>()?;
    Ok(db)
}

/// The arena's replicated permission-id counter (`PermSeqRow` singleton):
/// `(row id, the next permission id to assign)`, or `None` before it is seeded.
fn perm_seq_peek(db: &Db) -> Result<Option<(ObjectId<PermSeqRow>, i64)>, DbError> {
    Ok(db
        .table::<PermSeqRow>()?
        .iter()
        .next()
        .map(|r| (r.id(), r.next_id)))
}

/// Sets the arena's permission-id counter, creating the singleton if absent. The
/// write goes through the live Db, so it participates in the active undo session
/// and rolls back with the permission create it accompanies.
fn perm_seq_set(db: &mut Db, next: i64) -> Result<(), DbError> {
    // Bind the lookup to a local so the immutable borrow from `table().iter()`
    // ends here; a match scrutinee would hold it through the arms and collide
    // with the mutable `modify`/`create` below.
    let existing = db.table::<PermSeqRow>()?.iter().next().map(|r| r.id());
    match existing {
        Some(id) => db.modify::<PermSeqRow>(id, |r| r.next_id = next)?,
        None => {
            db.create::<PermSeqRow>(|r| r.next_id = next)?;
        }
    }
    Ok(())
}

impl ArenaShadow {
    /// Registers every ported table. Grows as tables come online.
    pub fn new() -> Result<Self, DbError> {
        let db = build_registered_db()?;
        Ok(ArenaShadow {
            inner: Arc::new(Mutex::new(db)),
            read_ok: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            read_fail: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pos_ok: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pos_fail: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            nc_ok: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            nc_fail: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            // The arena is the primary read backend: execution serves from it
            // from the outset, with chainbase kept only as the mirrored oracle.
            // A falsey PULSEVM_ARENA_READS is the kill switch back to chainbase.
            reads_enabled: Arc::new(std::sync::atomic::AtomicBool::new(arena_reads_default())),
        })
    }

    /// Route contract reads through the arena from now on (the cutover switch).
    pub fn enable_reads(&self) {
        self.reads_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn reads_enabled(&self) -> bool {
        self.reads_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Db> {
        self.inner.lock().expect("shadow arena mutex poisoned")
    }

    /// Inline read cross-check: given the value the node is about to hand a
    /// contract for `(code, scope, table, primary)`, confirm the arena serves the
    /// same bytes from its own state — including uncommitted, mid-transaction
    /// speculative writes, which the block-boundary root diff never sees. Tallies
    /// a match or mismatch (mismatches also print). Returns nothing; the counts
    /// are asserted after replay via `read_crosscheck_counts`.
    pub fn crosscheck_kv(&self, code: u64, scope: u64, table: u64, primary: u64, expected: &[u8]) {
        use std::sync::atomic::Ordering;
        if self.kv_get(code, scope, table, primary).as_deref() == Some(expected) {
            self.read_ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.read_fail.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "arena read cross-check mismatch at ({code},{scope},{table},{primary}): expected {} bytes",
                expected.len()
            );
        }
    }

    /// (matches, mismatches) tallied by `crosscheck_kv` so far.
    pub fn read_crosscheck_counts(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.read_ok.load(Ordering::Relaxed),
            self.read_fail.load(Ordering::Relaxed),
        )
    }

    pub fn set_revision(&self, revision: i64) -> Result<(), DbError> {
        self.lock().set_revision(revision)
    }

    // Lifecycle, driven from the controller in lockstep with the chainbase
    // undo-session boundaries.
    pub fn start_undo_session(&self) {
        self.lock().start_undo_session();
    }
    pub fn squash(&self) {
        self.lock().squash();
    }
    pub fn undo(&self) {
        self.lock().undo();
    }
    pub fn commit(&self, revision: i64) {
        self.lock().commit(revision);
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.lock().state_root()
    }

    // ----- ported mutations -------------------------------------------------

    pub fn create_account_metadata(&self, name: u64, privileged: bool) -> Result<(), DbError> {
        self.lock().create::<AccountMetaRow>(|row| {
            row.name = name;
            row.flags = privileged as u32;
        })?;
        Ok(())
    }

    /// Whether the mirror holds an account_metadata row for `name`, and its
    /// privileged flag — for diffing against chainbase.
    pub fn account_metadata_privileged(&self, name: u64) -> Option<bool> {
        self.lock()
            .find_by_hash::<AccountMetaRow, AccountMetaRowByName>(&name)
            .ok()
            .flatten()
            .map(|row| row.flags & 1 != 0)
    }

    /// Full account_metadata snapshot for `name`, mirroring the chainbase
    /// `account_metadata_object` accessors — for field-for-field diffing.
    /// Tuple: (privileged, recv_seq, auth_seq, code_seq, abi_seq, code_hash, vm_type, vm_version).
    #[allow(clippy::type_complexity)]
    pub fn account_metadata(
        &self,
        name: u64,
    ) -> Option<(bool, u64, u64, u64, u64, [u8; 32], u8, u8)> {
        self.lock()
            .find_by_hash::<AccountMetaRow, AccountMetaRowByName>(&name)
            .ok()
            .flatten()
            .map(|row| {
                (
                    row.flags & 1 != 0,
                    row.recv_sequence,
                    row.auth_sequence,
                    row.code_sequence,
                    row.abi_sequence,
                    row.code_hash,
                    row.vm_type,
                    row.vm_version,
                )
            })
    }

    /// Canonical serialization of the whole account_metadata table in name order.
    /// Field order and endianness match the chainbase `account_metadata_state_
    /// bytes` enumerator byte for byte, so hashing the two streams yields the
    /// same root when the tables hold the same logical state — a true
    /// cross-implementation state-root check over the full account set.
    pub fn account_metadata_state_bytes(&self) -> Vec<u8> {
        let db = self.lock();
        let mut rows: Vec<(u64, bool, u64, u64, u64, u64, [u8; 32], u8, u8)> =
            match db.table::<AccountMetaRow>() {
                Ok(t) => t
                    .iter()
                    .map(|r| {
                        (
                            r.name,
                            r.flags & 1 != 0,
                            r.recv_sequence,
                            r.auth_sequence,
                            r.code_sequence,
                            r.abi_sequence,
                            r.code_hash,
                            r.vm_type,
                            r.vm_version,
                        )
                    })
                    .collect(),
                Err(_) => return Vec::new(),
            };
        rows.sort_by_key(|r| r.0);
        let mut out = Vec::new();
        for (name, privileged, recv, auth, code, abi, hash, vm_type, vm_version) in rows {
            out.extend_from_slice(&name.to_le_bytes());
            out.push(privileged as u8);
            out.extend_from_slice(&recv.to_le_bytes());
            out.extend_from_slice(&auth.to_le_bytes());
            out.extend_from_slice(&code.to_le_bytes());
            out.extend_from_slice(&abi.to_le_bytes());
            out.extend_from_slice(&hash);
            out.push(vm_type);
            out.push(vm_version);
        }
        out
    }

    /// Loads account_metadata rows from the canonical byte layout produced by
    /// `account_metadata_state_bytes`. Genesis creates its native accounts inside
    /// C++ (`create_native_account`), below the per-write mirror hooks, so the
    /// mirror seeds those rows here from chainbase once at init; rows created
    /// later by actions still flow through the live `create_account_metadata`
    /// path. A name already present is left untouched, so re-seeding is safe.
    pub fn hydrate_account_metadata(&self, bytes: &[u8]) -> Result<(), DbError> {
        const ROW: usize = 75;
        let mut db = self.lock();
        for chunk in bytes.chunks_exact(ROW) {
            let name = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            if db
                .find_by_hash::<AccountMetaRow, AccountMetaRowByName>(&name)?
                .is_some()
            {
                continue;
            }
            let privileged = chunk[8];
            let recv = u64::from_le_bytes(chunk[9..17].try_into().unwrap());
            let auth = u64::from_le_bytes(chunk[17..25].try_into().unwrap());
            let code = u64::from_le_bytes(chunk[25..33].try_into().unwrap());
            let abi = u64::from_le_bytes(chunk[33..41].try_into().unwrap());
            let mut code_hash = [0u8; 32];
            code_hash.copy_from_slice(&chunk[41..73]);
            let vm_type = chunk[73];
            let vm_version = chunk[74];
            db.create::<AccountMetaRow>(|r| {
                r.name = name;
                r.flags = privileged as u32;
                r.recv_sequence = recv;
                r.auth_sequence = auth;
                r.code_sequence = code;
                r.abi_sequence = abi;
                r.code_hash = code_hash;
                r.vm_type = vm_type;
                r.vm_version = vm_version;
            })?;
        }
        Ok(())
    }

    /// Whether the mirror holds an account_object row for `name` — for diffing
    /// against chainbase's `find_account`.
    pub fn account_exists(&self, name: u64) -> bool {
        self.lock()
            .find_by::<AccountRow, AccountRowByName>(&name)
            .ok()
            .flatten()
            .is_some()
    }

    pub fn set_privileged(&self, name: u64, privileged: bool) -> Result<(), DbError> {
        let mut db = self.lock();
        let id = db
            .find_by_hash::<AccountMetaRow, AccountMetaRowByName>(&name)?
            .map(|r| r.id());
        if let Some(id) = id {
            db.modify::<AccountMetaRow>(id, |row| {
                row.flags = if privileged {
                    row.flags | 1
                } else {
                    row.flags & !1
                };
            })?;
        }
        Ok(())
    }

    /// Mirrors `next_auth_sequence`: bumps the actor's account_metadata
    /// auth_sequence by one, matching chainbase's per-call increment. A missing
    /// row is a no-op — the caller only advances sequences for existing accounts.
    pub fn next_auth_sequence(&self, actor: u64) -> Result<(), DbError> {
        let mut db = self.lock();
        let id = db
            .find_by_hash::<AccountMetaRow, AccountMetaRowByName>(&actor)?
            .map(|r| r.id());
        if let Some(id) = id {
            db.modify::<AccountMetaRow>(id, |row| row.auth_sequence += 1)?;
        }
        Ok(())
    }

    /// Mirrors `next_recv_sequence`: bumps the receiver's account_metadata
    /// recv_sequence by one and returns the incremented value, matching
    /// chainbase's `++recv_sequence; return recv_sequence`. `None` if the account
    /// has no metadata row (chainbase takes a reference and can't be missing).
    pub fn next_recv_sequence(&self, receiver: u64) -> Result<Option<u64>, DbError> {
        let mut db = self.lock();
        let Some(id) = db
            .find_by_hash::<AccountMetaRow, AccountMetaRowByName>(&receiver)?
            .map(|r| r.id())
        else {
            return Ok(None);
        };
        db.modify::<AccountMetaRow>(id, |row| row.recv_sequence += 1)?;
        let bumped = db
            .find_by_hash::<AccountMetaRow, AccountMetaRowByName>(&receiver)?
            .map(|r| r.recv_sequence);
        Ok(bumped)
    }

    /// Mirrors `update_account_abi`: bumps the account_metadata abi_sequence and
    /// reassigns the account_object abi blob. Both rows are located by the name
    /// recovered from the metadata object's get_name accessor.
    pub fn update_account_abi(&self, name: u64, abi: &[u8]) -> Result<(), DbError> {
        let mut db = self.lock();

        let meta_id = db
            .find_by_hash::<AccountMetaRow, AccountMetaRowByName>(&name)?
            .map(|r| r.id());
        if let Some(id) = meta_id {
            db.modify::<AccountMetaRow>(id, |row| row.abi_sequence += 1)?;
        }

        let acct_id = db
            .find_by::<AccountRow, AccountRowByName>(&name)?
            .map(|r| r.id());
        if let Some(id) = acct_id {
            let abi_blob = db.alloc_blob::<AccountRow>(abi)?;
            db.modify::<AccountRow>(id, |row| row.abi = abi_blob)?;
        }
        Ok(())
    }

    // ----- account_object ---------------------------------------------------

    pub fn create_account(&self, name: u64, creation_date: u32) -> Result<(), DbError> {
        self.lock().create::<AccountRow>(|row| {
            row.name = name;
            row.creation_date = creation_date;
        })?;
        Ok(())
    }

    /// Canonical serialization of the whole account_object table in name order,
    /// matching the chainbase `account_state_bytes` enumerator: per row name u64
    /// LE, creation_date slot u32 LE, then a u32 LE length-prefixed abi blob.
    pub fn account_state_bytes(&self) -> Vec<u8> {
        let db = self.lock();
        let mut refs: Vec<(u64, u32, BlobRef)> = match db.table::<AccountRow>() {
            Ok(t) => t.iter().map(|r| (r.name, r.creation_date, r.abi)).collect(),
            Err(_) => return Vec::new(),
        };
        refs.sort_by_key(|r| r.0);
        let mut out = Vec::new();
        for (name, creation_date, abi_ref) in refs {
            out.extend_from_slice(&name.to_le_bytes());
            out.extend_from_slice(&creation_date.to_le_bytes());
            let abi = db.blob::<AccountRow>(abi_ref).unwrap_or(&[]);
            out.extend_from_slice(&(abi.len() as u32).to_le_bytes());
            out.extend_from_slice(abi);
        }
        out
    }

    /// Seeds account_object rows from the canonical layout — the genesis
    /// counterpart to `hydrate_account_metadata`, since `create_native_account`
    /// makes these below the mirror hooks (the system account even carries a
    /// non-empty abi). A name already present is left untouched.
    pub fn hydrate_accounts(&self, bytes: &[u8]) -> Result<(), DbError> {
        let mut db = self.lock();
        let mut pos = 0usize;
        while pos + 16 <= bytes.len() {
            let name = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
            let creation_date = u32::from_le_bytes(bytes[pos + 8..pos + 12].try_into().unwrap());
            let abi_len =
                u32::from_le_bytes(bytes[pos + 12..pos + 16].try_into().unwrap()) as usize;
            pos += 16;
            if pos + abi_len > bytes.len() {
                break;
            }
            let abi = &bytes[pos..pos + abi_len];
            pos += abi_len;
            if db.find_by::<AccountRow, AccountRowByName>(&name)?.is_some() {
                continue;
            }
            let blob = db.alloc_blob::<AccountRow>(abi)?;
            db.create::<AccountRow>(|r| {
                r.name = name;
                r.creation_date = creation_date;
                r.abi = blob;
            })?;
        }
        Ok(())
    }

    // ----- permission_object / permission_usage_object ----------------------

    /// Mirrors `create_permission`, which also creates the linked
    /// `permission_usage_object`. The usage row is created first so its id can be
    /// stored on the permission, exactly as the C++ path does.
    pub fn create_permission(
        &self,
        cb_id: i64,
        parent: i64,
        owner: u64,
        perm_name: u64,
        creation_time_us: i64,
        auth: &[u8],
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let usage_id = db
            .create::<PermissionUsageRow>(|p| p.last_used = creation_time_us)?
            .id()
            .raw();
        let auth_blob = db.alloc_blob::<PermissionRow>(auth)?;
        db.create::<PermissionRow>(|p| {
            p.cb_id = cb_id;
            p.usage_id = usage_id;
            p.parent = parent;
            p.owner = owner;
            p.perm_name = perm_name;
            p.last_updated = creation_time_us;
            p.auth = auth_blob;
        })?;
        // Stage 1 (verify-first): confirm the arena could author this permission's
        // id identically to chainbase before anything consumes the arena's value.
        // The counter is kept in lockstep with chainbase (resynced to cb_id + 1),
        // so every create is checked independently against chainbase's assignment
        // rather than a single divergence cascading, and the resync is undo-tracked
        // so it rolls back with the create. Skipped until the counter is seeded at
        // hydration. When this stays silent across the full replay (genesis, forks,
        // undo, snapshot reload), the arena is proven able to author the id itself.
        if let Some((_, expected)) = perm_seq_peek(&db)? {
            if expected != cb_id {
                eprintln!(
                    "arena permission-id authoring diverged: computed {expected} != chainbase {cb_id} (owner {owner}, name {perm_name})"
                );
            }
        }
        perm_seq_set(&mut db, cb_id + 1)?;
        Ok(())
    }

    pub fn modify_permission(
        &self,
        owner: u64,
        perm_name: u64,
        auth: &[u8],
        last_updated_us: i64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let id = db
            .find_by::<PermissionRow, PermByOwner>(&(owner, perm_name))?
            .map(|p| p.id());
        let Some(id) = id else { return Ok(()) };
        let auth_blob = db.alloc_blob::<PermissionRow>(auth)?;
        db.modify::<PermissionRow>(id, |p| {
            p.auth = auth_blob;
            p.last_updated = last_updated_us;
        })?;
        Ok(())
    }

    /// Permission snapshot for diffing: `(parent id, authority threshold)`. The
    /// threshold is the first field of the encoded `shared_authority` blob, so it
    /// is read straight off the blob without decoding the whole authority.
    pub fn permission(&self, owner: u64, perm_name: u64) -> Option<(i64, u32)> {
        let db = self.lock();
        let (parent, auth) = db
            .find_by::<PermissionRow, PermByOwner>(&(owner, perm_name))
            .ok()
            .flatten()
            .map(|p| (p.parent, p.auth))?;
        let bytes = db.blob::<PermissionRow>(auth).ok()?;
        let threshold = u32::from_le_bytes(bytes.get(0..4)?.try_into().ok()?);
        Some((parent, threshold))
    }

    /// The chainbase id a permission mirrors (`cb_id`), for serving `get_id` from
    /// the arena. `None` if the permission is absent.
    pub fn permission_cb_id(&self, owner: u64, perm_name: u64) -> Option<i64> {
        let db = self.lock();
        db.find_by::<PermissionRow, PermByOwner>(&(owner, perm_name))
            .ok()
            .flatten()
            .map(|p| p.cb_id)
    }

    /// The full encoded `shared_authority` blob for a permission (the same bytes
    /// the FFI seam stored via `encode_authority`), for serving the whole
    /// authority — not just the threshold — from the arena. `None` if absent.
    pub fn permission_auth_blob(&self, owner: u64, perm_name: u64) -> Option<Vec<u8>> {
        let db = self.lock();
        let auth = db
            .find_by::<PermissionRow, PermByOwner>(&(owner, perm_name))
            .ok()
            .flatten()
            .map(|p| p.auth)?;
        db.blob::<PermissionRow>(auth).ok().map(|b| b.to_vec())
    }

    /// Arena mirror of `permission_satisfies_other_permission`: does permission
    /// `(owner_a, name_a)` satisfy `(owner_b, name_b)` — i.e. is it that same
    /// permission, its immediate parent, or an ancestor up its parent chain, with
    /// a matching owner. Walks `other`'s parent chain by id exactly as the C++
    /// does. `None` if either permission is absent from the mirror.
    pub fn permission_satisfies(
        &self,
        owner_a: u64,
        name_a: u64,
        owner_b: u64,
        name_b: u64,
    ) -> Option<bool> {
        let db = self.lock();
        let (a_owner, a_id) = db
            .find_by::<PermissionRow, PermByOwner>(&(owner_a, name_a))
            .ok()
            .flatten()
            .map(|p| (p.owner, p.cb_id))?;
        let (b_owner, b_id, b_parent) = db
            .find_by::<PermissionRow, PermByOwner>(&(owner_b, name_b))
            .ok()
            .flatten()
            .map(|p| (p.owner, p.cb_id, p.parent))?;

        // Different owners can never satisfy each other.
        if a_owner != b_owner {
            return Some(false);
        }
        // `a` is `b`, or `a` is `b`'s immediate parent. Both sides are chainbase
        // ids (`cb_id`), so this navigates the same id space chainbase does.
        if a_id == b_id || a_id == b_parent {
            return Some(true);
        }
        // Walk up `b`'s parent chain by chainbase id, looking for `a`.
        let mut parent = db
            .find_by::<PermissionRow, PermByCbId>(&b_parent)
            .ok()
            .flatten();
        while let Some(par) = parent {
            if a_id == par.parent {
                return Some(true);
            }
            if par.parent == 0 {
                return Some(false);
            }
            parent = db
                .find_by::<PermissionRow, PermByCbId>(&par.parent)
                .ok()
                .flatten();
        }
        Some(false)
    }

    /// Canonical serialization of the whole permission table in (owner, perm_name)
    /// order, matching `Database::permission_state_bytes`: per row owner u64 LE,
    /// perm_name u64 LE, cb_id u64 LE, parent id u64 LE, last_used u64 LE, then a
    /// u32 LE length-prefixed authority blob (the arena stores the auth already in
    /// the shared encode form). The reserved perm 0 (owner 0) is skipped. `cb_id`
    /// and `parent` are chainbase ids the mirror stores verbatim, so they compare
    /// directly and, on hydration, give the arena the chainbase id space its
    /// permission-tree walk needs.
    pub fn permission_state_bytes(&self) -> Vec<u8> {
        let db = self.lock();
        let mut refs: Vec<(u64, u64, i64, i64, i64, BlobRef)> = match db.table::<PermissionRow>() {
            Ok(t) => t
                .iter()
                .filter(|p| p.owner != 0)
                .map(|p| {
                    // last_used lives on the linked permission_usage row.
                    let last_used = db
                        .find::<PermissionUsageRow>(ObjectId::new(p.usage_id))
                        .ok()
                        .flatten()
                        .map(|u| u.last_used)
                        .unwrap_or(0);
                    (p.owner, p.perm_name, p.cb_id, p.parent, last_used, p.auth)
                })
                .collect(),
            Err(_) => return Vec::new(),
        };
        refs.sort_by_key(|r| (r.0, r.1));
        let mut out = Vec::new();
        for (owner, perm_name, cb_id, parent, last_used, auth_ref) in refs {
            out.extend_from_slice(&owner.to_le_bytes());
            out.extend_from_slice(&perm_name.to_le_bytes());
            out.extend_from_slice(&(cb_id as u64).to_le_bytes());
            out.extend_from_slice(&(parent as u64).to_le_bytes());
            out.extend_from_slice(&(last_used as u64).to_le_bytes());
            let auth = db.blob::<PermissionRow>(auth_ref).unwrap_or(&[]);
            out.extend_from_slice(&(auth.len() as u32).to_le_bytes());
            out.extend_from_slice(auth);
        }
        out
    }

    /// Seeds permission rows (and their linked usage rows) from the canonical
    /// layout — genesis counterpart to `hydrate_accounts`, since
    /// `create_native_account` and the genesis block make several permissions in
    /// C++. last_updated/last_used are not part of the canonical form, so they
    /// are left at zero. A `(owner, perm_name)` already present is left untouched.
    pub fn hydrate_permissions(&self, bytes: &[u8]) -> Result<(), DbError> {
        let mut db = self.lock();
        let mut pos = 0usize;
        while pos + 44 <= bytes.len() {
            let owner = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
            let perm_name = u64::from_le_bytes(bytes[pos + 8..pos + 16].try_into().unwrap());
            let cb_id = u64::from_le_bytes(bytes[pos + 16..pos + 24].try_into().unwrap()) as i64;
            let parent = u64::from_le_bytes(bytes[pos + 24..pos + 32].try_into().unwrap()) as i64;
            let last_used =
                u64::from_le_bytes(bytes[pos + 32..pos + 40].try_into().unwrap()) as i64;
            let auth_len =
                u32::from_le_bytes(bytes[pos + 40..pos + 44].try_into().unwrap()) as usize;
            pos += 44;
            if pos + auth_len > bytes.len() {
                break;
            }
            let auth = &bytes[pos..pos + auth_len];
            pos += auth_len;
            if db
                .find_by::<PermissionRow, PermByOwner>(&(owner, perm_name))?
                .is_some()
            {
                continue;
            }
            let usage_id = db
                .create::<PermissionUsageRow>(|u| u.last_used = last_used)?
                .id()
                .raw();
            let blob = db.alloc_blob::<PermissionRow>(auth)?;
            db.create::<PermissionRow>(|p| {
                p.cb_id = cb_id;
                p.usage_id = usage_id;
                p.parent = parent;
                p.owner = owner;
                p.perm_name = perm_name;
                p.last_updated = 0;
                p.auth = blob;
            })?;
        }
        // Seed the replicated permission-id counter to chainbase's post-hydration
        // `_next_id`. Genesis numbers permissions contiguously from 1 (id 0 is
        // reserved), so that is max(cb_id) + 1 over the rows now present. Re-run on
        // every hydration (genesis and snapshot restore) since the arena is rebuilt
        // fresh each time.
        let max_cb = db
            .table::<PermissionRow>()?
            .iter()
            .map(|p| p.cb_id)
            .max()
            .unwrap_or(0);
        perm_seq_set(&mut db, max_cb + 1)?;
        Ok(())
    }

    /// Canonical serialization of permission_link in (account, code,
    /// message_type) order. No genesis rows (links come only from linkauth).
    pub fn permission_link_state_bytes(&self) -> Vec<u8> {
        let db = self.lock();
        let mut rows: Vec<(u64, u64, u64, u64)> = match db.table::<PermissionLinkRow>() {
            Ok(t) => t
                .iter()
                .map(|l| (l.account, l.code, l.message_type, l.required_permission))
                .collect(),
            Err(_) => return Vec::new(),
        };
        rows.sort_by_key(|r| (r.0, r.1, r.2));
        let mut out = Vec::new();
        for (account, code, message_type, required) in rows {
            out.extend_from_slice(&account.to_le_bytes());
            out.extend_from_slice(&code.to_le_bytes());
            out.extend_from_slice(&message_type.to_le_bytes());
            out.extend_from_slice(&required.to_le_bytes());
        }
        out
    }

    /// Canonical serialization of code_object in (code_hash, vm_type, vm_version)
    /// order: hash 32B, vm_type, vm_version, ref_count u64 LE, first_block u32 LE,
    /// then a u32 LE length-prefixed code blob. No genesis rows (setcode only).
    pub fn code_state_bytes(&self) -> Vec<u8> {
        let db = self.lock();
        let mut refs: Vec<([u8; 32], u8, u8, u64, u32, BlobRef)> = match db.table::<CodeRow>() {
            Ok(t) => t
                .iter()
                .map(|c| {
                    (
                        c.code_hash,
                        c.vm_type,
                        c.vm_version,
                        c.code_ref_count,
                        c.first_block_used,
                        c.code,
                    )
                })
                .collect(),
            Err(_) => return Vec::new(),
        };
        refs.sort_by_key(|r| (r.0, r.1, r.2));
        let mut out = Vec::new();
        for (hash, vm_type, vm_version, ref_count, first_block, code_ref) in refs {
            out.extend_from_slice(&hash);
            out.push(vm_type);
            out.push(vm_version);
            out.extend_from_slice(&ref_count.to_le_bytes());
            out.extend_from_slice(&first_block.to_le_bytes());
            let code = db.blob::<CodeRow>(code_ref).unwrap_or(&[]);
            out.extend_from_slice(&(code.len() as u32).to_le_bytes());
            out.extend_from_slice(code);
        }
        out
    }

    /// Canonical serialization of the transaction dedupe set in trx_id order:
    /// trx_id 32B, expiration u32 LE (seconds). No genesis rows.
    pub fn transaction_state_bytes(&self) -> Vec<u8> {
        let db = self.lock();
        let mut rows: Vec<([u8; 32], u32)> = match db.table::<TransactionRow>() {
            Ok(t) => t.iter().map(|t| (t.trx_id, t.expiration)).collect(),
            Err(_) => return Vec::new(),
        };
        rows.sort_by_key(|r| r.0);
        let mut out = Vec::new();
        for (trx_id, expiration) in rows {
            out.extend_from_slice(&trx_id);
            out.extend_from_slice(&expiration.to_le_bytes());
        }
        out
    }

    /// Canonical serialization of resource_usage in owner order: owner u64 LE,
    /// ram_usage u64 LE, then the net and cpu accumulators.
    pub fn resource_usage_state_bytes(&self) -> Vec<u8> {
        let db = self.lock();
        let mut rows: Vec<(u64, u64, UsageAccumulator, UsageAccumulator)> =
            match db.table::<ResourceUsageRow>() {
                Ok(t) => t
                    .iter()
                    .map(|r| (r.owner, r.ram_usage, r.net_usage, r.cpu_usage))
                    .collect(),
                Err(_) => return Vec::new(),
            };
        rows.sort_by_key(|r| r.0);
        let mut out = Vec::new();
        let put_acc = |out: &mut Vec<u8>, a: &UsageAccumulator| {
            out.extend_from_slice(&a.value_ex.to_le_bytes());
            out.extend_from_slice(&a.consumed.to_le_bytes());
            out.extend_from_slice(&a.last_ordinal.to_le_bytes());
        };
        for (owner, ram, net, cpu) in rows {
            out.extend_from_slice(&owner.to_le_bytes());
            out.extend_from_slice(&ram.to_le_bytes());
            put_acc(&mut out, &net);
            put_acc(&mut out, &cpu);
        }
        out
    }

    /// Seeds resource_usage rows from the canonical layout — genesis native
    /// accounts get their rows (and billed ram) inside C++. A present owner is
    /// left untouched.
    pub fn hydrate_resource_usage(&self, bytes: &[u8]) -> Result<(), DbError> {
        const ROW: usize = 8 + 8 + 20 + 20; // owner, ram, net acc, cpu acc
        let mut db = self.lock();
        for c in bytes.chunks_exact(ROW) {
            let owner = u64::from_le_bytes(c[0..8].try_into().unwrap());
            if db
                .find_by::<ResourceUsageRow, ResourceUsageRowByOwner>(&owner)?
                .is_some()
            {
                continue;
            }
            let ram = u64::from_le_bytes(c[8..16].try_into().unwrap());
            let net = read_acc(&c[16..36]);
            let cpu = read_acc(&c[36..56]);
            db.create::<ResourceUsageRow>(|r| {
                r.owner = owner;
                r.ram_usage = ram;
                r.net_usage = net;
                r.cpu_usage = cpu;
            })?;
        }
        Ok(())
    }

    /// Canonical serialization of resource_limits in (pending, owner) order.
    pub fn account_limits_state_bytes(&self) -> Vec<u8> {
        let db = self.lock();
        let mut rows: Vec<(u8, u64, i64, i64, i64)> = match db.table::<ResourceLimitsRow>() {
            Ok(t) => t
                .iter()
                .map(|r| (r.pending, r.owner, r.ram_bytes, r.net_weight, r.cpu_weight))
                .collect(),
            Err(_) => return Vec::new(),
        };
        rows.sort_by_key(|r| (r.0, r.1));
        let mut out = Vec::new();
        for (pending, owner, ram, net, cpu) in rows {
            out.push(pending);
            out.extend_from_slice(&owner.to_le_bytes());
            out.extend_from_slice(&(ram as u64).to_le_bytes());
            out.extend_from_slice(&(net as u64).to_le_bytes());
            out.extend_from_slice(&(cpu as u64).to_le_bytes());
        }
        out
    }

    /// Seeds resource_limits rows from the canonical layout (genesis native
    /// accounts). A present `(pending, owner)` is left untouched.
    pub fn hydrate_account_limits(&self, bytes: &[u8]) -> Result<(), DbError> {
        const ROW: usize = 1 + 8 + 8 + 8 + 8;
        let mut db = self.lock();
        for c in bytes.chunks_exact(ROW) {
            let pending = c[0];
            let owner = u64::from_le_bytes(c[1..9].try_into().unwrap());
            if db
                .find_by::<ResourceLimitsRow, LimitsByOwner>(&(pending, owner))?
                .is_some()
            {
                continue;
            }
            let ram = u64::from_le_bytes(c[9..17].try_into().unwrap()) as i64;
            let net = u64::from_le_bytes(c[17..25].try_into().unwrap()) as i64;
            let cpu = u64::from_le_bytes(c[25..33].try_into().unwrap()) as i64;
            db.create::<ResourceLimitsRow>(|r| {
                r.pending = pending;
                r.owner = owner;
                r.ram_bytes = ram;
                r.net_weight = net;
                r.cpu_weight = cpu;
            })?;
        }
        Ok(())
    }

    /// Canonical serialization of the resource_limits_state singleton: the net
    /// and cpu block-usage accumulators, then pending/total/virtual scalars.
    pub fn resource_state_bytes(&self) -> Vec<u8> {
        let db = self.lock();
        let s = match db.table::<ResourceStateRow>() {
            Ok(t) => match t.iter().next() {
                Some(s) => *s,
                None => return Vec::new(),
            },
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        let put_acc = |out: &mut Vec<u8>, a: &UsageAccumulator| {
            out.extend_from_slice(&a.value_ex.to_le_bytes());
            out.extend_from_slice(&a.consumed.to_le_bytes());
            out.extend_from_slice(&a.last_ordinal.to_le_bytes());
        };
        put_acc(&mut out, &s.average_block_net_usage);
        put_acc(&mut out, &s.average_block_cpu_usage);
        out.extend_from_slice(&s.pending_net_usage.to_le_bytes());
        out.extend_from_slice(&s.pending_cpu_usage.to_le_bytes());
        out.extend_from_slice(&s.total_net_weight.to_le_bytes());
        out.extend_from_slice(&s.total_cpu_weight.to_le_bytes());
        out.extend_from_slice(&s.total_ram_bytes.to_le_bytes());
        out.extend_from_slice(&s.virtual_net_limit.to_le_bytes());
        out.extend_from_slice(&s.virtual_cpu_limit.to_le_bytes());
        out
    }

    /// Canonical serialization of the contract table_id_object rows in
    /// (code, scope, table) order: code, scope, table, payer (u64 LE each),
    /// count (u32 LE). No genesis rows (contracts create tables at runtime).
    pub fn contract_table_state_bytes(&self) -> Vec<u8> {
        let db = self.lock();
        let mut rows: Vec<(u64, u64, u64, u64, u32)> = match db.table::<ContractTableRow>() {
            Ok(t) => t
                .iter()
                .map(|r| (r.code, r.scope, r.table, r.payer, r.count))
                .collect(),
            Err(_) => return Vec::new(),
        };
        rows.sort_by_key(|r| (r.0, r.1, r.2));
        let mut out = Vec::new();
        for (code, scope, table, payer, count) in rows {
            out.extend_from_slice(&code.to_le_bytes());
            out.extend_from_slice(&scope.to_le_bytes());
            out.extend_from_slice(&table.to_le_bytes());
            out.extend_from_slice(&payer.to_le_bytes());
            out.extend_from_slice(&count.to_le_bytes());
        }
        out
    }

    /// Canonical serialization of the contract key_value rows in
    /// (code, scope, table, primary_key) order, with the table identity resolved
    /// from `t_id` (so the arena's own ids are never serialized): code, scope,
    /// table, primary_key, payer (u64 LE each), then a length-prefixed value.
    pub fn contract_kv_state_bytes(&self) -> Vec<u8> {
        use std::collections::HashMap;
        let db = self.lock();
        let table_key: HashMap<i64, (u64, u64, u64)> = match db.table::<ContractTableRow>() {
            Ok(t) => t
                .iter()
                .map(|r| (r.id().raw(), (r.code, r.scope, r.table)))
                .collect(),
            Err(_) => return Vec::new(),
        };
        let mut refs: Vec<(u64, u64, u64, u64, u64, BlobRef)> =
            match db.table::<ContractKeyValueRow>() {
                Ok(t) => t
                    .iter()
                    .filter_map(|r| {
                        table_key
                            .get(&r.t_id)
                            .map(|&(c, s, tb)| (c, s, tb, r.primary_key, r.payer, r.value))
                    })
                    .collect(),
                Err(_) => return Vec::new(),
            };
        refs.sort_by_key(|r| (r.0, r.1, r.2, r.3));
        let mut out = Vec::new();
        for (code, scope, table, primary, payer, value_ref) in refs {
            out.extend_from_slice(&code.to_le_bytes());
            out.extend_from_slice(&scope.to_le_bytes());
            out.extend_from_slice(&table.to_le_bytes());
            out.extend_from_slice(&primary.to_le_bytes());
            out.extend_from_slice(&payer.to_le_bytes());
            let value = db.blob::<ContractKeyValueRow>(value_ref).unwrap_or(&[]);
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    /// Mirrors `remove_permission` (and the `delete_auth` path that calls it):
    /// removes the permission and its linked `permission_usage_object`.
    pub fn remove_permission(&self, owner: u64, perm_name: u64) -> Result<(), DbError> {
        let mut db = self.lock();
        let found = db
            .find_by::<PermissionRow, PermByOwner>(&(owner, perm_name))?
            .map(|p| (p.id(), p.usage_id));
        let Some((id, usage_id)) = found else {
            return Ok(());
        };
        db.remove::<PermissionUsageRow>(ObjectId::new(usage_id))?;
        db.remove::<PermissionRow>(id)?;
        Ok(())
    }

    pub fn update_permission_usage(
        &self,
        owner: u64,
        perm_name: u64,
        last_used_us: i64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let usage_id = db
            .find_by::<PermissionRow, PermByOwner>(&(owner, perm_name))?
            .map(|p| p.usage_id);
        let Some(usage_id) = usage_id else {
            return Ok(());
        };
        db.modify::<PermissionUsageRow>(ObjectId::new(usage_id), |p| p.last_used = last_used_us)?;
        Ok(())
    }

    // ----- permission_link_object -------------------------------------------

    /// Mirrors `link_auth`: updates an existing link's required permission, or
    /// creates a new link when none exists for `(account, code, message_type)`.
    pub fn link_auth(
        &self,
        account: u64,
        code: u64,
        message_type: u64,
        required_permission: u64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let existing = db
            .find_by::<PermissionLinkRow, LinkByActionName>(&(account, code, message_type))?
            .map(|l| l.id());
        match existing {
            Some(id) => {
                db.modify::<PermissionLinkRow>(id, |l| {
                    l.required_permission = required_permission
                })?;
            }
            None => {
                db.create::<PermissionLinkRow>(|l| {
                    l.account = account;
                    l.code = code;
                    l.message_type = message_type;
                    l.required_permission = required_permission;
                })?;
            }
        }
        Ok(())
    }

    pub fn unlink_auth(&self, account: u64, code: u64, message_type: u64) -> Result<(), DbError> {
        let mut db = self.lock();
        let id = db
            .find_by::<PermissionLinkRow, LinkByActionName>(&(account, code, message_type))?
            .map(|l| l.id());
        if let Some(id) = id {
            db.remove::<PermissionLinkRow>(id)?;
        }
        Ok(())
    }

    /// Required permission of the mirrored `permission_link_object` for
    /// `(account, code, message_type)`, or `None` when absent — for diffing
    /// against chainbase's `find_permission_link`.
    pub fn permission_link(&self, account: u64, code: u64, message_type: u64) -> Option<u64> {
        self.lock()
            .find_by::<PermissionLinkRow, LinkByActionName>(&(account, code, message_type))
            .ok()
            .flatten()
            .map(|l| l.required_permission)
    }

    // ----- resource_usage (RAM) ---------------------------------------------

    /// Mirrors `initialize_account_resource_limits`: creates the account's
    /// resource_usage row (zero RAM) and its committed resource_limits row (-1
    /// unlimited on every dimension), matching chainbase.
    pub fn initialize_account_resource_limits(&self, owner: u64) -> Result<(), DbError> {
        let mut db = self.lock();
        db.create::<ResourceUsageRow>(|r| {
            r.owner = owner;
            r.ram_usage = 0;
        })?;
        db.create::<ResourceLimitsRow>(|r| {
            r.owner = owner;
            r.pending = 0;
            r.ram_bytes = -1;
            r.net_weight = -1;
            r.cpu_weight = -1;
        })?;
        Ok(())
    }

    /// Mirrors `set_account_limits`: stages the new limits on a pending row,
    /// creating it as a copy of the committed row on first change (matching
    /// chainbase's find-or-create-pending). The global weight totals are updated
    /// on commit in `process_account_limit_updates`, not here.
    pub fn set_account_limits(
        &self,
        account: u64,
        ram_bytes: i64,
        net_weight: i64,
        cpu_weight: i64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let pending = db
            .find_by::<ResourceLimitsRow, LimitsByOwner>(&(1u8, account))?
            .map(|r| r.id());
        let id = match pending {
            Some(id) => id,
            None => {
                let actual = db
                    .find_by::<ResourceLimitsRow, LimitsByOwner>(&(0u8, account))?
                    .map(|r| (r.ram_bytes, r.net_weight, r.cpu_weight));
                let Some((a_ram, a_net, a_cpu)) = actual else {
                    return Ok(());
                };
                db.create::<ResourceLimitsRow>(|r| {
                    r.owner = account;
                    r.pending = 1;
                    r.ram_bytes = a_ram;
                    r.net_weight = a_net;
                    r.cpu_weight = a_cpu;
                })?
                .id()
            }
        };
        db.modify::<ResourceLimitsRow>(id, |r| {
            r.ram_bytes = ram_bytes;
            r.net_weight = net_weight;
            r.cpu_weight = cpu_weight;
        })?;
        Ok(())
    }

    /// Mirrors the account-row half of `process_account_limit_updates`: copies
    /// each pending row onto its committed row and drops the pending row. The
    /// global total-weight bookkeeping is not mirrored (separate object).
    pub fn process_account_limit_updates(&self) -> Result<(), DbError> {
        let mut db = self.lock();
        let pendings: Vec<(ObjectId<ResourceLimitsRow>, u64, i64, i64, i64)> = {
            let table = db.table::<ResourceLimitsRow>()?;
            table
                .iter()
                .filter(|r| r.pending == 1)
                .map(|r| (r.id(), r.owner, r.ram_bytes, r.net_weight, r.cpu_weight))
                .collect()
        };
        let state_id = db
            .table::<ResourceStateRow>()?
            .iter()
            .next()
            .map(|s| s.id());
        // update_state_and_value: revert the old value from the total (if > 0)
        // and apply the new one (if > 0) — chainbase's total-weight bookkeeping.
        let update_total = |total: &mut u64, old: i64, new: i64| {
            if old > 0 {
                *total -= old as u64;
            }
            if new > 0 {
                *total += new as u64;
            }
        };
        for (pending_id, owner, ram_bytes, net_weight, cpu_weight) in pendings {
            let actual = db
                .find_by::<ResourceLimitsRow, LimitsByOwner>(&(0u8, owner))?
                .map(|r| (r.id(), r.ram_bytes, r.net_weight, r.cpu_weight));
            if let Some((actual_id, old_ram, old_net, old_cpu)) = actual {
                db.modify::<ResourceLimitsRow>(actual_id, |r| {
                    r.ram_bytes = ram_bytes;
                    r.net_weight = net_weight;
                    r.cpu_weight = cpu_weight;
                })?;
                if let Some(sid) = state_id {
                    db.modify::<ResourceStateRow>(sid, |s| {
                        update_total(&mut s.total_ram_bytes, old_ram, ram_bytes);
                        update_total(&mut s.total_net_weight, old_net, net_weight);
                        update_total(&mut s.total_cpu_weight, old_cpu, cpu_weight);
                    })?;
                }
            }
            db.remove::<ResourceLimitsRow>(pending_id)?;
        }
        Ok(())
    }

    /// Effective limits `(ram_bytes, net_weight, cpu_weight)` for `account` —
    /// pending row if one is staged, else the committed row — mirroring
    /// chainbase's `get_account_limits`.
    pub fn account_limits(&self, account: u64) -> Option<(i64, i64, i64)> {
        let db = self.lock();
        if let Some(r) = db
            .find_by::<ResourceLimitsRow, LimitsByOwner>(&(1u8, account))
            .ok()
            .flatten()
        {
            return Some((r.ram_bytes, r.net_weight, r.cpu_weight));
        }
        db.find_by::<ResourceLimitsRow, LimitsByOwner>(&(0u8, account))
            .ok()
            .flatten()
            .map(|r| (r.ram_bytes, r.net_weight, r.cpu_weight))
    }

    // ----- resource_limits_state (block usage + elastic virtual limits) -----

    /// Mirrors the state singleton `initialize_database`/`initialize_resource_
    /// limits` creates: virtual limits seeded to each resource's max (chainbase's
    /// slow-start), everything else zero. Idempotent — a second call is ignored
    /// so the genesis and direct-init paths cannot double-create the row.
    pub fn initialize_resource_state(&self, cpu_max: u64, net_max: u64) -> Result<(), DbError> {
        let mut db = self.lock();
        if db.table::<ResourceStateRow>()?.iter().next().is_some() {
            return Ok(());
        }
        db.create::<ResourceStateRow>(|s| {
            s.virtual_cpu_limit = cpu_max;
            s.virtual_net_limit = net_max;
        })?;
        Ok(())
    }

    /// Mirrors the block-accounting half of `add_transaction_usage`: adds the
    /// billed units to the block's pending totals on the state singleton.
    pub fn add_block_usage(&self, cpu_usage: u64, net_usage: u64) -> Result<(), DbError> {
        let mut db = self.lock();
        let id = db
            .table::<ResourceStateRow>()?
            .iter()
            .next()
            .map(|s| s.id());
        if let Some(id) = id {
            db.modify::<ResourceStateRow>(id, |s| {
                s.pending_cpu_usage += cpu_usage;
                s.pending_net_usage += net_usage;
            })?;
        }
        Ok(())
    }

    /// Mirrors `process_block_usage`: folds the block's pending usage into the
    /// windowed averages, recomputes the elastic virtual limits, and clears the
    /// pending totals — matching chainbase step for step.
    pub fn process_block_usage(
        &self,
        block_num: u32,
        cpu: ElasticParams,
        net: ElasticParams,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let id = db
            .table::<ResourceStateRow>()?
            .iter()
            .next()
            .map(|s| s.id());
        if let Some(id) = id {
            db.modify::<ResourceStateRow>(id, |s| {
                s.average_block_cpu_usage
                    .add(s.pending_cpu_usage, block_num, cpu.periods);
                s.virtual_cpu_limit = update_elastic_limit(
                    s.virtual_cpu_limit,
                    s.average_block_cpu_usage.average(),
                    &cpu,
                );
                s.pending_cpu_usage = 0;

                s.average_block_net_usage
                    .add(s.pending_net_usage, block_num, net.periods);
                s.virtual_net_limit = update_elastic_limit(
                    s.virtual_net_limit,
                    s.average_block_net_usage.average(),
                    &net,
                );
                s.pending_net_usage = 0;
            })?;
        }
        Ok(())
    }

    /// Mirrored `(virtual_cpu_limit, virtual_net_limit)`, or `None` if the state
    /// row is absent — for diffing against chainbase.
    pub fn state_virtual_limits(&self) -> Option<(u64, u64)> {
        self.lock()
            .table::<ResourceStateRow>()
            .ok()?
            .iter()
            .next()
            .map(|s| (s.virtual_cpu_limit, s.virtual_net_limit))
    }

    /// Mirrors `add_pending_ram_usage`: applies the externally-computed byte
    /// delta to the account's mirrored ram_usage. Chainbase guards against
    /// over/underflow before this runs, so the signed accumulation is safe.
    pub fn add_pending_ram_usage(&self, owner: u64, ram_delta: i64) -> Result<(), DbError> {
        if ram_delta == 0 {
            return Ok(());
        }
        let mut db = self.lock();
        let id = db
            .find_by::<ResourceUsageRow, ResourceUsageRowByOwner>(&owner)?
            .map(|r| r.id());
        if let Some(id) = id {
            db.modify::<ResourceUsageRow>(id, |r| {
                r.ram_usage = (r.ram_usage as i64 + ram_delta) as u64;
            })?;
        }
        Ok(())
    }

    /// Mirrored RAM usage for `owner`, or `None` if absent — for diffing against
    /// chainbase's `get_account_ram_usage`.
    pub fn account_ram_usage(&self, owner: u64) -> Option<u64> {
        self.lock()
            .find_by::<ResourceUsageRow, ResourceUsageRowByOwner>(&owner)
            .ok()
            .flatten()
            .map(|r| r.ram_usage)
    }

    /// Mirrors `add_transaction_usage`: advances the account's net/cpu usage
    /// accumulators by the billed units at `time_slot`. The windows come from
    /// chainbase config (passed in by the caller, which has the Database handle).
    pub fn add_transaction_usage(
        &self,
        owner: u64,
        cpu_usage: u64,
        net_usage: u64,
        time_slot: u32,
        net_window: u32,
        cpu_window: u32,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let id = db
            .find_by::<ResourceUsageRow, ResourceUsageRowByOwner>(&owner)?
            .map(|r| r.id());
        if let Some(id) = id {
            db.modify::<ResourceUsageRow>(id, |r| {
                r.net_usage.add(net_usage, time_slot, net_window);
                r.cpu_usage.add(cpu_usage, time_slot, cpu_window);
            })?;
        }
        Ok(())
    }

    /// Mirrors `update_account_usage`: decays the account's net/cpu accumulators
    /// to `time_slot` by adding zero units (the same call chainbase makes).
    pub fn update_account_usage(
        &self,
        owner: u64,
        time_slot: u32,
        net_window: u32,
        cpu_window: u32,
    ) -> Result<(), DbError> {
        self.add_transaction_usage(owner, 0, 0, time_slot, net_window, cpu_window)
    }

    /// Mirrored net_usage `value_ex` (the pre-multiplied accumulator state) for
    /// `owner` — for exact diffing against chainbase.
    pub fn account_net_usage_value_ex(&self, owner: u64) -> Option<u64> {
        self.lock()
            .find_by::<ResourceUsageRow, ResourceUsageRowByOwner>(&owner)
            .ok()
            .flatten()
            .map(|r| r.net_usage.value_ex)
    }

    /// Mirrored cpu_usage `value_ex` for `owner` — for exact diffing against
    /// chainbase.
    pub fn account_cpu_usage_value_ex(&self, owner: u64) -> Option<u64> {
        self.lock()
            .find_by::<ResourceUsageRow, ResourceUsageRowByOwner>(&owner)
            .ok()
            .flatten()
            .map(|r| r.cpu_usage.value_ex)
    }

    // ----- code_object ------------------------------------------------------

    /// Mirrors `update_account_code`: bumps the `account_metadata_object` code
    /// fields for `name` (code_hash, code_sequence++, vm_type, vm_version,
    /// last_code_update) and the `code_object` ref count for a non-empty image.
    /// `name` comes from the metadata object's `get_name` accessor added to the
    /// FFI, which is what lets the mirror locate the arena row that the C++ call
    /// reaches only by reference.
    pub fn update_account_code(
        &self,
        name: u64,
        code: &[u8],
        code_hash: [u8; 32],
        head_block_num: u32,
        vm_type: u8,
        vm_version: u8,
    ) -> Result<(), DbError> {
        let mut db = self.lock();

        let meta_id = db
            .find_by_hash::<AccountMetaRow, AccountMetaRowByName>(&name)?
            .map(|r| r.id());
        if let Some(id) = meta_id {
            db.modify::<AccountMetaRow>(id, |row| {
                row.code_hash = code_hash;
                row.code_sequence += 1;
                row.vm_type = vm_type;
                row.vm_version = vm_version;
                row.last_code_update = head_block_num as i64;
            })?;
        }

        if code.is_empty() {
            return Ok(());
        }
        let existing = db
            .find_by::<CodeRow, CodeByHash>(&(code_hash, vm_type, vm_version))?
            .map(|c| c.id());
        match existing {
            Some(id) => db.modify::<CodeRow>(id, |c| c.code_ref_count += 1)?,
            None => {
                let code_blob = db.alloc_blob::<CodeRow>(code)?;
                db.create::<CodeRow>(|c| {
                    c.code_hash = code_hash;
                    c.code = code_blob;
                    c.code_ref_count = 1;
                    c.first_block_used = head_block_num.wrapping_add(1);
                    c.vm_type = vm_type;
                    c.vm_version = vm_version;
                })?;
            }
        }
        Ok(())
    }

    /// The wasm image for `(code_hash, vm_type, vm_version)`, or `None` if the
    /// code row is absent. This is the bytecode the VM compiles and runs, so
    /// serving it from the arena is what puts contract execution on arena-owned
    /// code; it must be byte-identical to chainbase's `code_object::code`.
    pub fn code_by_hash(
        &self,
        code_hash: [u8; 32],
        vm_type: u8,
        vm_version: u8,
    ) -> Option<Vec<u8>> {
        let db = self.lock();
        let code_ref = db
            .find_by::<CodeRow, CodeByHash>(&(code_hash, vm_type, vm_version))
            .ok()
            .flatten()
            .map(|c| c.code)?;
        db.blob::<CodeRow>(code_ref).ok().map(|b| b.to_vec())
    }

    /// Mirrors `unlink_account_code`: drops the ref count of the code row and
    /// removes it at zero. The FFI `code_object` exposes only its hash, not
    /// `vm_type`/`vm_version`, so the row is located by hash; a hash is unique
    /// across the code table in practice.
    pub fn unlink_account_code(&self, code_hash: [u8; 32]) -> Result<(), DbError> {
        let mut db = self.lock();
        let found = {
            let table = db.table::<CodeRow>()?;
            table
                .iter()
                .find(|c| c.code_hash == code_hash)
                .map(|c| (c.id(), c.code_ref_count))
        };
        let Some((id, ref_count)) = found else {
            return Ok(());
        };
        if ref_count <= 1 {
            db.remove::<CodeRow>(id)?;
        } else {
            db.modify::<CodeRow>(id, |c| c.code_ref_count -= 1)?;
        }
        Ok(())
    }

    // ----- dynamic_global_property_object -----------------------------------

    /// Mirrors `next_global_sequence`, which returns the post-increment global
    /// action sequence. The mirror stores that value into its singleton row,
    /// creating the row on first use (genesis creates the chainbase row on the
    /// C++ side, so the mirror never sees its initial `0`).
    pub fn set_global_action_sequence(&self, value: u64) -> Result<(), DbError> {
        let mut db = self.lock();
        let existing = db
            .table::<DynGlobalPropertyRow>()?
            .iter()
            .next()
            .map(|r| r.id());
        match existing {
            Some(id) => {
                db.modify::<DynGlobalPropertyRow>(id, |r| r.global_action_sequence = value)?
            }
            None => {
                db.create::<DynGlobalPropertyRow>(|r| r.global_action_sequence = value)?;
            }
        }
        Ok(())
    }

    /// Mirrored `global_action_sequence`, or `None` if the singleton row has not
    /// been written yet — for diffing against chainbase.
    pub fn global_action_sequence(&self) -> Option<u64> {
        self.lock()
            .table::<DynGlobalPropertyRow>()
            .ok()?
            .iter()
            .next()
            .map(|r| r.global_action_sequence)
    }

    // ----- global_property_object (static chain_config) ---------------------

    /// Mirrors a write to the static `global_property_object`: creates the
    /// singleton `chain_config` row on first call (genesis seed) and modifies it
    /// in place thereafter (`setparams`).
    pub fn set_global_properties(&self, p: ChainConfigParams) -> Result<(), DbError> {
        let mut db = self.lock();
        let apply = |r: &mut GlobalPropertyRow| {
            r.max_block_net_usage = p.max_block_net_usage;
            r.target_block_net_usage_pct = p.target_block_net_usage_pct;
            r.max_transaction_net_usage = p.max_transaction_net_usage;
            r.base_per_transaction_net_usage = p.base_per_transaction_net_usage;
            r.net_usage_leeway = p.net_usage_leeway;
            r.context_free_discount_net_usage_num = p.context_free_discount_net_usage_num;
            r.context_free_discount_net_usage_den = p.context_free_discount_net_usage_den;
            r.max_block_cpu_usage = p.max_block_cpu_usage;
            r.target_block_cpu_usage_pct = p.target_block_cpu_usage_pct;
            r.max_transaction_cpu_usage = p.max_transaction_cpu_usage;
            r.min_transaction_cpu_usage = p.min_transaction_cpu_usage;
            r.max_transaction_lifetime = p.max_transaction_lifetime;
            r.max_transaction_delay = p.max_transaction_delay;
            r.max_inline_action_size = p.max_inline_action_size;
            r.max_inline_action_depth = p.max_inline_action_depth;
            r.max_authority_depth = p.max_authority_depth;
        };
        let existing = db
            .table::<GlobalPropertyRow>()?
            .iter()
            .next()
            .map(|r| r.id());
        match existing {
            Some(id) => db.modify::<GlobalPropertyRow>(id, apply)?,
            None => {
                db.create::<GlobalPropertyRow>(apply)?;
            }
        }
        Ok(())
    }

    /// Canonical serialization of the mirrored `chain_config` (16 fields, little
    /// endian, `ChainConfigV0` order), or empty when the singleton has not been
    /// seeded — byte-compatible with the chainbase `global_property_state_bytes`.
    pub fn global_property_state_bytes(&self) -> Vec<u8> {
        let db = self.lock();
        match db
            .table::<GlobalPropertyRow>()
            .ok()
            .and_then(|t| t.iter().next().copied())
        {
            Some(r) => r.params().to_state_bytes(),
            None => Vec::new(),
        }
    }

    // ----- resource_limits_config_object ------------------------------------

    /// Seeds the singleton `resource_limits_config` mirror from chainbase at
    /// genesis: elastic cpu/net params plus the two averaging windows.
    pub fn seed_resource_config(
        &self,
        cpu: ElasticParams,
        net: ElasticParams,
        cpu_window: u32,
        net_window: u32,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let apply = |r: &mut ResourceConfigRow| {
            Self::apply_elastic(r, &cpu, &net);
            r.account_cpu_usage_average_window = cpu_window;
            r.account_net_usage_average_window = net_window;
        };
        let existing = db
            .table::<ResourceConfigRow>()?
            .iter()
            .next()
            .map(|r| r.id());
        match existing {
            Some(id) => db.modify::<ResourceConfigRow>(id, apply)?,
            None => {
                db.create::<ResourceConfigRow>(apply)?;
            }
        }
        Ok(())
    }

    /// Mirrors `set_block_parameters`: updates only the elastic cpu/net params of
    /// the singleton (the averaging windows are genesis constants, left as seeded).
    pub fn set_block_parameters(
        &self,
        cpu: ElasticParams,
        net: ElasticParams,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let apply = |r: &mut ResourceConfigRow| Self::apply_elastic(r, &cpu, &net);
        let existing = db
            .table::<ResourceConfigRow>()?
            .iter()
            .next()
            .map(|r| r.id());
        match existing {
            Some(id) => db.modify::<ResourceConfigRow>(id, apply)?,
            None => {
                db.create::<ResourceConfigRow>(apply)?;
            }
        }
        Ok(())
    }

    fn apply_elastic(r: &mut ResourceConfigRow, cpu: &ElasticParams, net: &ElasticParams) {
        r.cpu_target = cpu.target;
        r.cpu_max = cpu.max;
        r.cpu_periods = cpu.periods;
        r.cpu_max_multiplier = cpu.max_multiplier;
        r.cpu_contract_num = cpu.contract.0;
        r.cpu_contract_den = cpu.contract.1;
        r.cpu_expand_num = cpu.expand.0;
        r.cpu_expand_den = cpu.expand.1;
        r.net_target = net.target;
        r.net_max = net.max;
        r.net_periods = net.periods;
        r.net_max_multiplier = net.max_multiplier;
        r.net_contract_num = net.contract.0;
        r.net_contract_den = net.contract.1;
        r.net_expand_num = net.expand.0;
        r.net_expand_den = net.expand.1;
    }

    /// Canonical serialization of the mirrored `resource_limits_config`, or empty
    /// when unseeded — byte-compatible with the chainbase `resource_config_state_bytes`.
    pub fn resource_config_state_bytes(&self) -> Vec<u8> {
        let db = self.lock();
        let Some(r) = db
            .table::<ResourceConfigRow>()
            .ok()
            .and_then(|t| t.iter().next().copied())
        else {
            return Vec::new();
        };
        let cpu = ElasticParams {
            target: r.cpu_target,
            max: r.cpu_max,
            periods: r.cpu_periods,
            max_multiplier: r.cpu_max_multiplier,
            contract: (r.cpu_contract_num, r.cpu_contract_den),
            expand: (r.cpu_expand_num, r.cpu_expand_den),
        };
        let net = ElasticParams {
            target: r.net_target,
            max: r.net_max,
            periods: r.net_periods,
            max_multiplier: r.net_max_multiplier,
            contract: (r.net_contract_num, r.net_contract_den),
            expand: (r.net_expand_num, r.net_expand_den),
        };
        serialize_resource_config(
            &cpu,
            &net,
            r.account_cpu_usage_average_window,
            r.account_net_usage_average_window,
        )
    }

    // ----- transaction_object -----------------------------------------------

    /// Mirrors `record_transaction`: inserts a dedupe entry keyed by `trx_id`
    /// with its `expiration` (whole seconds).
    pub fn record_transaction(&self, trx_id: [u8; 32], expiration: u32) -> Result<(), DbError> {
        self.lock().create::<TransactionRow>(|t| {
            t.trx_id = trx_id;
            t.expiration = expiration;
        })?;
        Ok(())
    }

    /// Whether the mirror holds a dedupe row for `trx_id` — for diffing against
    /// chainbase's `is_known_unexpired_transaction`.
    pub fn transaction_exists(&self, trx_id: [u8; 32]) -> bool {
        self.lock()
            .find_by::<TransactionRow, TxByTrxId>(&trx_id)
            .ok()
            .flatten()
            .is_some()
    }

    /// Mirrors `clear_expired_input_transactions`: drops every row whose
    /// expiration falls strictly before `cutoff` (both in microseconds, as the
    /// C++ compares `cutoff > expiration.to_time_point()`). Expirations are whole
    /// seconds, so they are scaled to microseconds for the comparison.
    pub fn clear_expired_input_transactions(&self, cutoff_micros: i64) -> Result<(), DbError> {
        let mut db = self.lock();
        let expired: Vec<ObjectId<TransactionRow>> = db
            .table::<TransactionRow>()?
            .iter()
            .filter(|t| (t.expiration as i64) * 1_000_000 < cutoff_micros)
            .map(|t| t.id())
            .collect();
        for id in expired {
            db.remove::<TransactionRow>(id)?;
        }
        Ok(())
    }

    // ----- contract tables + secondary indices ------------------------------
    //
    // The `update_*` chainbase paths are not mirrored: they take only an object
    // handle (`&key_value_object`, `&index64_object`, ...), whose `table_id` is
    // opaque across the FFI, so the owning `(code, scope, table)` cannot be
    // recovered at the call site to locate the arena row. Creates carry the
    // `&table_id_object` (hence code/scope/table); removes are resolved through
    // the iterator cache before deletion — so both are mirrored.

    /// Mirrors `create_table`. Idempotent: chainbase also reaches a table
    /// lazily, so a row may already exist from a child-store path.
    pub fn create_table(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        contract_table_oid(&mut db, code, scope, table, payer)?;
        Ok(())
    }

    /// Mirrors `remove_table`. No-op when the row is already gone (a preceding
    /// child remove may have deleted the now-empty table).
    pub fn remove_table(&self, code: u64, scope: u64, table: u64) -> Result<(), DbError> {
        let mut db = self.lock();
        if let Some(id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
            .map(|t| t.id())
        {
            db.remove::<ContractTableRow>(id)?;
        }
        Ok(())
    }

    pub fn create_key_value_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        value: &[u8],
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let t_id = contract_table_oid(&mut db, code, scope, table, payer)?;
        let blob = db.alloc_blob::<ContractKeyValueRow>(value)?;
        db.create::<ContractKeyValueRow>(|k| {
            k.t_id = t_id;
            k.primary_key = primary_key;
            k.payer = payer;
            k.value = blob;
        })?;
        contract_table_incr(&mut db, t_id)?;
        Ok(())
    }

    /// Mirrors `update_key_value_object`: reassigns the value blob and payer of
    /// the row at `(code, scope, table, primary_key)`. The FFI reaches the row by
    /// an opaque handle, so the caller resolves the table key via `get_table_by_kv`.
    /// Serve the raw contract-db read `(code, scope, table, primary_key)` -> value
    /// from the arena — the primitive behind db_get_i64/db_find_i64. Returns the
    /// stored value bytes, or `None` if the row is absent. This is the read the
    /// arena must answer identically to chainbase to run as primary.
    pub fn kv_get(&self, code: u64, scope: u64, table: u64, primary_key: u64) -> Option<Vec<u8>> {
        let db = self.lock();
        let t_id = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))
            .ok()
            .flatten()
            .map(|t| t.id().raw())?;
        let value_ref = db
            .find_by::<ContractKeyValueRow, ContractKvByScopePrimary>(&(t_id, primary_key))
            .ok()
            .flatten()
            .map(|k| k.value)?;
        db.blob::<ContractKeyValueRow>(value_ref)
            .ok()
            .map(|b| b.to_vec())
    }

    /// Serve a contract-table forward scan from the arena: every row in
    /// `(code, scope, table)` as `(primary_key, value)`, in ascending primary
    /// order — the sequence a contract walks with db_lowerbound_i64 + repeated
    /// db_next_i64. The order comes from the `by (t_id, primary_key)` index, not
    /// a sort we impose, so it exercises the same ordered structure the reads use.
    pub fn table_range(&self, code: u64, scope: u64, table: u64) -> Vec<(u64, Vec<u8>)> {
        use std::ops::Bound;
        let db = self.lock();
        let Some(t_id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))
            .ok()
            .flatten()
            .map(|t| t.id().raw())
        else {
            return Vec::new();
        };
        let Ok(tbl) = db.table::<ContractKeyValueRow>() else {
            return Vec::new();
        };
        tbl.get_index::<ContractKvByScopePrimary>()
            .range((
                Bound::Included((t_id, u64::MIN)),
                Bound::Included((t_id, u64::MAX)),
            ))
            .map(|(&(_, primary), row)| {
                let value = tbl.blob(row.value).to_vec();
                (primary, value)
            })
            .collect()
    }

    /// Iterator positioning from the arena — the primary key a contract's cursor
    /// lands on. `kv_lower_bound` = smallest primary >= key (db_lowerbound_i64);
    /// `kv_upper_bound` = smallest primary > key (db_upperbound_i64, and the
    /// successor db_next_i64 advances to); `kv_prev` = largest primary < key (the
    /// db_previous_i64 step). `None` means the walk ran off the table's end. All
    /// three read the `(t_id, primary_key)` index directly, so the order is the
    /// index's, not one we impose.
    pub fn kv_lower_bound(&self, code: u64, scope: u64, table: u64, key: u64) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.table::<ContractKeyValueRow>()
            .ok()?
            .get_index::<ContractKvByScopePrimary>()
            .range((
                Bound::Included((t_id, key)),
                Bound::Included((t_id, u64::MAX)),
            ))
            .next()
            .map(|(&(_, p), _)| p)
    }

    pub fn kv_upper_bound(&self, code: u64, scope: u64, table: u64, key: u64) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.table::<ContractKeyValueRow>()
            .ok()?
            .get_index::<ContractKvByScopePrimary>()
            .range((
                Bound::Excluded((t_id, key)),
                Bound::Included((t_id, u64::MAX)),
            ))
            .next()
            .map(|(&(_, p), _)| p)
    }

    pub fn kv_prev(&self, code: u64, scope: u64, table: u64, key: u64) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.table::<ContractKeyValueRow>()
            .ok()?
            .get_index::<ContractKvByScopePrimary>()
            .range((
                Bound::Included((t_id, u64::MIN)),
                Bound::Excluded((t_id, key)),
            ))
            .next_back()
            .map(|(&(_, p), _)| p)
    }

    /// The largest primary key in `(code, scope, table)`, or `None` if empty —
    /// where db_previous_i64 lands when stepping back from the end iterator.
    pub fn kv_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.table::<ContractKeyValueRow>()
            .ok()?
            .get_index::<ContractKvByScopePrimary>()
            .range((
                Bound::Included((t_id, u64::MIN)),
                Bound::Included((t_id, u64::MAX)),
            ))
            .next_back()
            .map(|(&(_, p), _)| p)
    }

    /// Secondary-index (idx64) positioning from the arena, in `(secondary_key,
    /// primary_key)` order — the sequence a contract walks with
    /// db_idx64_lowerbound + db_idx64_next. Each returns `(primary, secondary)`
    /// of the landing row. `idx64_lower_bound` = first secondary >= key,
    /// `idx64_upper_bound` = first secondary > key. Ordering is the
    /// `(t_id, secondary_key, primary_key)` index's own.
    pub fn idx64_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
    ) -> Option<(u64, u64)> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.table::<ContractIndex64Row>()
            .ok()?
            .get_index::<ContractIdx64BySecondary>()
            .range((
                Bound::Included((t_id, secondary, u64::MIN)),
                Bound::Included((t_id, u64::MAX, u64::MAX)),
            ))
            .next()
            .map(|(&(_, sec, primary), _)| (primary, sec))
    }

    pub fn idx64_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
    ) -> Option<(u64, u64)> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.table::<ContractIndex64Row>()
            .ok()?
            .get_index::<ContractIdx64BySecondary>()
            .range((
                Bound::Excluded((t_id, secondary, u64::MAX)),
                Bound::Included((t_id, u64::MAX, u64::MAX)),
            ))
            .next()
            .map(|(&(_, sec, primary), _)| (primary, sec))
    }

    /// db_idx64_find_secondary: the primary of the first row whose secondary key
    /// equals `secondary`, or `None` if none matches.
    pub fn idx64_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
    ) -> Option<u64> {
        self.idx64_lower_bound(code, scope, table, secondary)
            .filter(|&(_, sec)| sec == secondary)
            .map(|(primary, _)| primary)
    }

    /// db_idx64_find_primary: the secondary key stored for `primary`, or `None`.
    pub fn idx64_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.find_by::<ContractIndex64Row, ContractIdx64ByPrimary>(&(t_id, primary))
            .ok()
            .flatten()
            .map(|r| r.secondary_key)
    }

    /// db_idx64_next: the row after the one keyed by `primary`, in
    /// `(secondary, primary)` order within the same table. `None` when `primary`
    /// is the last row (or absent). Returns `(primary, secondary)` of the landing.
    pub fn idx64_next(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<(u64, u64)> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        let sec = db
            .find_by::<ContractIndex64Row, ContractIdx64ByPrimary>(&(t_id, primary))
            .ok()
            .flatten()?
            .secondary_key;
        db.table::<ContractIndex64Row>()
            .ok()?
            .get_index::<ContractIdx64BySecondary>()
            .range((
                Bound::Excluded((t_id, sec, primary)),
                Bound::Included((t_id, u64::MAX, u64::MAX)),
            ))
            .next()
            .map(|(&(_, s, p), _)| (p, s))
    }

    /// db_idx64_previous: the row before the one keyed by `primary`, in
    /// `(secondary, primary)` order within the same table. `None` when `primary`
    /// is the first row (or absent). Returns `(primary, secondary)` of the landing.
    pub fn idx64_previous(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<(u64, u64)> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        let sec = db
            .find_by::<ContractIndex64Row, ContractIdx64ByPrimary>(&(t_id, primary))
            .ok()
            .flatten()?
            .secondary_key;
        db.table::<ContractIndex64Row>()
            .ok()?
            .get_index::<ContractIdx64BySecondary>()
            .range((
                Bound::Included((t_id, u64::MIN, u64::MIN)),
                Bound::Excluded((t_id, sec, primary)),
            ))
            .next_back()
            .map(|(&(_, s, p), _)| (p, s))
    }

    /// db_idx64_previous from an end iterator: the last row of the table in
    /// `(secondary, primary)` order, or `None` when the index is empty.
    pub fn idx64_last(&self, code: u64, scope: u64, table: u64) -> Option<(u64, u64)> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.table::<ContractIndex64Row>()
            .ok()?
            .get_index::<ContractIdx64BySecondary>()
            .range((
                Bound::Included((t_id, u64::MIN, u64::MIN)),
                Bound::Included((t_id, u64::MAX, u64::MAX)),
            ))
            .next_back()
            .map(|(&(_, s, p), _)| (p, s))
    }

    /// idx128 secondary-index positioning, same semantics as the idx64 family but
    /// over a `u128` secondary key: `(primary, secondary)` of the landing row,
    /// in `(secondary, primary)` order.
    pub fn idx128_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u128,
    ) -> Option<(u64, u128)> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.table::<ContractIndex128Row>()
            .ok()?
            .get_index::<ContractIdx128BySecondary>()
            .range((
                Bound::Included((t_id, secondary, u64::MIN)),
                Bound::Included((t_id, u128::MAX, u64::MAX)),
            ))
            .next()
            .map(|(&(_, sec, primary), _)| (primary, sec))
    }

    pub fn idx128_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u128,
    ) -> Option<(u64, u128)> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.table::<ContractIndex128Row>()
            .ok()?
            .get_index::<ContractIdx128BySecondary>()
            .range((
                Bound::Excluded((t_id, secondary, u64::MAX)),
                Bound::Included((t_id, u128::MAX, u64::MAX)),
            ))
            .next()
            .map(|(&(_, sec, primary), _)| (primary, sec))
    }

    pub fn idx128_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u128,
    ) -> Option<u64> {
        self.idx128_lower_bound(code, scope, table, secondary)
            .filter(|&(_, sec)| sec == secondary)
            .map(|(primary, _)| primary)
    }

    pub fn idx128_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u128> {
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.find_by::<ContractIndex128Row, ContractIdx128ByPrimary>(&(t_id, primary))
            .ok()
            .flatten()
            .map(|r| r.secondary_key())
    }

    /// idx256 secondary-index positioning over a 32-byte key, ordered by its two
    /// little-endian `u128` words then primary. Landing row as `(primary, key)`.
    pub fn idx256_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: [u8; 32],
    ) -> Option<(u64, [u8; 32])> {
        use std::ops::Bound;
        let (w0, w1) = split_key256(&secondary);
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.table::<ContractIndex256Row>()
            .ok()?
            .get_index::<ContractIdx256BySecondary>()
            .range((
                Bound::Included((t_id, w0, w1, u64::MIN)),
                Bound::Included((t_id, u128::MAX, u128::MAX, u64::MAX)),
            ))
            .next()
            .map(|(&(_, a, b, primary), _)| (primary, join_key256(a, b)))
    }

    pub fn idx256_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: [u8; 32],
    ) -> Option<(u64, [u8; 32])> {
        use std::ops::Bound;
        let (w0, w1) = split_key256(&secondary);
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.table::<ContractIndex256Row>()
            .ok()?
            .get_index::<ContractIdx256BySecondary>()
            .range((
                Bound::Excluded((t_id, w0, w1, u64::MAX)),
                Bound::Included((t_id, u128::MAX, u128::MAX, u64::MAX)),
            ))
            .next()
            .map(|(&(_, a, b, primary), _)| (primary, join_key256(a, b)))
    }

    pub fn idx256_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: [u8; 32],
    ) -> Option<u64> {
        self.idx256_lower_bound(code, scope, table, secondary)
            .filter(|&(_, key)| key == secondary)
            .map(|(primary, _)| primary)
    }

    pub fn idx256_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<[u8; 32]> {
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.find_by::<ContractIndex256Row, ContractIdx256ByPrimary>(&(t_id, primary))
            .ok()
            .flatten()
            .map(|r| r.secondary_key)
    }

    /// idx_double secondary-index positioning over an IEEE-754 `f64`, ordered by
    /// `DoubleKey` (chainbase's software-float order, -0/+0 folded). Landing row
    /// as `(primary, secondary)`. The float key has no representable max, so the
    /// scan runs to the end of the index and keeps the hit only if it stayed in
    /// this table.
    pub fn idx_double_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: f64,
    ) -> Option<(u64, f64)> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        match db
            .table::<ContractIndexDoubleRow>()
            .ok()?
            .get_index::<ContractIdxDoubleBySecondary>()
            .range((
                Bound::Included((t_id, DoubleKey(secondary), u64::MIN)),
                Bound::Unbounded,
            ))
            .next()
        {
            Some((&(rt, dk, primary), _)) if rt == t_id => Some((primary, dk.0)),
            _ => None,
        }
    }

    pub fn idx_double_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: f64,
    ) -> Option<(u64, f64)> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        match db
            .table::<ContractIndexDoubleRow>()
            .ok()?
            .get_index::<ContractIdxDoubleBySecondary>()
            .range((
                Bound::Excluded((t_id, DoubleKey(secondary), u64::MAX)),
                Bound::Unbounded,
            ))
            .next()
        {
            Some((&(rt, dk, primary), _)) if rt == t_id => Some((primary, dk.0)),
            _ => None,
        }
    }

    pub fn idx_double_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: f64,
    ) -> Option<u64> {
        self.idx_double_lower_bound(code, scope, table, secondary)
            .filter(|&(_, sec)| DoubleKey(sec) == DoubleKey(secondary))
            .map(|(primary, _)| primary)
    }

    pub fn idx_double_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<f64> {
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.find_by::<ContractIndexDoubleRow, ContractIdxDoubleByPrimary>(&(t_id, primary))
            .ok()
            .flatten()
            .map(|r| r.secondary_key)
    }

    /// idx_long_double secondary-index positioning over a `float128_t` (given as
    /// its `(lo, hi)` u64 words), ordered by `LongDoubleKey`. Landing row as
    /// `(primary, (lo, hi))`. Same run-to-end-and-check-table scan as idx_double.
    pub fn idx_long_double_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: (u64, u64),
    ) -> Option<(u64, (u64, u64))> {
        use std::ops::Bound;
        let key = LongDoubleKey {
            lo: secondary.0,
            hi: secondary.1,
        };
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        match db
            .table::<ContractIndexLongDoubleRow>()
            .ok()?
            .get_index::<ContractIdxLongDoubleBySecondary>()
            .range((Bound::Included((t_id, key, u64::MIN)), Bound::Unbounded))
            .next()
        {
            Some((&(rt, k, primary), _)) if rt == t_id => Some((primary, (k.lo, k.hi))),
            _ => None,
        }
    }

    pub fn idx_long_double_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: (u64, u64),
    ) -> Option<(u64, (u64, u64))> {
        use std::ops::Bound;
        let key = LongDoubleKey {
            lo: secondary.0,
            hi: secondary.1,
        };
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        match db
            .table::<ContractIndexLongDoubleRow>()
            .ok()?
            .get_index::<ContractIdxLongDoubleBySecondary>()
            .range((Bound::Excluded((t_id, key, u64::MAX)), Bound::Unbounded))
            .next()
        {
            Some((&(rt, k, primary), _)) if rt == t_id => Some((primary, (k.lo, k.hi))),
            _ => None,
        }
    }

    pub fn idx_long_double_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: (u64, u64),
    ) -> Option<u64> {
        let want = LongDoubleKey {
            lo: secondary.0,
            hi: secondary.1,
        };
        self.idx_long_double_lower_bound(code, scope, table, secondary)
            .filter(|&(_, (lo, hi))| LongDoubleKey { lo, hi } == want)
            .map(|(primary, _)| primary)
    }

    pub fn idx_long_double_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<(u64, u64)> {
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        db.find_by::<ContractIndexLongDoubleRow, ContractIdxLongDoubleByPrimary>(&(t_id, primary))
            .ok()
            .flatten()
            .map(|r| (r.sec_lo, r.sec_hi))
    }

    // Secondary-order next/previous/last for iterator-handle minting, one family
    // per secondary-index type. Each returns the landing row's primary key: the
    // successor/predecessor of the row keyed by `primary` in `(secondary,
    // primary)` order within the same table, and the table's last row (for a
    // `previous` off the end iterator). The `rt == t_id` guard reproduces the C++
    // `itr->t_id != obj.t_id` check that stops iteration at a table boundary.

    pub fn idx128_next(&self, code: u64, scope: u64, table: u64, primary: u64) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        let sec = db
            .find_by::<ContractIndex128Row, ContractIdx128ByPrimary>(&(t_id, primary))
            .ok()
            .flatten()?
            .secondary_key();
        match db
            .table::<ContractIndex128Row>()
            .ok()?
            .get_index::<ContractIdx128BySecondary>()
            .range((Bound::Excluded((t_id, sec, primary)), Bound::Unbounded))
            .next()
        {
            Some((&(rt, _, p), _)) if rt == t_id => Some(p),
            _ => None,
        }
    }

    pub fn idx128_previous(&self, code: u64, scope: u64, table: u64, primary: u64) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        let sec = db
            .find_by::<ContractIndex128Row, ContractIdx128ByPrimary>(&(t_id, primary))
            .ok()
            .flatten()?
            .secondary_key();
        match db
            .table::<ContractIndex128Row>()
            .ok()?
            .get_index::<ContractIdx128BySecondary>()
            .range((Bound::Unbounded, Bound::Excluded((t_id, sec, primary))))
            .next_back()
        {
            Some((&(rt, _, p), _)) if rt == t_id => Some(p),
            _ => None,
        }
    }

    pub fn idx128_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        match db
            .table::<ContractIndex128Row>()
            .ok()?
            .get_index::<ContractIdx128BySecondary>()
            .range((
                Bound::Unbounded,
                Bound::Included((t_id, u128::MAX, u64::MAX)),
            ))
            .next_back()
        {
            Some((&(rt, _, p), _)) if rt == t_id => Some(p),
            _ => None,
        }
    }

    pub fn idx256_next(&self, code: u64, scope: u64, table: u64, primary: u64) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        let (w0, w1) = db
            .find_by::<ContractIndex256Row, ContractIdx256ByPrimary>(&(t_id, primary))
            .ok()
            .flatten()?
            .secondary_words();
        match db
            .table::<ContractIndex256Row>()
            .ok()?
            .get_index::<ContractIdx256BySecondary>()
            .range((Bound::Excluded((t_id, w0, w1, primary)), Bound::Unbounded))
            .next()
        {
            Some((&(rt, _, _, p), _)) if rt == t_id => Some(p),
            _ => None,
        }
    }

    pub fn idx256_previous(&self, code: u64, scope: u64, table: u64, primary: u64) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        let (w0, w1) = db
            .find_by::<ContractIndex256Row, ContractIdx256ByPrimary>(&(t_id, primary))
            .ok()
            .flatten()?
            .secondary_words();
        match db
            .table::<ContractIndex256Row>()
            .ok()?
            .get_index::<ContractIdx256BySecondary>()
            .range((Bound::Unbounded, Bound::Excluded((t_id, w0, w1, primary))))
            .next_back()
        {
            Some((&(rt, _, _, p), _)) if rt == t_id => Some(p),
            _ => None,
        }
    }

    pub fn idx256_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        match db
            .table::<ContractIndex256Row>()
            .ok()?
            .get_index::<ContractIdx256BySecondary>()
            .range((
                Bound::Unbounded,
                Bound::Included((t_id, u128::MAX, u128::MAX, u64::MAX)),
            ))
            .next_back()
        {
            Some((&(rt, _, _, p), _)) if rt == t_id => Some(p),
            _ => None,
        }
    }

    pub fn idx_double_next(&self, code: u64, scope: u64, table: u64, primary: u64) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        let sec = db
            .find_by::<ContractIndexDoubleRow, ContractIdxDoubleByPrimary>(&(t_id, primary))
            .ok()
            .flatten()?
            .secondary_key;
        match db
            .table::<ContractIndexDoubleRow>()
            .ok()?
            .get_index::<ContractIdxDoubleBySecondary>()
            .range((
                Bound::Excluded((t_id, DoubleKey(sec), primary)),
                Bound::Unbounded,
            ))
            .next()
        {
            Some((&(rt, _, p), _)) if rt == t_id => Some(p),
            _ => None,
        }
    }

    pub fn idx_double_previous(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        let sec = db
            .find_by::<ContractIndexDoubleRow, ContractIdxDoubleByPrimary>(&(t_id, primary))
            .ok()
            .flatten()?
            .secondary_key;
        match db
            .table::<ContractIndexDoubleRow>()
            .ok()?
            .get_index::<ContractIdxDoubleBySecondary>()
            .range((
                Bound::Unbounded,
                Bound::Excluded((t_id, DoubleKey(sec), primary)),
            ))
            .next_back()
        {
            Some((&(rt, _, p), _)) if rt == t_id => Some(p),
            _ => None,
        }
    }

    pub fn idx_double_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        match db
            .table::<ContractIndexDoubleRow>()
            .ok()?
            .get_index::<ContractIdxDoubleBySecondary>()
            .range((
                Bound::Unbounded,
                Bound::Included((t_id, DoubleKey(f64::INFINITY), u64::MAX)),
            ))
            .next_back()
        {
            Some((&(rt, _, p), _)) if rt == t_id => Some(p),
            _ => None,
        }
    }

    pub fn idx_long_double_next(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        let (lo, hi) = db
            .find_by::<ContractIndexLongDoubleRow, ContractIdxLongDoubleByPrimary>(&(t_id, primary))
            .ok()
            .flatten()
            .map(|r| (r.sec_lo, r.sec_hi))?;
        match db
            .table::<ContractIndexLongDoubleRow>()
            .ok()?
            .get_index::<ContractIdxLongDoubleBySecondary>()
            .range((
                Bound::Excluded((t_id, LongDoubleKey { lo, hi }, primary)),
                Bound::Unbounded,
            ))
            .next()
        {
            Some((&(rt, _, p), _)) if rt == t_id => Some(p),
            _ => None,
        }
    }

    pub fn idx_long_double_previous(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        let (lo, hi) = db
            .find_by::<ContractIndexLongDoubleRow, ContractIdxLongDoubleByPrimary>(&(t_id, primary))
            .ok()
            .flatten()
            .map(|r| (r.sec_lo, r.sec_hi))?;
        match db
            .table::<ContractIndexLongDoubleRow>()
            .ok()?
            .get_index::<ContractIdxLongDoubleBySecondary>()
            .range((
                Bound::Unbounded,
                Bound::Excluded((t_id, LongDoubleKey { lo, hi }, primary)),
            ))
            .next_back()
        {
            Some((&(rt, _, p), _)) if rt == t_id => Some(p),
            _ => None,
        }
    }

    pub fn idx_long_double_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        use std::ops::Bound;
        let db = self.lock();
        let t_id = self.resolve_t_id(&db, code, scope, table)?;
        // +inf is the largest ordering key over valid (non-NaN) stored secondaries.
        let max_key = LongDoubleKey {
            lo: 0,
            hi: 0x7FFF_0000_0000_0000,
        };
        match db
            .table::<ContractIndexLongDoubleRow>()
            .ok()?
            .get_index::<ContractIdxLongDoubleBySecondary>()
            .range((Bound::Unbounded, Bound::Included((t_id, max_key, u64::MAX))))
            .next_back()
        {
            Some((&(rt, _, p), _)) if rt == t_id => Some(p),
            _ => None,
        }
    }

    fn resolve_t_id(&self, db: &Db, code: u64, scope: u64, table: u64) -> Option<i64> {
        db.find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))
            .ok()
            .flatten()
            .map(|t| t.id().raw())
    }

    /// Tally an iterator-positioning cross-check (arena landing == chainbase's).
    pub fn note_pos(&self, matched: bool) {
        use std::sync::atomic::Ordering;
        if matched {
            self.pos_ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.pos_fail.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// (matches, mismatches) tallied by iterator-positioning cross-checks.
    pub fn pos_crosscheck_counts(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.pos_ok.load(Ordering::Relaxed),
            self.pos_fail.load(Ordering::Relaxed),
        )
    }

    /// Write a full checkpoint of the mirror's committed state to `path` (atomic).
    pub fn checkpoint(&self, path: &std::path::Path) -> Result<(), DbError> {
        self.lock().checkpoint(path)
    }

    /// Load a checkpoint into this (freshly constructed, empty) mirror.
    pub fn load(&self, path: &std::path::Path) -> Result<(), DbError> {
        self.lock().load(path)
    }

    /// Restart in place: discard the live `Db` and rebuild it from the checkpoint
    /// at `path`, exactly as a node would on reboot. The shared counters and the
    /// cutover switch survive (they live outside the `Db`), so the reloaded
    /// mirror keeps serving. The restored revision must line up with chainbase's
    /// for the next block's undo session to match.
    pub fn reload_from(&self, path: &std::path::Path) -> Result<(), DbError> {
        let mut fresh = build_registered_db()?;
        fresh.load(path)?;
        *self.lock() = fresh;
        Ok(())
    }

    /// Append the committed changes since the last flush to the write-ahead log
    /// at `path` (O(rows changed)). Called once per accepted block, this is the
    /// incremental durability a running node relies on between checkpoints.
    pub fn flush_delta(&self, path: &std::path::Path) -> Result<(), DbError> {
        self.lock().flush_delta(path)
    }

    /// Replay every complete frame in the log at `path` onto this mirror,
    /// restoring the state a sequence of `flush_delta` calls recorded.
    pub fn replay_log(&self, path: &std::path::Path) -> Result<(), DbError> {
        self.lock().replay_log(path)
    }

    /// Tally a non-contract read cross-check (arena lookup == chainbase's).
    pub fn note_noncontract(&self, matched: bool) {
        use std::sync::atomic::Ordering;
        if matched {
            self.nc_ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.nc_fail.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// (matches, mismatches) tallied by non-contract read cross-checks.
    pub fn noncontract_crosscheck_counts(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.nc_ok.load(Ordering::Relaxed),
            self.nc_fail.load(Ordering::Relaxed),
        )
    }

    pub fn update_key_value_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        value: &[u8],
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let Some(t_id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
            .map(|t| t.id().raw())
        else {
            return Ok(());
        };
        let found = db
            .find_by::<ContractKeyValueRow, ContractKvByScopePrimary>(&(t_id, primary_key))?
            .map(|k| (k.id(), k.value));
        if let Some((id, old_value)) = found {
            // Reuse the row's previous value span instead of leaking it — this is
            // the hot path (a contract row's value is rewritten on every update).
            let blob = db.realloc_blob::<ContractKeyValueRow>(old_value, value)?;
            db.modify::<ContractKeyValueRow>(id, |k| {
                k.value = blob;
                k.payer = payer;
            })?;
        }
        Ok(())
    }

    pub fn remove_key_value_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let Some(t_id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
            .map(|t| t.id().raw())
        else {
            return Ok(());
        };
        let found = db
            .find_by::<ContractKeyValueRow, ContractKvByScopePrimary>(&(t_id, primary_key))?
            .map(|k| (k.id(), k.value));
        if let Some((id, value)) = found {
            db.remove::<ContractKeyValueRow>(id)?;
            db.free_blob::<ContractKeyValueRow>(value)?; // reclaim the removed row's value span
            contract_table_decr(&mut db, t_id)?;
        }
        Ok(())
    }

    pub fn create_index64_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: u64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let t_id = contract_table_oid(&mut db, code, scope, table, payer)?;
        db.create::<ContractIndex64Row>(|e| {
            e.t_id = t_id;
            e.primary_key = primary_key;
            e.secondary_key = secondary_key;
            e.payer = payer;
        })?;
        contract_table_incr(&mut db, t_id)?;
        Ok(())
    }

    /// Mirror of `db.update_index64_object`: re-point the row's secondary key (and
    /// payer). The row count is unchanged, so no table refcount adjustment.
    pub fn update_index64_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: u64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let Some(t_id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
            .map(|t| t.id().raw())
        else {
            return Ok(());
        };
        let id = db
            .find_by::<ContractIndex64Row, ContractIdx64ByPrimary>(&(t_id, primary_key))?
            .map(|e| e.id());
        if let Some(id) = id {
            db.modify::<ContractIndex64Row>(id, |e| {
                e.secondary_key = secondary_key;
                e.payer = payer;
            })?;
        }
        Ok(())
    }

    pub fn remove_index64_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let Some(t_id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
            .map(|t| t.id().raw())
        else {
            return Ok(());
        };
        let found = db
            .find_by::<ContractIndex64Row, ContractIdx64ByPrimary>(&(t_id, primary_key))?
            .map(|e| e.id());
        if let Some(id) = found {
            db.remove::<ContractIndex64Row>(id)?;
            contract_table_decr(&mut db, t_id)?;
        }
        Ok(())
    }

    pub fn create_index128_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: u128,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let t_id = contract_table_oid(&mut db, code, scope, table, payer)?;
        db.create::<ContractIndex128Row>(|e| {
            e.t_id = t_id;
            e.primary_key = primary_key;
            e.sec_lo = secondary_key as u64;
            e.sec_hi = (secondary_key >> 64) as u64;
            e.payer = payer;
        })?;
        contract_table_incr(&mut db, t_id)?;
        Ok(())
    }

    pub fn update_index128_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: u128,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let Some(t_id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
            .map(|t| t.id().raw())
        else {
            return Ok(());
        };
        let id = db
            .find_by::<ContractIndex128Row, ContractIdx128ByPrimary>(&(t_id, primary_key))?
            .map(|e| e.id());
        if let Some(id) = id {
            db.modify::<ContractIndex128Row>(id, |e| {
                e.sec_lo = secondary_key as u64;
                e.sec_hi = (secondary_key >> 64) as u64;
                e.payer = payer;
            })?;
        }
        Ok(())
    }

    pub fn remove_index128_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let Some(t_id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
            .map(|t| t.id().raw())
        else {
            return Ok(());
        };
        let found = db
            .find_by::<ContractIndex128Row, ContractIdx128ByPrimary>(&(t_id, primary_key))?
            .map(|e| e.id());
        if let Some(id) = found {
            db.remove::<ContractIndex128Row>(id)?;
            contract_table_decr(&mut db, t_id)?;
        }
        Ok(())
    }

    pub fn create_index256_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: [u8; 32],
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let t_id = contract_table_oid(&mut db, code, scope, table, payer)?;
        db.create::<ContractIndex256Row>(|e| {
            e.t_id = t_id;
            e.primary_key = primary_key;
            e.secondary_key = secondary_key;
            e.payer = payer;
        })?;
        contract_table_incr(&mut db, t_id)?;
        Ok(())
    }

    pub fn update_index256_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: [u8; 32],
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let Some(t_id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
            .map(|t| t.id().raw())
        else {
            return Ok(());
        };
        let id = db
            .find_by::<ContractIndex256Row, ContractIdx256ByPrimary>(&(t_id, primary_key))?
            .map(|e| e.id());
        if let Some(id) = id {
            db.modify::<ContractIndex256Row>(id, |e| {
                e.secondary_key = secondary_key;
                e.payer = payer;
            })?;
        }
        Ok(())
    }

    pub fn remove_index256_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let Some(t_id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
            .map(|t| t.id().raw())
        else {
            return Ok(());
        };
        let found = db
            .find_by::<ContractIndex256Row, ContractIdx256ByPrimary>(&(t_id, primary_key))?
            .map(|e| e.id());
        if let Some(id) = found {
            db.remove::<ContractIndex256Row>(id)?;
            contract_table_decr(&mut db, t_id)?;
        }
        Ok(())
    }

    /// `secondary_key` is the raw IEEE-754 bit pattern (the FFI carries the
    /// softfloat `float64_t` as a `u64`); it is reinterpreted, not converted.
    pub fn create_idx_double_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: u64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let t_id = contract_table_oid(&mut db, code, scope, table, payer)?;
        db.create::<ContractIndexDoubleRow>(|e| {
            e.t_id = t_id;
            e.primary_key = primary_key;
            e.secondary_key = f64::from_bits(secondary_key);
            e.payer = payer;
        })?;
        contract_table_incr(&mut db, t_id)?;
        Ok(())
    }

    /// `secondary_key` is the raw IEEE-754 bit pattern, reinterpreted not converted.
    pub fn update_idx_double_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: u64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let Some(t_id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
            .map(|t| t.id().raw())
        else {
            return Ok(());
        };
        let id = db
            .find_by::<ContractIndexDoubleRow, ContractIdxDoubleByPrimary>(&(t_id, primary_key))?
            .map(|e| e.id());
        if let Some(id) = id {
            db.modify::<ContractIndexDoubleRow>(id, |e| {
                e.secondary_key = f64::from_bits(secondary_key);
                e.payer = payer;
            })?;
        }
        Ok(())
    }

    pub fn remove_idx_double_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let Some(t_id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
            .map(|t| t.id().raw())
        else {
            return Ok(());
        };
        let found = db
            .find_by::<ContractIndexDoubleRow, ContractIdxDoubleByPrimary>(&(t_id, primary_key))?
            .map(|e| e.id());
        if let Some(id) = found {
            db.remove::<ContractIndexDoubleRow>(id)?;
            contract_table_decr(&mut db, t_id)?;
        }
        Ok(())
    }

    /// `secondary` is the `float128_t` as its `(lo, hi)` `u64` words.
    pub fn create_idx_long_double_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary: (u64, u64),
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let t_id = contract_table_oid(&mut db, code, scope, table, payer)?;
        db.create::<ContractIndexLongDoubleRow>(|e| {
            e.t_id = t_id;
            e.primary_key = primary_key;
            e.sec_lo = secondary.0;
            e.sec_hi = secondary.1;
            e.payer = payer;
        })?;
        contract_table_incr(&mut db, t_id)?;
        Ok(())
    }

    /// `secondary` is the `float128_t` as its `(lo, hi)` `u64` words.
    pub fn update_idx_long_double_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary: (u64, u64),
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let Some(t_id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
            .map(|t| t.id().raw())
        else {
            return Ok(());
        };
        let id = db
            .find_by::<ContractIndexLongDoubleRow, ContractIdxLongDoubleByPrimary>(&(
                t_id,
                primary_key,
            ))?
            .map(|e| e.id());
        if let Some(id) = id {
            db.modify::<ContractIndexLongDoubleRow>(id, |e| {
                e.sec_lo = secondary.0;
                e.sec_hi = secondary.1;
                e.payer = payer;
            })?;
        }
        Ok(())
    }

    pub fn remove_idx_long_double_object(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), DbError> {
        let mut db = self.lock();
        let Some(t_id) = db
            .find_by::<ContractTableRow, ContractTableByCodeScopeTable>(&(code, scope, table))?
            .map(|t| t.id().raw())
        else {
            return Ok(());
        };
        let found = db
            .find_by::<ContractIndexLongDoubleRow, ContractIdxLongDoubleByPrimary>(&(
                t_id,
                primary_key,
            ))?
            .map(|e| e.id());
        if let Some(id) = found {
            db.remove::<ContractIndexLongDoubleRow>(id)?;
            contract_table_decr(&mut db, t_id)?;
        }
        Ok(())
    }
}

/// Split a 32-byte idx256 key into its two little-endian `u128` words, the same
/// way `ContractIndex256Row::secondary_words` does, so query keys sort against
/// stored rows identically.
fn split_key256(key: &[u8; 32]) -> (u128, u128) {
    let mut w0 = [0u8; 16];
    let mut w1 = [0u8; 16];
    w0.copy_from_slice(&key[0..16]);
    w1.copy_from_slice(&key[16..32]);
    (u128::from_le_bytes(w0), u128::from_le_bytes(w1))
}

/// Inverse of [`split_key256`].
fn join_key256(w0: u128, w1: u128) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0..16].copy_from_slice(&w0.to_le_bytes());
    key[16..32].copy_from_slice(&w1.to_le_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The read primitives the arena serves to a contract — point read, forward
    /// scan, and the four iterator-positioning queries — must follow the index's
    /// primary-key order regardless of insertion order.
    #[test]
    fn contract_read_positioning_follows_index_order() {
        let s = ArenaShadow::new().unwrap();
        let (code, scope, table, payer) = (1u64, 2u64, 3u64, 9u64);
        // Insert out of order; the index, not insertion, decides traversal.
        for &pk in &[50u64, 10, 30, 20, 40] {
            s.create_key_value_object(code, scope, table, payer, pk, &[pk as u8])
                .unwrap();
        }

        // Point read (db_get_i64).
        assert_eq!(s.kv_get(code, scope, table, 30), Some(vec![30u8]));
        assert_eq!(s.kv_get(code, scope, table, 99), None);

        // Forward scan (db_lowerbound -> repeated db_next).
        let scan: Vec<u64> = s
            .table_range(code, scope, table)
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        assert_eq!(scan, vec![10, 20, 30, 40, 50]);

        // lower_bound: first primary >= key.
        assert_eq!(s.kv_lower_bound(code, scope, table, 25), Some(30));
        assert_eq!(s.kv_lower_bound(code, scope, table, 30), Some(30));
        assert_eq!(s.kv_lower_bound(code, scope, table, 51), None);

        // upper_bound: first primary > key (the db_next successor).
        assert_eq!(s.kv_upper_bound(code, scope, table, 30), Some(40));
        assert_eq!(s.kv_upper_bound(code, scope, table, 50), None);

        // prev: last primary < key (the db_previous step from a live row).
        assert_eq!(s.kv_prev(code, scope, table, 30), Some(20));
        assert_eq!(s.kv_prev(code, scope, table, 10), None);

        // last: greatest primary (db_previous from the end iterator).
        assert_eq!(s.kv_last(code, scope, table), Some(50));

        // An absent table answers empty everywhere, never a wrong row.
        assert_eq!(s.kv_last(code, scope, 999), None);
        assert_eq!(s.kv_lower_bound(code, scope, 999, 0), None);
        assert_eq!(s.table_range(code, scope, 999), Vec::new());
    }

    /// The idx64 secondary-index reads must walk `(secondary_key, primary_key)`
    /// order, including duplicate secondaries (find_secondary returns the lowest
    /// primary; the next distinct secondary is upper_bound's landing).
    #[test]
    fn idx64_secondary_reads_follow_secondary_then_primary() {
        let s = ArenaShadow::new().unwrap();
        let (code, scope, table, payer) = (1u64, 2u64, 3u64, 9u64);
        // (primary, secondary) pairs, inserted out of order, with a duplicate
        // secondary (200) across primaries 5 and 2.
        for &(primary, secondary) in &[(7u64, 300u64), (5, 200), (2, 200), (9, 100)] {
            s.create_index64_object(code, scope, table, payer, primary, secondary)
                .unwrap();
        }

        // lower_bound by secondary: first row with secondary >= key, as
        // (primary, secondary). The 200s tie-break by primary, so 2 comes first.
        assert_eq!(s.idx64_lower_bound(code, scope, table, 100), Some((9, 100)));
        assert_eq!(s.idx64_lower_bound(code, scope, table, 150), Some((2, 200)));
        assert_eq!(s.idx64_lower_bound(code, scope, table, 200), Some((2, 200)));
        assert_eq!(s.idx64_lower_bound(code, scope, table, 301), None);

        // upper_bound by secondary: first row with secondary strictly greater.
        assert_eq!(s.idx64_upper_bound(code, scope, table, 200), Some((7, 300)));
        assert_eq!(s.idx64_upper_bound(code, scope, table, 300), None);

        // find_secondary: lowest primary carrying that secondary; None if absent.
        assert_eq!(s.idx64_find_secondary(code, scope, table, 200), Some(2));
        assert_eq!(s.idx64_find_secondary(code, scope, table, 250), None);

        // find_primary: the secondary stored for a primary.
        assert_eq!(s.idx64_find_primary(code, scope, table, 5), Some(200));
        assert_eq!(s.idx64_find_primary(code, scope, table, 42), None);

        // Secondary order is 9(100), 2(200), 5(200), 7(300); next/previous walk
        // it and fall off the ends (the ties break by primary, so 2 precedes 5).
        assert_eq!(s.idx64_next(code, scope, table, 9), Some((2, 200)));
        assert_eq!(s.idx64_next(code, scope, table, 2), Some((5, 200)));
        assert_eq!(s.idx64_next(code, scope, table, 5), Some((7, 300)));
        assert_eq!(s.idx64_next(code, scope, table, 7), None);
        assert_eq!(s.idx64_previous(code, scope, table, 7), Some((5, 200)));
        assert_eq!(s.idx64_previous(code, scope, table, 5), Some((2, 200)));
        assert_eq!(s.idx64_previous(code, scope, table, 2), Some((9, 100)));
        assert_eq!(s.idx64_previous(code, scope, table, 9), None);
        assert_eq!(s.idx64_last(code, scope, table), Some((7, 300)));
    }

    /// idx128 reads follow the same (secondary, primary) order over a u128 key,
    /// including secondaries above u64::MAX that a narrower key would truncate.
    #[test]
    fn idx128_secondary_reads_follow_secondary_then_primary() {
        let s = ArenaShadow::new().unwrap();
        let (code, scope, table, payer) = (1u64, 2u64, 3u64, 9u64);
        let big = (1u128 << 96) + 7; // well beyond u64
        for &(primary, secondary) in &[(7u64, big), (5, 200u128), (2, 200), (9, 100)] {
            s.create_index128_object(code, scope, table, payer, primary, secondary)
                .unwrap();
        }

        assert_eq!(
            s.idx128_lower_bound(code, scope, table, 150),
            Some((2, 200))
        );
        assert_eq!(
            s.idx128_lower_bound(code, scope, table, big),
            Some((7, big))
        );
        assert_eq!(
            s.idx128_upper_bound(code, scope, table, 200),
            Some((7, big))
        );
        assert_eq!(s.idx128_upper_bound(code, scope, table, big), None);
        assert_eq!(s.idx128_find_secondary(code, scope, table, 200), Some(2));
        assert_eq!(s.idx128_find_secondary(code, scope, table, 199), None);
        assert_eq!(s.idx128_find_primary(code, scope, table, 7), Some(big));

        // Secondary order is 9, 2, 5, 7 (by secondary then primary).
        assert_eq!(s.idx128_next(code, scope, table, 9), Some(2));
        assert_eq!(s.idx128_next(code, scope, table, 5), Some(7));
        assert_eq!(s.idx128_next(code, scope, table, 7), None);
        assert_eq!(s.idx128_previous(code, scope, table, 2), Some(9));
        assert_eq!(s.idx128_previous(code, scope, table, 9), None);
        assert_eq!(s.idx128_last(code, scope, table), Some(7));

        // update re-points a row's secondary (the u128 lo/hi split): move
        // primary 9 from 100 to 250. The old key is gone, the new one resolves.
        s.update_index128_object(code, scope, table, 9, payer, 250)
            .unwrap();
        assert_eq!(s.idx128_find_primary(code, scope, table, 9), Some(250));
        assert_eq!(s.idx128_find_secondary(code, scope, table, 100), None);
        assert_eq!(s.idx128_find_secondary(code, scope, table, 250), Some(9));
    }

    /// idx256 reads order by the 32-byte key's two little-endian words then
    /// primary, and round-trip the key bytes unchanged.
    #[test]
    fn idx256_secondary_reads_order_by_key_words() {
        let s = ArenaShadow::new().unwrap();
        let (code, scope, table, payer) = (1u64, 2u64, 3u64, 9u64);
        let key = |n: u8| {
            let mut k = [0u8; 32];
            k[0] = n;
            k
        };
        for &(primary, n) in &[(7u64, 30u8), (5, 20), (2, 20), (9, 10)] {
            s.create_index256_object(code, scope, table, payer, primary, key(n))
                .unwrap();
        }

        assert_eq!(
            s.idx256_lower_bound(code, scope, table, key(15)),
            Some((2, key(20)))
        );
        assert_eq!(
            s.idx256_lower_bound(code, scope, table, key(10)),
            Some((9, key(10)))
        );
        assert_eq!(
            s.idx256_upper_bound(code, scope, table, key(20)),
            Some((7, key(30)))
        );
        assert_eq!(s.idx256_upper_bound(code, scope, table, key(30)), None);
        assert_eq!(
            s.idx256_find_secondary(code, scope, table, key(20)),
            Some(2)
        );
        assert_eq!(s.idx256_find_secondary(code, scope, table, key(25)), None);
        assert_eq!(s.idx256_find_primary(code, scope, table, 5), Some(key(20)));

        // Secondary order is 9, 2, 5, 7 (by key word then primary).
        assert_eq!(s.idx256_next(code, scope, table, 9), Some(2));
        assert_eq!(s.idx256_next(code, scope, table, 5), Some(7));
        assert_eq!(s.idx256_next(code, scope, table, 7), None);
        assert_eq!(s.idx256_previous(code, scope, table, 2), Some(9));
        assert_eq!(s.idx256_previous(code, scope, table, 9), None);
        assert_eq!(s.idx256_last(code, scope, table), Some(7));

        // update re-points a row's 32-byte key: move primary 9 from key(10) to
        // key(25). The old key is gone, the new one resolves.
        s.update_index256_object(code, scope, table, 9, payer, key(25))
            .unwrap();
        assert_eq!(s.idx256_find_primary(code, scope, table, 9), Some(key(25)));
        assert_eq!(s.idx256_find_secondary(code, scope, table, key(10)), None);
        assert_eq!(
            s.idx256_find_secondary(code, scope, table, key(25)),
            Some(9)
        );
    }

    /// idx_double reads follow the software-float order (negatives before
    /// positives), tie-breaking equal secondaries by primary.
    #[test]
    fn idx_double_secondary_reads_follow_float_order() {
        let s = ArenaShadow::new().unwrap();
        let (code, scope, table, payer) = (1u64, 2u64, 3u64, 9u64);
        for &(primary, secondary) in &[(7u64, 3.5f64), (5, 2.0), (2, 2.0), (9, 1.0), (3, -1.0)] {
            s.create_idx_double_object(code, scope, table, payer, primary, secondary.to_bits())
                .unwrap();
        }

        // Order is: (3,-1.0) (9,1.0) (2,2.0) (5,2.0) (7,3.5).
        assert_eq!(
            s.idx_double_lower_bound(code, scope, table, -2.0),
            Some((3, -1.0))
        );
        assert_eq!(
            s.idx_double_lower_bound(code, scope, table, 1.5),
            Some((2, 2.0))
        );
        assert_eq!(s.idx_double_lower_bound(code, scope, table, 4.0), None);
        assert_eq!(
            s.idx_double_upper_bound(code, scope, table, 2.0),
            Some((7, 3.5))
        );
        assert_eq!(s.idx_double_upper_bound(code, scope, table, 3.5), None);
        assert_eq!(
            s.idx_double_find_secondary(code, scope, table, 2.0),
            Some(2)
        );
        assert_eq!(s.idx_double_find_secondary(code, scope, table, 2.5), None);
        assert_eq!(s.idx_double_find_primary(code, scope, table, 5), Some(2.0));

        // Secondary order is 3, 9, 2, 5, 7 (negatives first, ties by primary).
        assert_eq!(s.idx_double_next(code, scope, table, 3), Some(9));
        assert_eq!(s.idx_double_next(code, scope, table, 2), Some(5));
        assert_eq!(s.idx_double_next(code, scope, table, 7), None);
        assert_eq!(s.idx_double_previous(code, scope, table, 9), Some(3));
        assert_eq!(s.idx_double_previous(code, scope, table, 3), None);
        assert_eq!(s.idx_double_last(code, scope, table), Some(7));

        // update re-points a row's float key (bits -> from_bits): move primary 3
        // from -1.0 to 5.0. The old key is gone, the new one resolves.
        s.update_idx_double_object(code, scope, table, 3, payer, 5.0f64.to_bits())
            .unwrap();
        assert_eq!(s.idx_double_find_primary(code, scope, table, 3), Some(5.0));
        assert_eq!(s.idx_double_find_secondary(code, scope, table, -1.0), None);
        assert_eq!(
            s.idx_double_find_secondary(code, scope, table, 5.0),
            Some(3)
        );
    }

    /// idx_long_double reads order by the 128-bit key then primary.
    #[test]
    fn idx_long_double_secondary_reads_order_by_key() {
        let s = ArenaShadow::new().unwrap();
        let (code, scope, table, payer) = (1u64, 2u64, 3u64, 9u64);
        // (lo, hi) words; with hi small positive the 128-bit key sorts by hi.
        for &(primary, sec) in &[(7u64, (0u64, 3u64)), (5, (0, 2)), (2, (0, 2)), (9, (0, 1))] {
            s.create_idx_long_double_object(code, scope, table, payer, primary, sec)
                .unwrap();
        }

        // Order: (9,(0,1)) (2,(0,2)) (5,(0,2)) (7,(0,3)).
        assert_eq!(
            s.idx_long_double_lower_bound(code, scope, table, (0, 1)),
            Some((9, (0, 1)))
        );
        assert_eq!(
            s.idx_long_double_lower_bound(code, scope, table, (0, 2)),
            Some((2, (0, 2)))
        );
        assert_eq!(
            s.idx_long_double_upper_bound(code, scope, table, (0, 2)),
            Some((7, (0, 3)))
        );
        assert_eq!(
            s.idx_long_double_upper_bound(code, scope, table, (0, 3)),
            None
        );
        assert_eq!(
            s.idx_long_double_find_secondary(code, scope, table, (0, 2)),
            Some(2)
        );
        assert_eq!(
            s.idx_long_double_find_secondary(code, scope, table, (0, 4)),
            None
        );
        assert_eq!(
            s.idx_long_double_find_primary(code, scope, table, 5),
            Some((0, 2))
        );

        // Secondary order is 9, 2, 5, 7 (by 128-bit key then primary).
        assert_eq!(s.idx_long_double_next(code, scope, table, 9), Some(2));
        assert_eq!(s.idx_long_double_next(code, scope, table, 5), Some(7));
        assert_eq!(s.idx_long_double_next(code, scope, table, 7), None);
        assert_eq!(s.idx_long_double_previous(code, scope, table, 2), Some(9));
        assert_eq!(s.idx_long_double_previous(code, scope, table, 9), None);
        assert_eq!(s.idx_long_double_last(code, scope, table), Some(7));

        // update re-points a row's (lo, hi) key: move primary 9 from (0,1) to
        // (0,5). The old key is gone, the new one resolves.
        s.update_idx_long_double_object(code, scope, table, 9, payer, (0, 5))
            .unwrap();
        assert_eq!(
            s.idx_long_double_find_primary(code, scope, table, 9),
            Some((0, 5))
        );
        assert_eq!(
            s.idx_long_double_find_secondary(code, scope, table, (0, 1)),
            None
        );
        assert_eq!(
            s.idx_long_double_find_secondary(code, scope, table, (0, 5)),
            Some(9)
        );
    }
}
