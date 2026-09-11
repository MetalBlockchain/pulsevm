//! State-history (SHiP) chain-state delta serialization over the arena — the
//! pure-Rust port of nodeos' `pack_deltas` (state_history/create_deltas.cpp and
//! serialization.hpp). It reproduces, byte-for-byte, the per-block `table_delta`
//! stream chainbase used to emit, so a SHiP consumer sees an identical wire feed.
//!
//! The output is validated against a frozen C++ golden (`ship_golden.txt.gz`,
//! captured from a chainbase replay at commit 782d9a47): a full snapshot for the
//! first appended block, true per-block deltas after. See
//! `pulsevm_core/.../state_history/SHIP_DELTA_BLUEPRINT.md` for the full spec.
//!
//! Two facts pin the format down and are load-bearing here:
//! - chainbase prepends modified and removed rows to intrusive singly linked lists, so those groups
//!   are emitted in reverse first-touch order; new rows come from the primary index in ascending id
//!   order.
//! - `pack_deltas` runs *before* the block's undo session commits, so removed rows (and their
//!   blobs, held but not yet truncated) are still resolvable.

use std::collections::HashMap;

use pulsevm_arena::{
    ArenaObject,
    Db,
    ObjectId,
};

use super::{
    AccountMetaRow,
    AccountRow,
    CodeRow,
    ContractIndex64Row,
    ContractIndex128Row,
    ContractIndex256Row,
    ContractIndexDoubleRow,
    ContractIndexLongDoubleRow,
    ContractKeyValueRow,
    ContractTableRow,
    DeferredTransactionRow,
    GlobalPropertyRow,
    PermissionLinkRow,
    PermissionRow,
    ProtocolFeatureRow,
    ResourceConfigRow,
    ResourceLimitsRow,
    ResourceStateRow,
    ResourceUsageRow,
    UsageAccumulator,
};

/// Genesis `wasm_config` (config.hpp `default_initial_wasm_configuration`) — a
/// consensus constant the arena does not store because it never changes on this
/// chain. Only `global_property` (block-2 full snapshot, or a `setparams`
/// delta) serializes it. Verified against the golden's block-2 slice.
const WASM_CONFIG: [u32; 11] = [
    1024,     // max_mutable_global_bytes
    1024,     // max_table_elements
    8192,     // max_section_elements
    65536,    // max_linear_memory_init
    8192,     // max_func_local_bytes
    1024,     // max_nested_structures
    8192,     // max_symbol_bytes
    20971520, // max_module_bytes
    20971520, // max_code_bytes
    528,      // max_pages
    251,      // max_call_depth
];

/// Genesis `max_action_return_value_size` (config.hpp). Carried by the
/// `chain_config` history serialization but not by `GlobalPropertyRow` (the
/// params intrinsic never sets it), so it is sourced as the fixed constant.
const MAX_ACTION_RETURN_VALUE_SIZE: u32 = 256;

/// The 19 chain-state tables, in the fixed order `create_deltas.cpp` emits them.
/// A table appears in the stream only when it has entries for the block.
const TABLE_ORDER: [&str; 19] = [
    "account",
    "account_metadata",
    "code",
    "contract_table",
    "contract_row",
    "contract_index64",
    "contract_index128",
    "contract_index256",
    "contract_index_double",
    "contract_index_long_double",
    "global_property",
    "generated_transaction",
    "protocol_state",
    "permission",
    "permission_link",
    "resource_limits",
    "resource_usage",
    "resource_limits_state",
    "resource_limits_config",
];

/// Little-endian / LEB128 writer matching `fc::raw::pack` for the primitive
/// encodings the history format uses.
struct Ser {
    buf: Vec<u8>,
}

impl Ser {
    fn new() -> Self {
        Ser { buf: Vec::new() }
    }

    /// `fc::unsigned_int` LEB128 (also `history_pack_varuint64`).
    fn uvar(&mut self, mut v: u64) {
        loop {
            let mut b = (v as u8) & 0x7f;
            v >>= 7;
            if v > 0 {
                b |= 0x80;
            }
            self.buf.push(b);
            if v == 0 {
                break;
            }
        }
    }

    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn bool(&mut self, v: bool) {
        self.buf.push(v as u8);
    }

    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// `shared_string` / `bytes` / a table name: `uvar(len)` then the bytes.
    fn bytes(&mut self, b: &[u8]) {
        self.uvar(b.len() as u64);
        self.raw(b);
    }
}

/// A row ready to frame: whether it is present (a removal is `false`) and its
/// history-serialized payload.
type Rows = Vec<(bool, Vec<u8>)>;

/// One column serializer over the arena: given the whole db (for blob and
/// cross-table lookups) and a row of its type, append the history bytes.
fn ser_usage_accumulator(s: &mut Ser, a: &UsageAccumulator) {
    s.uvar(0);
    s.u32(a.last_ordinal);
    s.u64(a.value_ex);
    s.u64(a.consumed);
}

fn ser_account(s: &mut Ser, db: &Db, r: &AccountRow) {
    s.uvar(0);
    s.u64(r.name);
    s.u32(r.creation_date); // block_timestamp_type
    let abi = db.blob::<AccountRow>(r.abi).unwrap_or(&[]);
    s.bytes(abi);
}

fn ser_account_metadata(s: &mut Ser, r: &AccountMetaRow) {
    s.uvar(0);
    s.u64(r.name);
    s.bool(r.flags & 1 != 0); // is_privileged
    s.i64(r.last_code_update); // time_point (micros)
    let has_code = r.code_hash != [0u8; 32];
    s.bool(has_code);
    if has_code {
        s.u8(r.vm_type);
        s.u8(r.vm_version);
        s.raw(&r.code_hash);
    }
}

fn ser_code(s: &mut Ser, db: &Db, r: &CodeRow) {
    s.uvar(0);
    s.u8(r.vm_type);
    s.u8(r.vm_version);
    s.raw(&r.code_hash);
    let code = db.blob::<CodeRow>(r.code).unwrap_or(&[]);
    s.bytes(code);
}

fn ser_contract_table(s: &mut Ser, r: &ContractTableRow) {
    s.uvar(0);
    s.u64(r.code);
    s.u64(r.scope);
    s.u64(r.table);
    s.u64(r.payer);
}

/// Resolves a `t_id` (arena id of a `ContractTableRow`) to its `(code, scope,
/// table)`, consulting removed table_id rows too — a contract_row and its table
/// can be removed in the same block (chainbase's `removed_table_id` fallback).
fn table_id_context(map: &HashMap<i64, (u64, u64, u64)>, t_id: i64) -> (u64, u64, u64) {
    *map.get(&t_id).unwrap_or(&(0, 0, 0))
}

fn ser_contract_row(
    s: &mut Ser,
    db: &Db,
    map: &HashMap<i64, (u64, u64, u64)>,
    r: &ContractKeyValueRow,
) {
    let (code, scope, table) = table_id_context(map, r.t_id);
    s.uvar(0);
    s.u64(code);
    s.u64(scope);
    s.u64(table);
    s.u64(r.primary_key);
    s.u64(r.payer);
    let value = db.blob::<ContractKeyValueRow>(r.value).unwrap_or(&[]);
    s.bytes(value); // history_pack_big_bytes(shared_blob) == uvar(len)+bytes
}

fn ser_secondary_header(
    s: &mut Ser,
    map: &HashMap<i64, (u64, u64, u64)>,
    t_id: i64,
    primary_key: u64,
    payer: u64,
) {
    let (code, scope, table) = table_id_context(map, t_id);
    s.uvar(0);
    s.u64(code);
    s.u64(scope);
    s.u64(table);
    s.u64(primary_key);
    s.u64(payer);
}

fn ser_index64(s: &mut Ser, map: &HashMap<i64, (u64, u64, u64)>, r: &ContractIndex64Row) {
    ser_secondary_header(s, map, r.t_id, r.primary_key, r.payer);
    s.u64(r.secondary_key);
}

fn ser_index128(s: &mut Ser, map: &HashMap<i64, (u64, u64, u64)>, r: &ContractIndex128Row) {
    ser_secondary_header(s, map, r.t_id, r.primary_key, r.payer);
    // fc::raw::pack(uint128) == 16 bytes little-endian == low word then high word.
    s.u64(r.sec_lo);
    s.u64(r.sec_hi);
}

fn ser_index256(s: &mut Ser, map: &HashMap<i64, (u64, u64, u64)>, r: &ContractIndex256Row) {
    ser_secondary_header(s, map, r.t_id, r.primary_key, r.payer);
    // key256_t serialization byte-reverses each 16-byte word (serialization.hpp
    // `rev`), then packs it; the arena stores the two words verbatim.
    let mut w0: [u8; 16] = r.secondary_key[0..16].try_into().unwrap();
    let mut w1: [u8; 16] = r.secondary_key[16..32].try_into().unwrap();
    w0.reverse();
    w1.reverse();
    s.raw(&w0);
    s.raw(&w1);
}

fn ser_index_double(s: &mut Ser, map: &HashMap<i64, (u64, u64, u64)>, r: &ContractIndexDoubleRow) {
    ser_secondary_header(s, map, r.t_id, r.primary_key, r.payer);
    // nodeos copies the IEEE-754 bit pattern into a uint64 before packing it.
    s.u64(r.secondary_key.to_bits());
}

fn ser_index_long_double(
    s: &mut Ser,
    map: &HashMap<i64, (u64, u64, u64)>,
    r: &ContractIndexLongDoubleRow,
) {
    ser_secondary_header(s, map, r.t_id, r.primary_key, r.payer);
    // float128_t is copied into a uint128 and packed little-endian: low word,
    // then high word. The Arena row stores those words separately.
    s.u64(r.sec_lo);
    s.u64(r.sec_hi);
}

fn ser_generated_transaction(s: &mut Ser, db: &Db, r: &DeferredTransactionRow) {
    s.uvar(0);
    s.u64(r.sender);
    s.u64(r.sender_id_lo);
    s.u64(r.sender_id_hi);
    s.u64(r.payer);
    s.raw(&r.trx_id);
    let packed = db
        .blob::<DeferredTransactionRow>(r.packed_trx)
        .unwrap_or(&[]);
    s.bytes(packed);
}

fn ser_global_property(s: &mut Ser, r: &GlobalPropertyRow, chain_id: &[u8; 32]) {
    s.uvar(1); // global_property_object history version = 1
    // Leap 5 serializes the optional producer-authority schedule before the
    // chain config. Arena currently has the producer schedule in Controller,
    // not in this row, so emit the valid empty schedule shape. The three
    // fields are: optional-present=false, schedule version 0, producer count 0.
    s.bool(false);
    s.u32(0);
    s.uvar(0);
    // chain_config (history version 1).
    s.uvar(1);
    s.u64(r.max_block_net_usage);
    s.u32(r.target_block_net_usage_pct);
    s.u32(r.max_transaction_net_usage);
    s.u32(r.base_per_transaction_net_usage);
    s.u32(r.net_usage_leeway);
    s.u32(r.context_free_discount_net_usage_num);
    s.u32(r.context_free_discount_net_usage_den);
    s.u32(r.max_block_cpu_usage);
    s.u32(r.target_block_cpu_usage_pct);
    s.u32(r.max_transaction_cpu_usage);
    s.u32(r.min_transaction_cpu_usage);
    s.u32(r.max_transaction_lifetime);
    s.u32(r.deferred_trx_expiration_window);
    s.u32(r.max_transaction_delay);
    s.u32(r.max_inline_action_size);
    s.u16(r.max_inline_action_depth);
    s.u16(r.max_authority_depth);
    s.u32(MAX_ACTION_RETURN_VALUE_SIZE);
    // chain_id, then wasm_config (history version 0).
    s.raw(chain_id);
    s.uvar(0);
    for v in WASM_CONFIG {
        s.u32(v);
    }
}

/// The permission authority blob (`encode_authority`) re-serialized in history
/// order. Layout of the stored blob: threshold u32, then length-prefixed
/// key/account/wait containers (see `pulsevm_database::database::encode_authority`).
/// A `public_key`'s stored packed form (tag byte + 33 bytes for K1) is exactly
/// its `fc::raw::pack(public_key_type)` encoding, so key bytes pass through.
fn ser_authority(s: &mut Ser, blob: &[u8]) {
    // A default (never-authored) authority: threshold 0 and three empty
    // containers. Also the shape of the reserved id-0 permission's authority.
    if blob.is_empty() {
        s.u32(0);
        s.uvar(0);
        s.uvar(0);
        s.uvar(0);
        return;
    }
    let mut p = 0usize;
    let rd_u16 = |b: &[u8], p: &mut usize| -> u16 {
        let v = u16::from_le_bytes(b[*p..*p + 2].try_into().unwrap());
        *p += 2;
        v
    };
    let rd_u32 = |b: &[u8], p: &mut usize| -> u32 {
        let v = u32::from_le_bytes(b[*p..*p + 4].try_into().unwrap());
        *p += 4;
        v
    };
    let rd_u64 = |b: &[u8], p: &mut usize| -> u64 {
        let v = u64::from_le_bytes(b[*p..*p + 8].try_into().unwrap());
        *p += 8;
        v
    };

    let threshold = rd_u32(blob, &mut p);
    s.u32(threshold);

    let nkeys = rd_u32(blob, &mut p);
    s.uvar(nkeys as u64);
    for _ in 0..nkeys {
        let len = rd_u32(blob, &mut p) as usize;
        s.raw(&blob[p..p + len]); // packed public_key == fc public_key_type bytes
        p += len;
        let weight = rd_u16(blob, &mut p);
        s.u16(weight);
    }

    let naccounts = rd_u32(blob, &mut p);
    s.uvar(naccounts as u64);
    for _ in 0..naccounts {
        let actor = rd_u64(blob, &mut p);
        let permission = rd_u64(blob, &mut p);
        let weight = rd_u16(blob, &mut p);
        s.u64(actor);
        s.u64(permission);
        s.u16(weight);
    }

    let nwaits = rd_u32(blob, &mut p);
    s.uvar(nwaits as u64);
    for _ in 0..nwaits {
        let wait_sec = rd_u32(blob, &mut p);
        let weight = rd_u16(blob, &mut p);
        s.u32(wait_sec);
        s.u16(weight);
    }
}

fn ser_permission(s: &mut Ser, db: &Db, parent_names: &HashMap<i64, u64>, r: &PermissionRow) {
    s.uvar(0);
    s.u64(r.owner);
    s.u64(r.perm_name);
    // parent's perm_name (0 when this is a root permission).
    let parent_name = if r.parent != 0 {
        *parent_names.get(&r.parent).unwrap_or(&0)
    } else {
        0
    };
    s.u64(parent_name);
    s.i64(r.last_updated); // time_point
    let auth = db.blob::<PermissionRow>(r.auth).unwrap_or(&[]);
    ser_authority(s, auth);
}

fn ser_permission_link(s: &mut Ser, r: &PermissionLinkRow) {
    s.uvar(0);
    s.u64(r.account);
    s.u64(r.code);
    s.u64(r.message_type);
    s.u64(r.required_permission);
}

fn ser_resource_limits(s: &mut Ser, r: &ResourceLimitsRow) {
    s.uvar(0);
    s.u64(r.owner);
    s.i64(r.net_weight);
    s.i64(r.cpu_weight);
    s.i64(r.ram_bytes);
}

fn ser_resource_usage(s: &mut Ser, r: &ResourceUsageRow) {
    s.uvar(0);
    s.u64(r.owner);
    ser_usage_accumulator(s, &r.net_usage);
    ser_usage_accumulator(s, &r.cpu_usage);
    s.u64(r.ram_usage);
}

fn ser_resource_limits_state(s: &mut Ser, r: &ResourceStateRow) {
    s.uvar(0);
    ser_usage_accumulator(s, &r.average_block_net_usage);
    ser_usage_accumulator(s, &r.average_block_cpu_usage);
    s.u64(r.total_net_weight);
    s.u64(r.total_cpu_weight);
    s.u64(r.total_ram_bytes);
    s.u64(r.virtual_net_limit);
    s.u64(r.virtual_cpu_limit);
}

fn ser_ratio(s: &mut Ser, num: u64, den: u64) {
    s.uvar(0);
    s.u64(num);
    s.u64(den);
}

fn ser_resource_limits_config(s: &mut Ser, r: &ResourceConfigRow) {
    s.uvar(0);
    // cpu elastic_limit_parameters.
    s.uvar(0);
    s.u64(r.cpu_target);
    s.u64(r.cpu_max);
    s.u32(r.cpu_periods);
    s.u32(r.cpu_max_multiplier);
    ser_ratio(s, r.cpu_contract_num, r.cpu_contract_den);
    ser_ratio(s, r.cpu_expand_num, r.cpu_expand_den);
    // net elastic_limit_parameters.
    s.uvar(0);
    s.u64(r.net_target);
    s.u64(r.net_max);
    s.u32(r.net_periods);
    s.u32(r.net_max_multiplier);
    ser_ratio(s, r.net_contract_num, r.net_contract_den);
    ser_ratio(s, r.net_expand_num, r.net_expand_den);
    s.u32(r.account_cpu_usage_average_window);
    s.u32(r.account_net_usage_average_window);
}

/// Builds `t_id -> (code, scope, table)` from live and (session-)removed
/// `ContractTableRow`s, so contract_row/index serialization can resolve a table
/// even when it was removed in the same block.
fn table_id_map(db: &Db, full_snapshot: bool) -> HashMap<i64, (u64, u64, u64)> {
    let mut map = HashMap::new();
    if let Ok(t) = db.table::<ContractTableRow>() {
        for r in t.iter() {
            map.insert(r.id().raw(), (r.code, r.scope, r.table));
        }
        if !full_snapshot && let Some(ch) = t.last_undo_session_changes() {
            for (id, r) in ch.removed_values {
                map.entry(id).or_insert((r.code, r.scope, r.table));
            }
        }
    }
    map
}

/// Builds `cb_id -> perm_name` from live and (session-)removed permissions, for
/// resolving a permission's parent name (the parent may be removed alongside it).
fn permission_parent_names(db: &Db, full_snapshot: bool) -> HashMap<i64, u64> {
    let mut map = HashMap::new();
    if let Ok(t) = db.table::<PermissionRow>() {
        for r in t.iter() {
            map.insert(r.cb_id, r.perm_name);
        }
        if !full_snapshot && let Some(ch) = t.last_undo_session_changes() {
            for (_id, r) in ch.removed_values {
                map.entry(r.cb_id).or_insert(r.perm_name);
            }
        }
    }
    map
}

/// Whether a modification to a `T` is materially different enough to emit
/// (chainbase `include_delta`). Default is "any change"; the exceptions mirror
/// the C++ overloads.
trait IncludeDelta {
    fn include_delta(old: &Self, curr: &Self) -> bool;
}

impl IncludeDelta for AccountRow {
    fn include_delta(_: &Self, _: &Self) -> bool {
        true
    }
}
impl IncludeDelta for AccountMetaRow {
    fn include_delta(o: &Self, c: &Self) -> bool {
        o.name != c.name
            || (o.flags & 1) != (c.flags & 1)
            || o.last_code_update != c.last_code_update
            || o.vm_type != c.vm_type
            || o.vm_version != c.vm_version
            || o.code_hash != c.code_hash
    }
}
impl IncludeDelta for CodeRow {
    fn include_delta(_: &Self, _: &Self) -> bool {
        // code_object history data is never modified, only created/deleted.
        false
    }
}
impl IncludeDelta for ContractTableRow {
    fn include_delta(o: &Self, c: &Self) -> bool {
        o.payer != c.payer
    }
}
impl IncludeDelta for ContractKeyValueRow {
    fn include_delta(_: &Self, _: &Self) -> bool {
        true
    }
}
impl IncludeDelta for ContractIndex64Row {
    fn include_delta(_: &Self, _: &Self) -> bool {
        true
    }
}
impl IncludeDelta for ContractIndex128Row {
    fn include_delta(_: &Self, _: &Self) -> bool {
        true
    }
}
impl IncludeDelta for ContractIndex256Row {
    fn include_delta(_: &Self, _: &Self) -> bool {
        true
    }
}
impl IncludeDelta for ContractIndexDoubleRow {
    fn include_delta(_: &Self, _: &Self) -> bool {
        true
    }
}
impl IncludeDelta for ContractIndexLongDoubleRow {
    fn include_delta(_: &Self, _: &Self) -> bool {
        true
    }
}
impl IncludeDelta for GlobalPropertyRow {
    fn include_delta(_: &Self, _: &Self) -> bool {
        true
    }
}
impl IncludeDelta for DeferredTransactionRow {
    fn include_delta(_: &Self, _: &Self) -> bool {
        true
    }
}
impl IncludeDelta for PermissionRow {
    fn include_delta(_: &Self, _: &Self) -> bool {
        true
    }
}
impl IncludeDelta for PermissionLinkRow {
    fn include_delta(_: &Self, _: &Self) -> bool {
        true
    }
}
impl IncludeDelta for ResourceLimitsRow {
    fn include_delta(o: &Self, c: &Self) -> bool {
        o.net_weight != c.net_weight || o.cpu_weight != c.cpu_weight || o.ram_bytes != c.ram_bytes
    }
}
impl IncludeDelta for ResourceUsageRow {
    fn include_delta(_: &Self, _: &Self) -> bool {
        true
    }
}
impl IncludeDelta for ResourceStateRow {
    fn include_delta(o: &Self, c: &Self) -> bool {
        o.average_block_net_usage != c.average_block_net_usage
            || o.average_block_cpu_usage != c.average_block_cpu_usage
            || o.total_net_weight != c.total_net_weight
            || o.total_cpu_weight != c.total_cpu_weight
            || o.total_ram_bytes != c.total_ram_bytes
            || o.virtual_net_limit != c.virtual_net_limit
            || o.virtual_cpu_limit != c.virtual_cpu_limit
    }
}
impl IncludeDelta for ResourceConfigRow {
    fn include_delta(o: &Self, c: &Self) -> bool {
        // chainbase modifies resource_limits_config only on `setparams`; the
        // arena re-applies the (unchanging) genesis params every block via
        // `set_block_parameters`, so drop a modify that changed nothing to match.
        o.cpu_target != c.cpu_target
            || o.cpu_max != c.cpu_max
            || o.cpu_contract_num != c.cpu_contract_num
            || o.cpu_contract_den != c.cpu_contract_den
            || o.cpu_expand_num != c.cpu_expand_num
            || o.cpu_expand_den != c.cpu_expand_den
            || o.cpu_periods != c.cpu_periods
            || o.cpu_max_multiplier != c.cpu_max_multiplier
            || o.net_target != c.net_target
            || o.net_max != c.net_max
            || o.net_contract_num != c.net_contract_num
            || o.net_contract_den != c.net_contract_den
            || o.net_expand_num != c.net_expand_num
            || o.net_expand_den != c.net_expand_den
            || o.net_periods != c.net_periods
            || o.net_max_multiplier != c.net_max_multiplier
            || o.account_cpu_usage_average_window != c.account_cpu_usage_average_window
            || o.account_net_usage_average_window != c.account_net_usage_average_window
    }
}

/// Collects a table's rows for the block, in chainbase order: for a full
/// snapshot every live row (id order); for a delta the modified rows that pass
/// `include_delta` (present, current value), then removed rows (absent), then
/// new rows (present). `ser` serializes one live row.
fn collect_table<T, F>(db: &Db, full_snapshot: bool, mut ser: F) -> Rows
where
    T: ArenaObject + Clone + IncludeDelta,
    F: FnMut(&Db, &T) -> Vec<u8>,
{
    let mut rows: Rows = Vec::new();
    let Ok(table) = db.table::<T>() else {
        return rows;
    };

    if full_snapshot {
        let mut live: Vec<&T> = table.iter().collect();
        live.sort_by_key(|r| r.id().raw());
        for r in live {
            rows.push((true, ser(db, r)));
        }
        return rows;
    }

    let Some(changes) = table.last_undo_session_changes() else {
        return rows;
    };

    // chainbase emits modified rows, then removed rows, then new rows. Its
    // intrusive undo lists use push_front, so modified and removed rows arrive
    // in reverse first-touch order; new rows come from the primary index in
    // ascending id (creation) order.
    for (id, old_row) in &changes.old_values {
        if let Some(curr) = table.find(ObjectId::new(*id))
            && T::include_delta(old_row, curr)
        {
            rows.push((true, ser(db, curr)));
        }
    }

    for (_id, removed_row) in &changes.removed_values {
        rows.push((false, ser(db, removed_row)));
    }

    let mut created: Vec<&T> = table
        .iter()
        .filter(|r| r.id().raw() >= changes.old_next_id)
        .collect();
    created.sort_by_key(|r| r.id().raw());
    for r in created {
        rows.push((true, ser(db, r)));
    }

    rows
}

/// The `protocol_state` singleton: imported feature activations are retained
/// for lossless SHiP export. A new Pulse chain does not activate additional
/// source features, so live deltas remain empty.
fn collect_protocol_state(db: &Db, full_snapshot: bool) -> Rows {
    if !full_snapshot {
        return Vec::new();
    }
    let mut features: Vec<_> = db
        .table::<ProtocolFeatureRow>()
        .map(|table| table.iter().copied().collect())
        .unwrap_or_default();
    features.sort_by_key(|row| row.id().raw());
    let mut s = Ser::new();
    s.uvar(0); // protocol_state_v0 history version
    s.uvar(features.len() as u64);
    for feature in features {
        s.uvar(0); // activated_protocol_feature_v0 history version
        s.raw(&feature.feature_digest);
        s.u32(feature.activation_block_num);
    }
    vec![(true, s.buf)]
}

fn frame_table(out: &mut Ser, name: &str, rows: &Rows) {
    if rows.is_empty() {
        return;
    }
    out.uvar(0); // table_delta variant struct_version
    out.bytes(name.as_bytes());
    out.uvar(rows.len() as u64);
    for (present, payload) in rows {
        out.bool(*present);
        out.uvar(payload.len() as u64);
        out.raw(payload);
    }
}

/// Serialize every chain-state table for the block into the `table_delta`
/// stream. `full_snapshot` emits all live rows; otherwise the open undo
/// session's per-block changes. `chain_id` supplies the one `global_property`
/// field the arena does not store.
pub(crate) fn pack_deltas(db: &Db, full_snapshot: bool, chain_id: &[u8; 32]) -> Vec<u8> {
    let tid_map = table_id_map(db, full_snapshot);
    let parent_names = permission_parent_names(db, full_snapshot);

    // Build every table's rows first so num_tables can count the non-empty ones.
    let mut per_table: HashMap<&str, Rows> = HashMap::new();

    per_table.insert(
        "account",
        collect_table::<AccountRow, _>(db, full_snapshot, |db, r| {
            let mut s = Ser::new();
            ser_account(&mut s, db, r);
            s.buf
        }),
    );
    per_table.insert(
        "account_metadata",
        collect_table::<AccountMetaRow, _>(db, full_snapshot, |_db, r| {
            let mut s = Ser::new();
            ser_account_metadata(&mut s, r);
            s.buf
        }),
    );
    per_table.insert(
        "code",
        collect_table::<CodeRow, _>(db, full_snapshot, |db, r| {
            let mut s = Ser::new();
            ser_code(&mut s, db, r);
            s.buf
        }),
    );
    per_table.insert(
        "contract_table",
        collect_table::<ContractTableRow, _>(db, full_snapshot, |_db, r| {
            let mut s = Ser::new();
            ser_contract_table(&mut s, r);
            s.buf
        }),
    );
    per_table.insert(
        "contract_row",
        collect_table::<ContractKeyValueRow, _>(db, full_snapshot, |db, r| {
            let mut s = Ser::new();
            ser_contract_row(&mut s, db, &tid_map, r);
            s.buf
        }),
    );
    per_table.insert(
        "contract_index64",
        collect_table::<ContractIndex64Row, _>(db, full_snapshot, |_db, r| {
            let mut s = Ser::new();
            ser_index64(&mut s, &tid_map, r);
            s.buf
        }),
    );
    per_table.insert(
        "contract_index128",
        collect_table::<ContractIndex128Row, _>(db, full_snapshot, |_db, r| {
            let mut s = Ser::new();
            ser_index128(&mut s, &tid_map, r);
            s.buf
        }),
    );
    per_table.insert(
        "contract_index256",
        collect_table::<ContractIndex256Row, _>(db, full_snapshot, |_db, r| {
            let mut s = Ser::new();
            ser_index256(&mut s, &tid_map, r);
            s.buf
        }),
    );
    per_table.insert(
        "contract_index_double",
        collect_table::<ContractIndexDoubleRow, _>(db, full_snapshot, |_db, r| {
            let mut s = Ser::new();
            ser_index_double(&mut s, &tid_map, r);
            s.buf
        }),
    );
    per_table.insert(
        "contract_index_long_double",
        collect_table::<ContractIndexLongDoubleRow, _>(db, full_snapshot, |_db, r| {
            let mut s = Ser::new();
            ser_index_long_double(&mut s, &tid_map, r);
            s.buf
        }),
    );
    per_table.insert(
        "global_property",
        collect_table::<GlobalPropertyRow, _>(db, full_snapshot, |_db, r| {
            let mut s = Ser::new();
            ser_global_property(&mut s, r, chain_id);
            s.buf
        }),
    );
    per_table.insert(
        "generated_transaction",
        collect_table::<DeferredTransactionRow, _>(db, full_snapshot, |db, r| {
            let mut s = Ser::new();
            ser_generated_transaction(&mut s, db, r);
            s.buf
        }),
    );
    per_table.insert("protocol_state", collect_protocol_state(db, full_snapshot));
    {
        let rows = collect_table::<PermissionRow, _>(db, full_snapshot, |db, r| {
            let mut s = Ser::new();
            ser_permission(&mut s, db, &parent_names, r);
            s.buf
        });
        per_table.insert("permission", rows);
    }
    per_table.insert(
        "permission_link",
        collect_table::<PermissionLinkRow, _>(db, full_snapshot, |_db, r| {
            let mut s = Ser::new();
            ser_permission_link(&mut s, r);
            s.buf
        }),
    );
    per_table.insert(
        "resource_limits",
        collect_table::<ResourceLimitsRow, _>(db, full_snapshot, |_db, r| {
            let mut s = Ser::new();
            ser_resource_limits(&mut s, r);
            s.buf
        }),
    );
    per_table.insert(
        "resource_usage",
        collect_table::<ResourceUsageRow, _>(db, full_snapshot, |_db, r| {
            let mut s = Ser::new();
            ser_resource_usage(&mut s, r);
            s.buf
        }),
    );
    per_table.insert(
        "resource_limits_state",
        collect_table::<ResourceStateRow, _>(db, full_snapshot, |_db, r| {
            let mut s = Ser::new();
            ser_resource_limits_state(&mut s, r);
            s.buf
        }),
    );
    per_table.insert(
        "resource_limits_config",
        collect_table::<ResourceConfigRow, _>(db, full_snapshot, |_db, r| {
            let mut s = Ser::new();
            ser_resource_limits_config(&mut s, r);
            s.buf
        }),
    );

    let num_tables = TABLE_ORDER
        .iter()
        .filter(|name| !per_table[**name].is_empty())
        .count();

    let mut out = Ser::new();
    out.uvar(num_tables as u64);
    for name in TABLE_ORDER {
        frame_table(&mut out, name, &per_table[name]);
    }
    out.buf
}

#[cfg(test)]
mod global_property_tests {
    use super::{
        GlobalPropertyRow,
        Ser,
        ser_global_property,
    };

    #[test]
    fn global_property_matches_leap5_envelope() {
        let row = GlobalPropertyRow {
            deferred_trx_expiration_window: 600,
            max_transaction_delay: 3_888_000,
            ..GlobalPropertyRow::default()
        };
        let chain_id = [0xabu8; 32];
        let mut ser = Ser::new();
        ser_global_property(&mut ser, &row, &chain_id);

        // 157 bytes is the Leap 5 global_property row shape: the six-byte
        // producer-schedule envelope and both deferred-transaction config
        // fields are part of the chain_config history version.
        assert_eq!(ser.buf.len(), 157);
        assert_eq!(&ser.buf[..8], &[1, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(u32::from_le_bytes(ser.buf[60..64].try_into().unwrap()), 600);
        assert_eq!(
            u32::from_le_bytes(ser.buf[64..68].try_into().unwrap()),
            3_888_000
        );
        assert_eq!(&ser.buf[80..112], &chain_id);
    }
}

#[cfg(test)]
mod tests {
    use pulsevm_arena::{
        ArenaObject,
        ObjectId,
    };

    use super::pack_deltas;
    use crate::{
        AccountMetaRow,
        PermissionRow,
    };

    #[derive(Debug, PartialEq, Eq)]
    struct PackedTable {
        name: String,
        rows: Vec<(bool, Vec<u8>)>,
    }

    fn read_uvar(bytes: &[u8], pos: &mut usize) -> u64 {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = bytes[*pos];
            *pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
            shift += 7;
        }
    }

    fn unpack_tables(bytes: &[u8]) -> Vec<PackedTable> {
        let mut pos = 0;
        let table_count = read_uvar(bytes, &mut pos);
        let mut tables = Vec::new();
        for _ in 0..table_count {
            assert_eq!(read_uvar(bytes, &mut pos), 0, "table_delta version");
            let name_len = read_uvar(bytes, &mut pos) as usize;
            let name = std::str::from_utf8(&bytes[pos..pos + name_len])
                .unwrap()
                .to_owned();
            pos += name_len;
            let row_count = read_uvar(bytes, &mut pos);
            let mut rows = Vec::new();
            for _ in 0..row_count {
                let present = bytes[pos] != 0;
                pos += 1;
                let payload_len = read_uvar(bytes, &mut pos) as usize;
                rows.push((present, bytes[pos..pos + payload_len].to_vec()));
                pos += payload_len;
            }
            tables.push(PackedTable { name, rows });
        }
        assert_eq!(pos, bytes.len(), "unparsed SHiP bytes remain");
        tables
    }

    fn metadata_name(payload: &[u8]) -> u64 {
        let mut pos = 0;
        assert_eq!(read_uvar(payload, &mut pos), 0, "row version");
        u64::from_le_bytes(payload[pos..pos + 8].try_into().unwrap())
    }

    #[test]
    fn empty_delta_has_no_tables() {
        let db = crate::build_registered_db().unwrap();
        assert_eq!(pack_deltas(&db, false, &[0; 32]), [0]);
    }

    #[test]
    fn empty_full_snapshot_contains_protocol_state_without_permission_sentinel() {
        let db = crate::build_registered_db().unwrap();
        let expected = vec![
            1, // one non-empty table
            0, // table_delta version
            14, b'p', b'r', b'o', b't', b'o', b'c', b'o', b'l', b'_', b's', b't', b'a', b't', b'e',
            1, // one row
            1, // present
            2, // row payload length
            0, // protocol_state version
            0, // no activated protocol features
        ];
        assert_eq!(pack_deltas(&db, true, &[0; 32]), expected);
    }

    #[test]
    fn full_snapshot_serializes_reserved_permission_zero() {
        let mut db = crate::build_registered_db().unwrap();
        db.create::<PermissionRow>(|row| {
            row.cb_id = 0;
            row.usage_id = 0;
        })
        .unwrap();

        let tables = unpack_tables(&pack_deltas(&db, true, &[0; 32]));
        let permission = tables
            .iter()
            .find(|table| table.name == "permission")
            .unwrap();
        assert_eq!(permission.rows, vec![(true, vec![0; 40])]);
    }

    #[test]
    fn delta_frames_modified_removed_and_created_rows_in_chainbase_order() {
        let mut db = crate::build_registered_db().unwrap();
        for name in [10, 20, 30] {
            db.create::<AccountMetaRow>(|row| row.name = name).unwrap();
        }

        db.start_undo_session();
        db.modify::<AccountMetaRow>(ObjectId::new(0), |row| row.flags = 1)
            .unwrap();
        db.start_undo_session();
        db.modify::<AccountMetaRow>(ObjectId::new(1), |row| row.flags = 1)
            .unwrap();
        db.modify::<AccountMetaRow>(ObjectId::new(0), |row| row.last_code_update = 7)
            .unwrap();
        db.modify::<AccountMetaRow>(ObjectId::new(2), |row| row.flags = 1)
            .unwrap();
        db.remove::<AccountMetaRow>(ObjectId::new(1)).unwrap();
        let created = db
            .create::<AccountMetaRow>(|row| row.name = 40)
            .unwrap()
            .id();
        assert_eq!(created.raw(), 3);
        db.squash();

        let tables = unpack_tables(&pack_deltas(&db, false, &[0; 32]));
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].name, "account_metadata");
        let rows: Vec<(bool, u64)> = tables[0]
            .rows
            .iter()
            .map(|(present, payload)| (*present, metadata_name(payload)))
            .collect();
        assert_eq!(rows, vec![(true, 30), (true, 10), (false, 20), (true, 40)]);
    }

    #[test]
    fn full_snapshot_is_id_ordered_and_deterministic() {
        let mut db = crate::build_registered_db().unwrap();
        for name in [30, 10, 20] {
            db.create::<AccountMetaRow>(|row| row.name = name).unwrap();
        }

        let first = pack_deltas(&db, true, &[7; 32]);
        let second = pack_deltas(&db, true, &[7; 32]);
        assert_eq!(first, second);
        let tables = unpack_tables(&first);
        let metadata = tables
            .iter()
            .find(|table| table.name == "account_metadata")
            .unwrap();
        let names: Vec<u64> = metadata
            .rows
            .iter()
            .map(|(present, payload)| {
                assert!(*present);
                metadata_name(payload)
            })
            .collect();
        assert_eq!(names, [30, 10, 20], "full snapshots follow object id order");
    }
}
