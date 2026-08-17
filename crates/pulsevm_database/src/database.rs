#![allow(clippy::needless_return, clippy::too_many_arguments)]

use std::{
    fs,
    io::{
        Read,
        Seek,
        SeekFrom,
        Write,
    },
    path::Path,
};

use pulsevm_error::ChainError;
use pulsevm_name::Name;

use crate::{
    Authority,
    ChainConfigV0,
    CpuLimitResult,
    ElasticLimitParameters,
    Float128,
    NetLimitResult,
    // `PermissionObject` is named only for its compile-time `billable_size_v`
    // (the RAM a permission bills); the arena is the sole database backend.
    PermissionObject,
    Ratio,
    U256,
};

/// The RAM a `permission_link_object` is billed:
/// `billable_size_v<permission_link_object>` = round_up_16(40 + 3*32) = 144
/// (config.hpp / permission_link_object.hpp in the reference chain).
const PERMISSION_LINK_OBJECT_BILLABLE: i64 = 144;
// The public `Database` methods use the shared pure-Rust time type.
use pulsevm_chain_types::TimePoint;
// These pure-Rust authority sub-types back the arena authority decoder.
use crate::{
    KeyWeight,
    PermissionLevel,
    PermissionLevelWeight,
    WaitWeight,
};
use pulsevm_billable_size::billable_size_v;
use pulsevm_crypto::k1::K1PublicKey;

/// Field-for-field snapshot of an `account_metadata_object` read back from the
/// arena database, matching the chainbase accessors used to diff it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArenaAccountMetadata {
    pub privileged: bool,
    pub recv_sequence: u64,
    pub auth_sequence: u64,
    pub code_sequence: u64,
    pub abi_sequence: u64,
    pub code_hash: [u8; 32],
    pub vm_type: u8,
    pub vm_version: u8,
}
/// Converts public elastic-limit parameters into the arena's stored form.
fn to_elastic_params(p: &ElasticLimitParameters) -> crate::backend::ElasticParams {
    crate::backend::ElasticParams {
        target: p.target,
        max: p.max,
        periods: p.periods,
        max_multiplier: p.max_multiplier,
        contract: (p.contract_rate.numerator, p.contract_rate.denominator),
        expand: (p.expand_rate.numerator, p.expand_rate.denominator),
    }
}

/// Reverse of [`to_elastic_params`]: rebuilds `ElasticLimitParameters` from the
/// arena's stored form.
fn from_elastic_params(p: &crate::backend::ElasticParams) -> ElasticLimitParameters {
    ElasticLimitParameters {
        target: p.target,
        max: p.max,
        periods: p.periods,
        max_multiplier: p.max_multiplier,
        contract_rate: Ratio {
            numerator: p.contract.0,
            denominator: p.contract.1,
        },
        expand_rate: Ratio {
            numerator: p.expand.0,
            denominator: p.expand.1,
        },
    }
}

/// The runtime `chain_config` rebuilt from the arena params — the same
/// 16 fields, `deferred_trx_expiration_window` reported 0 as above. Lets the
/// per-transaction and per-block config reads use an owned value.
fn chain_config_v0_from_params(p: &crate::backend::ChainConfigParams) -> ChainConfigV0 {
    ChainConfigV0 {
        max_block_net_usage: p.max_block_net_usage,
        target_block_net_usage_pct: p.target_block_net_usage_pct,
        max_transaction_net_usage: p.max_transaction_net_usage,
        base_per_transaction_net_usage: p.base_per_transaction_net_usage,
        net_usage_leeway: p.net_usage_leeway,
        context_free_discount_net_usage_num: p.context_free_discount_net_usage_num,
        context_free_discount_net_usage_den: p.context_free_discount_net_usage_den,
        max_block_cpu_usage: p.max_block_cpu_usage,
        target_block_cpu_usage_pct: p.target_block_cpu_usage_pct,
        max_transaction_cpu_usage: p.max_transaction_cpu_usage,
        min_transaction_cpu_usage: p.min_transaction_cpu_usage,
        max_transaction_lifetime: p.max_transaction_lifetime,
        deferred_trx_expiration_window: 0,
        max_transaction_delay: p.max_transaction_delay,
        max_inline_action_size: p.max_inline_action_size,
        max_inline_action_depth: p.max_inline_action_depth,
        max_authority_depth: p.max_authority_depth,
    }
}

/// The same params from the `ChainConfigV0` a `setparams` intrinsic just wrote —
/// so the database updates to exactly what chainbase was handed.
fn chain_config_params_from_v0(cfg: &ChainConfigV0) -> crate::backend::ChainConfigParams {
    crate::backend::ChainConfigParams {
        max_block_net_usage: cfg.max_block_net_usage,
        target_block_net_usage_pct: cfg.target_block_net_usage_pct,
        max_transaction_net_usage: cfg.max_transaction_net_usage,
        base_per_transaction_net_usage: cfg.base_per_transaction_net_usage,
        net_usage_leeway: cfg.net_usage_leeway,
        context_free_discount_net_usage_num: cfg.context_free_discount_net_usage_num,
        context_free_discount_net_usage_den: cfg.context_free_discount_net_usage_den,
        max_block_cpu_usage: cfg.max_block_cpu_usage,
        target_block_cpu_usage_pct: cfg.target_block_cpu_usage_pct,
        max_transaction_cpu_usage: cfg.max_transaction_cpu_usage,
        min_transaction_cpu_usage: cfg.min_transaction_cpu_usage,
        max_transaction_lifetime: cfg.max_transaction_lifetime,
        max_transaction_delay: cfg.max_transaction_delay,
        max_inline_action_size: cfg.max_inline_action_size,
        max_inline_action_depth: cfg.max_inline_action_depth,
        max_authority_depth: cfg.max_authority_depth,
    }
}

/// Name-encode a table/scope identifier for the RPC formatters.
fn name_u64(s: &str) -> Result<u64, ChainError> {
    use std::str::FromStr;
    pulsevm_name::Name::from_str(s)
        .map(|n| n.as_u64())
        .map_err(|e| ChainError::InternalError(format!("bad name {s:?}: {e:?}")))
}

/// The raw `symbol_code` form of a ticker: its ASCII bytes packed low byte first
/// (a token contract's `stat` table is scoped by this).
fn symbol_code_from_str(s: &str) -> u64 {
    let mut raw = 0u64;
    for (i, b) in s.bytes().take(7).enumerate() {
        raw |= (b as u64) << (8 * i);
    }
    raw
}

/// fc's `block_timestamp` epoch (2000-01-01T00:00:00) in microseconds.
const BLOCK_TIMESTAMP_EPOCH_MICROS: i64 = 946_684_800_000_000;

/// A `block_timestamp` slot (500ms since the epoch) to fc microseconds — the
/// account creation date the RPC formatter renders.
fn block_slot_to_micros(slot: u32) -> i64 {
    BLOCK_TIMESTAMP_EPOCH_MICROS + slot as i64 * 500_000
}

/// An fc time point to its containing 500ms block-timestamp slot.
fn micros_to_block_slot(micros: i64) -> u32 {
    micros
        .saturating_sub(BLOCK_TIMESTAMP_EPOCH_MICROS)
        .div_euclid(500_000)
        .clamp(0, u32::MAX as i64) as u32
}

/// Parse a symbol string (`"4,SYS"`, or a bare code) to its packed form
/// (precision in the low byte, ASCII code above). Used only when the RPC caller
/// supplies an expected core symbol.
fn symbol_from_str(s: &str) -> Option<u64> {
    let (precision, code) = match s.split_once(',') {
        Some((p, c)) => (p.trim().parse::<u64>().ok()?, c.trim()),
        None => (0, s.trim()),
    };
    Some((symbol_code_from_str(code) << 8) | (precision & 0xff))
}

/// C++ `convert_to_type<uint64_t>` compatibility for RPC scopes and i64 keys:
/// decimal first, then an EOSIO name, then a symbol (with optional precision).
fn rpc_u64(s: &str, description: &str) -> Result<u64, ChainError> {
    use std::str::FromStr;

    if let Ok(value) = s.parse::<u64>() {
        return Ok(value);
    }
    if let Ok(name) = Name::from_str(s.trim()) {
        return Ok(name.as_u64());
    }
    let symbol = if s.contains(',') {
        symbol_from_str(s)
    } else {
        // `string_to_symbol(0, s) >> 8` returns the bare symbol_code.
        Some(symbol_code_from_str(s))
    };
    symbol.ok_or_else(|| {
        ChainError::InternalError(format!("could not convert {description} {s:?} to uint64"))
    })
}

fn rpc_bound(s: &str, key_type: &str, description: &str) -> Result<u64, ChainError> {
    if key_type == "name" {
        name_u64(s)
    } else {
        rpc_u64(s, description)
    }
}

/// Return `(primary, physical index table)`, matching nodeos' accepted numeric
/// and ordinal spellings for `index_position`.
fn rpc_table_index(table: u64, position: &str) -> Result<(bool, u64), ChainError> {
    if table & 0x0f != 0 {
        return Err(ChainError::InternalError(format!(
            "unsupported table name {}",
            Name::new(table)
        )));
    }
    let primary = position.is_empty()
        || matches!(position, "first" | "primary" | "one")
        || position.parse::<u64>().is_ok_and(|p| p < 2);
    if primary {
        return Ok((true, table));
    }
    let pos = if position.starts_with("sec") || position == "two" {
        0
    } else if position.starts_with("ter") || position.starts_with("th") {
        1
    } else if position.starts_with("fou") {
        2
    } else if position.starts_with("fi") {
        3
    } else if position.starts_with("six") {
        4
    } else if position.starts_with("sev") {
        5
    } else if position.starts_with("eig") {
        6
    } else if position.starts_with("nin") {
        7
    } else if position.starts_with("ten") {
        8
    } else {
        position.parse::<u64>().map_err(|_| {
            ChainError::InternalError(format!("invalid index_position {position:?}"))
        })? - 2
    };
    Ok((false, table | (pos & 0x0f)))
}

type RpcPositionedRow = (u64, u64, Vec<u8>);

/// Apply the common inclusive-bound, direction, and pagination rules after a
/// primary or secondary index has produced rows in ascending key order.
fn rpc_table_page(
    rows: impl IntoIterator<Item = RpcPositionedRow>,
    lower: u64,
    upper: u64,
    reverse: bool,
    limit: u32,
) -> (Vec<RpcPositionedRow>, bool, String) {
    let mut rows: Vec<_> = rows
        .into_iter()
        .filter(|(key, _, _)| *key >= lower && *key <= upper)
        .collect();
    if reverse {
        rows.reverse();
    }
    let limit = limit.min(1000) as usize;
    let more = rows.len() > limit;
    let next_key = rows
        .get(limit)
        .map(|(key, _, _)| key.to_string())
        .unwrap_or_default();
    rows.truncate(limit);
    (rows, more, next_key)
}

/// Reconstructs an [`Authority`] from the blob [`encode_authority`] produced and
/// the arena stored — the exact inverse, so `decode_authority(encode_authority(a))`
/// round-trips. This is what lets the arena serve the *whole* authority (not just
/// the threshold) for authorization checks, which consume a bridge `Authority`
/// using the same canonical field order as the historical reference encoding.
fn decode_authority(blob: &[u8]) -> Result<Authority, ChainError> {
    fn take<'a>(b: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], ChainError> {
        let end = pos
            .checked_add(n)
            .filter(|e| *e <= b.len())
            .ok_or_else(|| ChainError::InternalError("authority blob truncated".into()))?;
        let s = &b[*pos..end];
        *pos = end;
        Ok(s)
    }
    fn rd_u16(b: &[u8], pos: &mut usize) -> Result<u16, ChainError> {
        Ok(u16::from_le_bytes(take(b, pos, 2)?.try_into().unwrap()))
    }
    fn rd_u32(b: &[u8], pos: &mut usize) -> Result<u32, ChainError> {
        Ok(u32::from_le_bytes(take(b, pos, 4)?.try_into().unwrap()))
    }
    fn rd_u64(b: &[u8], pos: &mut usize) -> Result<u64, ChainError> {
        Ok(u64::from_le_bytes(take(b, pos, 8)?.try_into().unwrap()))
    }

    let mut pos = 0usize;
    let threshold = rd_u32(blob, &mut pos)?;

    let nkeys = rd_u32(blob, &mut pos)? as usize;
    let mut keys = Vec::with_capacity(nkeys);
    for _ in 0..nkeys {
        let len = rd_u32(blob, &mut pos)? as usize;
        let key_bytes = take(blob, &mut pos, len)?;
        let key = K1PublicKey::from_packed(key_bytes)
            .map_err(|e| ChainError::InternalError(format!("authority key decode: {e}")))?;
        let weight = rd_u16(blob, &mut pos)?;
        keys.push(KeyWeight { key, weight });
    }

    let naccounts = rd_u32(blob, &mut pos)? as usize;
    let mut accounts = Vec::with_capacity(naccounts);
    for _ in 0..naccounts {
        let actor = rd_u64(blob, &mut pos)?;
        let permission = rd_u64(blob, &mut pos)?;
        let weight = rd_u16(blob, &mut pos)?;
        accounts.push(PermissionLevelWeight {
            permission: PermissionLevel { actor, permission },
            weight,
        });
    }

    let nwaits = rd_u32(blob, &mut pos)? as usize;
    let mut waits = Vec::with_capacity(nwaits);
    for _ in 0..nwaits {
        let wait_sec = rd_u32(blob, &mut pos)?;
        let weight = rd_u16(blob, &mut pos)?;
        waits.push(WaitWeight { wait_sec, weight });
    }

    Ok(Authority {
        threshold,
        keys,
        accounts,
        waits,
    })
}

/// Serializes an [`Authority`] into the deterministic byte layout the arena
/// stores for `permission_object::auth`. The exact
/// encoding is private to the database; it only has to be stable so equal
/// authorities hash equal.
/// Build an authority blob in the exact [`encode_authority`] layout from plain
/// parts, used while authoring pure-Rust genesis.
/// `keys` are `(packed_public_key_bytes, weight)`, `accounts` are
/// `(actor, permission, weight)`, `waits` are `(wait_sec, weight)`.
fn build_auth_blob(
    threshold: u32,
    keys: &[(Vec<u8>, u16)],
    accounts: &[(u64, u64, u16)],
    waits: &[(u32, u16)],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&threshold.to_le_bytes());
    out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for (bytes, weight) in keys {
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
        out.extend_from_slice(&weight.to_le_bytes());
    }
    out.extend_from_slice(&(accounts.len() as u32).to_le_bytes());
    for (actor, permission, weight) in accounts {
        out.extend_from_slice(&actor.to_le_bytes());
        out.extend_from_slice(&permission.to_le_bytes());
        out.extend_from_slice(&weight.to_le_bytes());
    }
    out.extend_from_slice(&(waits.len() as u32).to_le_bytes());
    for (wait_sec, weight) in waits {
        out.extend_from_slice(&wait_sec.to_le_bytes());
        out.extend_from_slice(&weight.to_le_bytes());
    }
    out
}

fn encode_authority(auth: &Authority) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&auth.threshold.to_le_bytes());
    out.extend_from_slice(&(auth.keys.len() as u32).to_le_bytes());
    for k in &auth.keys {
        let bytes = k.key.to_packed();
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
        out.extend_from_slice(&k.weight.to_le_bytes());
    }
    out.extend_from_slice(&(auth.accounts.len() as u32).to_le_bytes());
    for a in &auth.accounts {
        out.extend_from_slice(&a.permission.actor.to_le_bytes());
        out.extend_from_slice(&a.permission.permission.to_le_bytes());
        out.extend_from_slice(&a.weight.to_le_bytes());
    }
    out.extend_from_slice(&(auth.waits.len() as u32).to_le_bytes());
    for w in &auth.waits {
        out.extend_from_slice(&w.wait_sec.to_le_bytes());
        out.extend_from_slice(&w.weight.to_le_bytes());
    }
    out
}

/// `shared_authority::get_billable_size()` computed straight from the arena's
/// stored auth blob, so the newaccount RAM accounting has no chainbase object in
/// the loop. The per-key length prefix written by [`encode_authority`] is exactly
/// `fc::raw::pack_size(key)`, so this reproduces the C++ sum
/// (`authority.hpp::get_billable_size`): each key adds `billable_size_v<KeyWeight>`
/// plus its packed size, each account adds `billable_size_v<PermissionLevelWeight>`,
/// each wait adds `billable_size_v<WaitWeight>`. `None` if the blob is malformed.
fn authority_blob_billable_size(blob: &[u8]) -> Option<i64> {
    fn rd_u32(b: &[u8], pos: &mut usize) -> Option<usize> {
        let end = pos.checked_add(4).filter(|e| *e <= b.len())?;
        let v = u32::from_le_bytes(b[*pos..end].try_into().ok()?) as usize;
        *pos = end;
        Some(v)
    }
    fn skip(b: &[u8], pos: &mut usize, n: usize) -> Option<()> {
        let end = pos.checked_add(n).filter(|e| *e <= b.len())?;
        *pos = end;
        Some(())
    }

    let mut pos = 0usize;
    skip(blob, &mut pos, 4)?; // threshold
    let mut total: i64 = 0;

    let nkeys = rd_u32(blob, &mut pos)?;
    for _ in 0..nkeys {
        let key_len = rd_u32(blob, &mut pos)?;
        skip(blob, &mut pos, key_len)?; // packed key bytes
        skip(blob, &mut pos, 2)?; // weight
        total += billable_size_v::<KeyWeight>() as i64 + key_len as i64;
    }

    let naccounts = rd_u32(blob, &mut pos)?;
    for _ in 0..naccounts {
        skip(blob, &mut pos, 18)?; // actor(8) + permission(8) + weight(2)
        total += billable_size_v::<PermissionLevelWeight>() as i64;
    }

    let nwaits = rd_u32(blob, &mut pos)?;
    for _ in 0..nwaits {
        skip(blob, &mut pos, 6)?; // wait_sec(4) + weight(2)
        total += billable_size_v::<WaitWeight>() as i64;
    }

    Some(total)
}

#[derive(Clone)]
pub struct Database {
    /// The directory the arena persists into, kept so snapshots can checkpoint
    /// and restore at the same path without threading the config back down from
    /// the controller.
    path: String,
    /// The pure-Rust arena (pulsevm_chaindb). The sole state backend, shared
    /// across clones so every apply/transaction context reaches the same handle.
    backend: crate::backend::ChainDatabase,
}

/// The staged arena checkpoint file used to move a snapshot through the transport
/// envelope, relative to the database dir.
const SHARED_MEMORY_FILE: &str = "arena_snapshot.bin";

/// The persisted arena state, written on close and reloaded on open — the arena's
/// equivalent of chainbase's memory-mapped `shared_memory.bin`, so a node's state
/// survives a restart (including a state-synced node, whose block log does not
/// start at genesis).
const ARENA_STATE_FILE: &str = "arena_state.bin";

/// Read until `buf` is full or EOF, so each snapshot chunk is a fixed,
/// block-aligned size regardless of how the OS splits the underlying reads —
/// which keeps the sparse run boundaries (and thus the snapshot bytes)
/// deterministic. Returns the number of bytes read (< `buf.len()` only at EOF).
fn fill(f: &mut fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match f.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

impl Database {
    pub fn new(path: &str, _size: u64) -> Result<Self, String> {
        let backend =
            crate::backend::ChainDatabase::new().map_err(|e| format!("arena init: {e:?}"))?;
        // Reload persisted state if this directory already holds a checkpoint (a
        // restart, or a state-synced node). A fresh directory starts empty and the
        // controller authors genesis.
        let state_file = Path::new(path).join(ARENA_STATE_FILE);
        if state_file.exists() {
            backend
                .reload_from(&state_file)
                .map_err(|e| format!("arena reload {}: {e:?}", state_file.display()))?;
        }
        Ok(Database {
            path: path.to_string(),
            backend,
        })
    }

    /// The arena database's account_metadata privileged flag for `name`, or
    /// `None` if the database has no such row — for diffing
    /// against chainbase's `find_account_metadata`.
    pub fn arena_account_metadata_privileged(&self, name: u64) -> Option<bool> {
        self.backend.account_metadata_privileged(name)
    }

    /// Full account_metadata snapshot from the database, or `None` when the row
    /// is absent.
    pub fn arena_account_metadata(&self, name: u64) -> Option<ArenaAccountMetadata> {
        {
            Some(&self.backend)
                .and_then(|s| s.account_metadata(name))
                .map(
                    |(
                        privileged,
                        recv_sequence,
                        auth_sequence,
                        code_sequence,
                        abi_sequence,
                        code_hash,
                        vm_type,
                        vm_version,
                    )| {
                        ArenaAccountMetadata {
                            privileged,
                            recv_sequence,
                            auth_sequence,
                            code_sequence,
                            abi_sequence,
                            code_hash,
                            vm_type,
                            vm_version,
                        }
                    },
                )
        }
    }

    /// Permission snapshot `(parent id, authority threshold)` from the database, or
    /// `None` when the permission is absent — for diffing
    /// against chainbase's `find_permission_by_actor_and_permission`.
    pub fn arena_permission(&self, owner: u64, perm_name: u64) -> Option<(i64, u32)> {
        self.backend.permission(owner, perm_name)
    }

    /// The full authority for `(owner, perm_name)` reconstructed from the arena's
    /// stored `shared_authority` blob, or `None` when the
    /// permission is absent. This is the whole authority the authorization checker
    /// consumes (threshold, keys, accounts, waits), not just the threshold, so it
    /// can eventually replace the chainbase `PermissionObject::get_authority` read.
    pub fn arena_permission_authority(&self, owner: u64, perm_name: u64) -> Option<Authority> {
        let blob = Some(&self.backend).and_then(|s| s.permission_auth_blob(owner, perm_name))?;
        decode_authority(&blob).ok()
    }

    /// Every permission of `owner` as `(perm_name, parent_perm_name, authority)`
    /// in `(owner, perm_name)` order, for the RPC account formatter. Empty when
    /// the requested state is absent.
    pub fn arena_permissions_of(&self, owner: u64) -> Vec<(u64, u64, Authority)> {
        let s = &self.backend;
        s.permissions_of(owner)
            .into_iter()
            .filter_map(|(perm_name, parent_name, blob)| {
                decode_authority(&blob)
                    .ok()
                    .map(|auth| (perm_name, parent_name, auth))
            })
            .collect()
    }

    /// Required permission of the stored permission_link for `(account, code,
    /// message_type)`, or `None` when the link is absent — for
    /// diffing against chainbase's `find_permission_link`.
    pub fn arena_permission_link(&self, account: u64, code: u64, message_type: u64) -> Option<u64> {
        self.backend.permission_link(account, code, message_type)
    }

    /// Stored RAM usage for `account_name`, or `None` when the requested state is absent /
    /// the account is absent — for diffing against chainbase's
    /// `get_account_ram_usage`.
    pub fn arena_account_ram_usage(&self, account_name: u64) -> Option<u64> {
        self.backend.account_ram_usage(account_name)
    }

    /// The block's SHiP chain-state `table_delta` stream, packed over the arena
    /// (nodeos `pack_deltas`). `full_snapshot` emits all live rows; otherwise the
    /// open block undo session's changes. Call before the block commits.
    pub fn pack_deltas(&self, full_snapshot: bool, chain_id: &[u8; 32]) -> Vec<u8> {
        self.backend.pack_deltas(full_snapshot, chain_id)
    }

    /// A contract table's rows as `(primary_key, payer, value)` in primary order,
    /// the read behind the RPC `get_table_rows`. Empty
    pub fn arena_table_range_with_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Vec<(u64, u64, Vec<u8>)> {
        {
            Some(&self.backend)
                .map(|s| s.table_range_with_payer(code, scope, table))
                .unwrap_or_default()
        }
    }

    /// An idx64 table's rows as `(secondary_key, primary_key, payer)`, ordered
    /// by secondary then primary. Empty
    pub fn arena_idx64_range_with_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Vec<(u64, u64, u64)> {
        {
            Some(&self.backend)
                .map(|s| s.idx64_range_with_payer(code, scope, table))
                .unwrap_or_default()
        }
    }

    /// The account's creation-date block-timestamp slot, for the RPC account
    /// formatter's `created` field. `None` when absent.
    pub fn arena_account_creation_date(&self, account_name: u64) -> Option<u32> {
        self.backend.account_creation_date(account_name)
    }

    /// The account's creation time in microseconds since the fc epoch — what the
    /// `get_account_creation_time` intrinsic returns. Errors when the account is
    /// absent, matching the old chainbase `get_account` lookup.
    pub fn account_creation_time_micros(&self, account_name: u64) -> Result<i64, ChainError> {
        self.backend
            .account_creation_date(account_name)
            .map(block_slot_to_micros)
            .ok_or_else(|| ChainError::InternalError(format!("account not found: {account_name}")))
    }

    /// The account's stored ABI bytes (empty if it has none), for decoding the
    /// contract rows the RPC formatters return. `None` when the requested state is absent /
    /// the account is absent.
    pub fn arena_account_abi_bytes(&self, account_name: u64) -> Option<Vec<u8>> {
        self.backend.account_abi_bytes(account_name)
    }

    /// The account's `last_code_update` (fc microseconds), for the RPC account
    /// formatter. `None` when the metadata is absent.
    pub fn arena_account_last_code_update(&self, account_name: u64) -> Option<i64> {
        self.backend.account_last_code_update(account_name)
    }

    /// The arena database's canonical account_metadata serialization, or `None`
    /// byte-compatible with `account_metadata_state_bytes`
    /// so their hashes match iff the tables hold the same state.
    pub fn arena_account_metadata_state_bytes(&self) -> Option<Vec<u8>> {
        Some(self.backend.account_metadata_state_bytes())
    }

    /// The arena database's canonical account_object serialization, or `None` when
    /// the requested state is absent.
    pub fn arena_account_state_bytes(&self) -> Option<Vec<u8>> {
        Some(self.backend.account_state_bytes())
    }

    /// The arena database's canonical permission serialization, or `None` when
    /// the requested state is absent.
    pub fn arena_permission_state_bytes(&self) -> Option<Vec<u8>> {
        Some(self.backend.permission_state_bytes())
    }

    pub fn resource_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        return Ok(Vec::new());
    }

    /// Arena database canonical serializations for the remaining tables, `None`
    /// each byte-compatible with the chainbase method of
    /// the same name for the cross-impl root.
    pub fn arena_permission_link_state_bytes(&self) -> Option<Vec<u8>> {
        Some(self.backend.permission_link_state_bytes())
    }

    pub fn arena_code_state_bytes(&self) -> Option<Vec<u8>> {
        Some(self.backend.code_state_bytes())
    }

    pub fn arena_transaction_state_bytes(&self) -> Option<Vec<u8>> {
        Some(self.backend.transaction_state_bytes())
    }

    pub fn arena_resource_usage_state_bytes(&self) -> Option<Vec<u8>> {
        Some(self.backend.resource_usage_state_bytes())
    }

    pub fn arena_account_limits_state_bytes(&self) -> Option<Vec<u8>> {
        Some(self.backend.account_limits_state_bytes())
    }

    pub fn arena_resource_state_bytes(&self) -> Option<Vec<u8>> {
        Some(self.backend.resource_state_bytes())
    }

    pub fn arena_contract_table_state_bytes(&self) -> Option<Vec<u8>> {
        Some(self.backend.contract_table_state_bytes())
    }

    pub fn arena_contract_kv_state_bytes(&self) -> Option<Vec<u8>> {
        Some(self.backend.contract_kv_state_bytes())
    }

    /// Serve a raw contract-db read from the arena: the value stored at
    /// `(code, scope, table, primary_key)`, or `None` if absent. This is the
    /// primitive behind db_get_i64/db_find_i64 — the read the arena must answer
    /// identically to chainbase to stand in as the primary store.
    pub fn arena_kv_get(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Option<Vec<u8>> {
        self.backend.kv_get(code, scope, table, primary_key)
    }

    /// Serve a contract-table forward scan from the arena: `(primary_key, value)`
    /// for every row in `(code, scope, table)`, ascending by primary — the order
    /// a contract sees walking db_lowerbound_i64 -> db_next_i64. Empty when the
    /// table is absent.
    pub fn arena_table_range(&self, code: u64, scope: u64, table: u64) -> Vec<(u64, Vec<u8>)> {
        {
            Some(&self.backend)
                .map(|s| s.table_range(code, scope, table))
                .unwrap_or_default()
        }
    }

    /// Inline read cross-check: confirm the arena would serve `expected` (the
    /// value the node is handing a contract) for `(code, scope, table, primary)`.
    /// No-op  Tallies match/mismatch; see
    /// `arena_read_crosscheck_counts`.
    /// Arena iterator positioning: the primary a cursor lands on. `lower_bound` =
    /// first primary >= key, `upper_bound` = first primary > key (also the
    /// db_next successor), `prev` = last primary < key. `None` = off the end.
    /// All return `None`
    pub fn arena_kv_lower_bound(&self, code: u64, scope: u64, table: u64, key: u64) -> Option<u64> {
        self.backend.kv_lower_bound(code, scope, table, key)
    }

    pub fn arena_kv_table_exists(&self, code: u64, scope: u64, table: u64) -> bool {
        {
            Some(&self.backend)
                .map(|s| s.kv_table_exists(code, scope, table))
                .unwrap_or(false)
        }
    }

    pub fn arena_kv_upper_bound(&self, code: u64, scope: u64, table: u64, key: u64) -> Option<u64> {
        self.backend.kv_upper_bound(code, scope, table, key)
    }

    pub fn arena_kv_prev(&self, code: u64, scope: u64, table: u64, key: u64) -> Option<u64> {
        self.backend.kv_prev(code, scope, table, key)
    }

    /// Largest primary in the table — db_previous_i64's landing when stepping
    /// back from the end iterator. `None` if empty.
    pub fn arena_kv_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        self.backend.kv_last(code, scope, table)
    }

    /// Arena idx64 secondary-index positioning, updating db_idx64_find_secondary
    /// (primary of the first row with that secondary), db_idx64_lowerbound /
    /// db_idx64_upperbound (`(primary, secondary)` landing), and
    /// db_idx64_find_primary (secondary stored for a primary). All `None` when
    /// the requested state is absent.
    pub fn arena_idx64_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
    ) -> Option<u64> {
        self.backend
            .idx64_find_secondary(code, scope, table, secondary)
    }

    pub fn arena_idx64_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
    ) -> Option<(u64, u64)> {
        self.backend
            .idx64_lower_bound(code, scope, table, secondary)
    }

    pub fn arena_idx64_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
    ) -> Option<(u64, u64)> {
        self.backend
            .idx64_upper_bound(code, scope, table, secondary)
    }

    pub fn arena_idx64_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        self.backend.idx64_find_primary(code, scope, table, primary)
    }

    /// Secondary-order next/previous/last for idx64 iterator-handle minting:
    /// `(primary, secondary)` of the row after/before the one keyed by `primary`,
    /// and the last row of the table (for previous from an end iterator). `None`
    /// when there is no such row.
    pub fn arena_idx64_next(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<(u64, u64)> {
        self.backend.idx64_next(code, scope, table, primary)
    }

    pub fn arena_idx64_previous(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<(u64, u64)> {
        self.backend.idx64_previous(code, scope, table, primary)
    }

    /// Update an idx64 secondary key in the arena.
    pub fn arena_update_index64(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        payer: u64,
        secondary: u64,
    ) {
        let s = &self.backend;
        if let Err(e) = s.update_index64_object(code, scope, table, primary, payer, secondary) {
            eprintln!("arena database of update_index64_object diverged: {e:?}");
        }
    }

    pub fn arena_update_index128(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        payer: u64,
        secondary: u128,
    ) {
        let s = &self.backend;
        if let Err(e) = s.update_index128_object(code, scope, table, primary, payer, secondary) {
            eprintln!("arena database of update_index128_object diverged: {e:?}");
        }
    }

    pub fn arena_update_index256(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        payer: u64,
        secondary: &U256,
    ) {
        let s = &self.backend;
        if let Err(e) =
            s.update_index256_object(code, scope, table, primary, payer, secondary.value)
        {
            eprintln!("arena database of update_index256_object diverged: {e:?}");
        }
    }

    pub fn arena_update_idx_double(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        payer: u64,
        secondary: u64,
    ) {
        let s = &self.backend;
        if let Err(e) = s.update_idx_double_object(code, scope, table, primary, payer, secondary) {
            eprintln!("arena database of update_idx_double_object diverged: {e:?}");
        }
    }

    pub fn arena_update_idx_long_double(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        payer: u64,
        secondary: &Float128,
    ) {
        let s = &self.backend;
        if let Err(e) = s.update_idx_long_double_object(
            code,
            scope,
            table,
            primary,
            payer,
            (secondary.lo, secondary.hi),
        ) {
            eprintln!("arena database of update_idx_long_double_object diverged: {e:?}");
        }
    }

    pub fn arena_idx64_last(&self, code: u64, scope: u64, table: u64) -> Option<(u64, u64)> {
        self.backend.idx64_last(code, scope, table)
    }

    pub fn arena_idx128_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u128,
    ) -> Option<u64> {
        self.backend
            .idx128_find_secondary(code, scope, table, secondary)
    }

    pub fn arena_idx128_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u128> {
        self.backend
            .idx128_find_primary(code, scope, table, primary)
    }

    pub fn arena_idx128_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u128,
    ) -> Option<(u64, u128)> {
        self.backend
            .idx128_lower_bound(code, scope, table, secondary)
    }

    pub fn arena_idx128_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u128,
    ) -> Option<(u64, u128)> {
        self.backend
            .idx128_upper_bound(code, scope, table, secondary)
    }

    // idx_double: the intrinsic carries the float64 as its raw u64 bit pattern;
    // the arena keys on f64, so convert at the boundary (bit-exact both ways).
    pub fn arena_idx_double_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary_bits: u64,
    ) -> Option<u64> {
        {
            self.backend.idx_double_find_secondary(
                code,
                scope,
                table,
                f64::from_bits(secondary_bits),
            )
        }
    }

    pub fn arena_idx_double_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        {
            Some(&self.backend)
                .and_then(|s| s.idx_double_find_primary(code, scope, table, primary))
                .map(|f| f.to_bits())
        }
    }

    pub fn arena_idx_double_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary_bits: u64,
    ) -> Option<(u64, u64)> {
        {
            Some(&self.backend)
                .and_then(|s| {
                    s.idx_double_lower_bound(code, scope, table, f64::from_bits(secondary_bits))
                })
                .map(|(p, f)| (p, f.to_bits()))
        }
    }

    pub fn arena_idx_double_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary_bits: u64,
    ) -> Option<(u64, u64)> {
        {
            Some(&self.backend)
                .and_then(|s| {
                    s.idx_double_upper_bound(code, scope, table, f64::from_bits(secondary_bits))
                })
                .map(|(p, f)| (p, f.to_bits()))
        }
    }

    // idx256: the arena keys on the raw 32-byte value (U256.value).
    pub fn arena_idx256_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: [u8; 32],
    ) -> Option<u64> {
        self.backend
            .idx256_find_secondary(code, scope, table, secondary)
    }

    pub fn arena_idx256_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<[u8; 32]> {
        self.backend
            .idx256_find_primary(code, scope, table, primary)
    }

    pub fn arena_idx256_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: [u8; 32],
    ) -> Option<(u64, [u8; 32])> {
        self.backend
            .idx256_lower_bound(code, scope, table, secondary)
    }

    pub fn arena_idx256_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: [u8; 32],
    ) -> Option<(u64, [u8; 32])> {
        self.backend
            .idx256_upper_bound(code, scope, table, secondary)
    }

    // idx_long_double: the intrinsic carries the float128 as (lo, hi) u64 words.
    pub fn arena_idx_long_double_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: (u64, u64),
    ) -> Option<u64> {
        {
            Some(&self.backend)
                .and_then(|s| s.idx_long_double_find_secondary(code, scope, table, secondary))
        }
    }

    pub fn arena_idx_long_double_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<(u64, u64)> {
        {
            Some(&self.backend)
                .and_then(|s| s.idx_long_double_find_primary(code, scope, table, primary))
        }
    }

    pub fn arena_idx_long_double_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: (u64, u64),
    ) -> Option<(u64, (u64, u64))> {
        {
            Some(&self.backend)
                .and_then(|s| s.idx_long_double_lower_bound(code, scope, table, secondary))
        }
    }

    pub fn arena_idx_long_double_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: (u64, u64),
    ) -> Option<(u64, (u64, u64))> {
        {
            Some(&self.backend)
                .and_then(|s| s.idx_long_double_upper_bound(code, scope, table, secondary))
        }
    }

    /// Secondary-order next/previous/last for iterator-handle minting on the
    /// idx128/256/double/long_double families. `next`/`previous` return the
    /// landing row's primary relative to the row keyed by `primary`; `last`
    /// returns the table's last row (for a `previous` off an end iterator). All
    /// `None` when there is no such row.
    pub fn arena_idx128_next(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        self.backend.idx128_next(code, scope, table, primary)
    }

    pub fn arena_idx128_previous(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        self.backend.idx128_previous(code, scope, table, primary)
    }

    pub fn arena_idx128_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        self.backend.idx128_last(code, scope, table)
    }

    pub fn arena_idx256_next(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        self.backend.idx256_next(code, scope, table, primary)
    }

    pub fn arena_idx256_previous(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        self.backend.idx256_previous(code, scope, table, primary)
    }

    pub fn arena_idx256_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        self.backend.idx256_last(code, scope, table)
    }

    pub fn arena_idx_double_next(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        self.backend.idx_double_next(code, scope, table, primary)
    }

    pub fn arena_idx_double_previous(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        self.backend
            .idx_double_previous(code, scope, table, primary)
    }

    pub fn arena_idx_double_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        self.backend.idx_double_last(code, scope, table)
    }

    pub fn arena_idx_long_double_next(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        self.backend
            .idx_long_double_next(code, scope, table, primary)
    }

    pub fn arena_idx_long_double_previous(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        {
            Some(&self.backend)
                .and_then(|s| s.idx_long_double_previous(code, scope, table, primary))
        }
    }

    pub fn arena_idx_long_double_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        self.backend.idx_long_double_last(code, scope, table)
    }

    /// Persistence round-trip at the database's current (real) state size:
    /// checkpoint the live database to `path`, load it into a fresh, empty database,
    /// and return `(state_roots_match, checkpoint_bytes)`. A `true` means the
    /// arena survived a full save/load with a byte-identical state root — the
    /// durability the primary store needs. Returns `None`
    pub fn arena_persistence_roundtrip(
        &self,
        path: &std::path::Path,
    ) -> Result<Option<(bool, u64)>, ChainError> {
        {
            let cur = &self.backend;
            cur.checkpoint(path)
                .map_err(|e| ChainError::InternalError(format!("arena checkpoint: {e:?}")))?;
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let fresh = crate::backend::ChainDatabase::new()
                .map_err(|e| ChainError::InternalError(format!("arena new: {e:?}")))?;
            fresh
                .load(path)
                .map_err(|e| ChainError::InternalError(format!("arena load: {e:?}")))?;
            Ok(Some((cur.state_root() == fresh.state_root(), size)))
        }
    }

    /// Append the database's committed delta since the last flush to the WAL at
    /// `path`. Call once per accepted block for incremental durability. No-op
    pub fn arena_flush_delta(&self, path: &std::path::Path) -> Result<(), ChainError> {
        {
            {
                let s = &self.backend;
                s.flush_delta(path)
                    .map_err(|e| ChainError::InternalError(format!("arena flush_delta: {e:?}")))?;
            }
        }
        Ok(())
    }

    /// Reconstruct a fresh database by replaying the WAL at `path` (no base
    /// checkpoint), and return whether its state root matches the live database —
    /// the crash-recovery guarantee for the incremental path. `None` when
    /// the requested state is absent.
    pub fn arena_wal_reload_matches(
        &self,
        path: &std::path::Path,
    ) -> Result<Option<bool>, ChainError> {
        {
            let cur = &self.backend;
            let fresh = crate::backend::ChainDatabase::new()
                .map_err(|e| ChainError::InternalError(format!("arena new: {e:?}")))?;
            fresh
                .replay_log(path)
                .map_err(|e| ChainError::InternalError(format!("arena replay_log: {e:?}")))?;
            Ok(Some(cur.state_root() == fresh.state_root()))
        }
    }

    /// Simulate a node restart: checkpoint the live database to `path`, then
    /// rebuild it in place from that checkpoint. After this the backend holds
    /// reloaded-from-disk state (same object, restored revision) and keeps
    /// serving — so the caller can carry on applying blocks and confirm the
    /// database stays in lockstep with chainbase across the restart. `Ok(false)`
    pub fn arena_restart(&self, path: &std::path::Path) -> Result<bool, ChainError> {
        {
            let cur = &self.backend;
            cur.checkpoint(path)
                .map_err(|e| ChainError::InternalError(format!("arena checkpoint: {e:?}")))?;
            cur.reload_from(path)
                .map_err(|e| ChainError::InternalError(format!("arena reload: {e:?}")))?;
            Ok(true)
        }
    }

    /// Whether the arena database holds an account_object for `name` — for diffing
    /// against chainbase's `find_account`.
    pub fn arena_account_exists(&self, name: u64) -> bool {
        {
            Some(&self.backend)
                .map(|s| s.account_exists(name))
                .unwrap_or(false)
        }
    }

    /// State root of the stored database.
    pub fn arena_state_root(&self) -> Option<[u8; 32]> {
        Some(self.backend.state_root())
    }

    /// Arena undo-session lifecycle, driven by the controller's block boundaries.
    pub fn arena_start_undo_session(&self) {
        self.backend.start_undo_session();
    }
    pub fn arena_squash(&self) {
        self.backend.squash();
    }
    pub fn arena_undo(&self) {
        self.backend.undo();
    }

    /// The arena lives in memory behind an `Arc`, so there is nothing to close;
    /// dropping the last handle releases it. Retained for the controller's
    /// restart sequence.
    pub fn close(&self) -> Result<(), ChainError> {
        // Persist the committed arena to disk so the next open reloads it, matching
        // chainbase's mapped `shared_memory.bin`. The directory may not exist yet
        // for a never-opened default database, so create it first.
        if self.path.is_empty() {
            return Ok(());
        }
        let dir = Path::new(&self.path);
        fs::create_dir_all(dir)
            .map_err(|e| ChainError::InternalError(format!("close: create {}: {e}", self.path)))?;
        self.backend
            .checkpoint(&dir.join(ARENA_STATE_FILE))
            .map_err(|e| ChainError::InternalError(format!("close: checkpoint: {e:?}")))
    }

    /// Capture a snapshot of the committed arena state, wrapped in the transport
    /// envelope (see `snapshot`).
    ///
    /// The arena is checkpointed to a staging file and read back through the same
    /// sparse envelope the transport uses, so the on-wire format is unchanged.
    /// Call this only at a quiescent point (no open undo session): the checkpoint
    /// reflects whatever is committed to the arena at that instant.
    pub fn snapshot_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let revision = self.backend.revision();
        let file = Path::new(&self.path).join(SHARED_MEMORY_FILE);
        self.backend
            .checkpoint(&file)
            .map_err(|e| ChainError::InternalError(format!("snapshot: checkpoint: {e:?}")))?;
        let snapshot = Self::read_sparse_snapshot(&file, revision);
        let _ = fs::remove_file(&file);
        snapshot
    }

    /// Read `shared_memory.bin` into a sparse, envelope-wrapped snapshot without
    /// ever holding the whole (mostly-zero) file in memory. Fixed-size,
    /// block-aligned chunks keep the run boundaries deterministic, so re-reading
    /// an unchanged file yields byte-identical output.
    fn read_sparse_snapshot(file: &Path, revision: i64) -> Result<Vec<u8>, ChainError> {
        let mut f = fs::File::open(file).map_err(|e| {
            ChainError::InternalError(format!("snapshot: open {}: {e}", file.display()))
        })?;
        let len = f
            .metadata()
            .map_err(|e| ChainError::InternalError(format!("snapshot: stat: {e}")))?
            .len();

        let mut payload = crate::snapshot::sparse_begin(len);
        // A multiple of SPARSE_BLOCK, so every full chunk starts block-aligned.
        let mut buf = vec![0u8; 4 * 1024 * 1024];
        let mut offset = 0u64;
        loop {
            let n = fill(&mut f, &mut buf)
                .map_err(|e| ChainError::InternalError(format!("snapshot: read: {e}")))?;
            if n == 0 {
                break;
            }
            crate::snapshot::sparse_append(&mut payload, offset, &buf[..n]);
            offset += n as u64;
        }
        Ok(crate::snapshot::encode(revision, &payload))
    }

    /// Expand a validated sparse payload into `file`: write each run at its
    /// offset over a freshly-truncated file, then extend to the logical length so
    /// the unwritten remainder stays a (zeroed) hole.
    fn write_sparse_snapshot(file: &Path, payload: &[u8]) -> Result<(), ChainError> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file)
            .map_err(|e| {
                ChainError::InternalError(format!("restore: create {}: {e}", file.display()))
            })?;
        let logical_len = crate::snapshot::sparse_expand(payload, |off, data| {
            f.seek(SeekFrom::Start(off))?;
            f.write_all(data)
        })?;
        f.set_len(logical_len).map_err(|e| {
            ChainError::InternalError(format!("restore: size {}: {e}", file.display()))
        })?;
        f.sync_all().map_err(|e| {
            ChainError::InternalError(format!("restore: sync {}: {e}", file.display()))
        })?;
        Ok(())
    }

    /// Replace the live arena with the state carried in `snapshot`, in place.
    ///
    /// This is the accept side of state sync, where the database is already
    /// open. The envelope is validated and the payload staged to a sibling file
    /// while the current mapping is still up, so a bad snapshot never disturbs
    /// the running database. Only then is the write lock taken to drop the
    /// mapping, swap the file in atomically, and remap — the same
    /// lock-held-across-the-whole-window discipline as `snapshot_bytes`, and it
    /// always remaps so a failure never leaves the database closed.
    pub fn restore_from_bytes(
        &self,
        snapshot: &[u8],
    ) -> Result<crate::snapshot::SnapshotHeader, ChainError> {
        // Validate and locate the payload before touching the running arena.
        let (header, payload) = crate::snapshot::decode(snapshot)?;

        // Land the checkpoint at the persistent state path and rebuild the live
        // arena from it, so the restored state is durable across a restart without
        // waiting for a clean close.
        let dir = Path::new(&self.path);
        fs::create_dir_all(dir).map_err(|e| {
            ChainError::InternalError(format!("restore: create {}: {e}", self.path))
        })?;
        let dest = dir.join(ARENA_STATE_FILE);
        let staged = Self::stage_snapshot(dir, header, payload)?;
        staged.persist(&dest).map_err(|e| {
            ChainError::InternalError(format!("restore: install {}: {}", dest.display(), e.error))
        })?;
        self.backend
            .reload_from(&dest)
            .map_err(|e| ChainError::InternalError(format!("restore: reload: {e:?}")))?;
        Ok(header)
    }

    /// Expand and fully load a snapshot checkpoint before it is allowed to
    /// replace durable state. Loading catches malformed arena sections and the
    /// revision comparison prevents an envelope from claiming a different
    /// accepted height than the state it actually carries.
    fn stage_snapshot(
        dir: &Path,
        header: crate::snapshot::SnapshotHeader,
        payload: &[u8],
    ) -> Result<tempfile::NamedTempFile, ChainError> {
        let staged = tempfile::NamedTempFile::new_in(dir)
            .map_err(|e| ChainError::InternalError(format!("restore: stage: {e}")))?;
        Self::write_sparse_snapshot(staged.path(), payload)?;

        let candidate = crate::backend::ChainDatabase::new()
            .map_err(|e| ChainError::InternalError(format!("restore: arena init: {e:?}")))?;
        candidate
            .load(staged.path())
            .map_err(|e| ChainError::InternalError(format!("restore: invalid arena: {e:?}")))?;
        if candidate.revision() != header.revision {
            return Err(ChainError::InternalError(format!(
                "snapshot payload revision {} does not match envelope revision {}",
                candidate.revision(),
                header.revision
            )));
        }
        Ok(staged)
    }

    pub fn commit(&mut self, revision: i64) -> Result<(), ChainError> {
        self.backend.commit(revision);
        Ok(())
    }

    pub fn undo(&mut self) -> Result<(), ChainError> {
        self.backend.undo();
        Ok(())
    }

    pub fn revision(&self) -> i64 {
        self.backend.revision()
    }

    pub fn set_revision(&mut self, revision: i64) -> Result<(), ChainError> {
        self.backend
            .set_revision(revision)
            .map_err(|e| ChainError::InternalError(format!("arena set_revision: {e:?}")))
    }

    /// The arena registers its index set at construction, so this is a no-op.
    pub fn add_indices(&mut self) -> Result<(), ChainError> {
        Ok(())
    }

    pub fn initialize_database(
        &mut self,
        genesis: &pulsevm_chain_types::GenesisState,
    ) -> Result<(), ChainError> {
        // Genesis is authored directly on the arena, reproducing C++
        // `initialize_database` without a chainbase bootstrap.
        self.initialize_genesis_arena(genesis)
    }

    /// Author the entire genesis state directly on the arena, reproducing C++
    /// `initialize_database` (database.cpp) without a chainbase bootstrap. Every
    /// value is derived from the genesis state or from the fixed genesis
    /// constants, and the whole thing is pinned by the block-1 golden roots.
    fn initialize_genesis_arena(
        &self,
        genesis: &pulsevm_chain_types::GenesisState,
    ) -> Result<(), ChainError> {
        use crate::backend::ElasticParams;

        let s = self.backend_ref()?;

        // Genesis timestamp: micros since the fc epoch (1970) for permission
        // last_updated/last_used, and the block_timestamp slot for account
        // creation_date (config::block_timestamp_epoch = 946684800000ms, 500ms
        // slots).
        let ts_us: i64 = genesis.initial_timestamp_micros;
        let creation_slot: u32 = (((ts_us / 1000) - 946_684_800_000i64) / 500i64).max(0) as u32;

        // Genesis account / permission names (config.hpp), as name-encoded u64.
        const PULSE: u64 = 12_584_048_018_849_792_000;
        const PULSE_NULL: u64 = 12_584_048_029_495_738_368;
        const PULSE_PRODS: u64 = 12_584_048_030_520_602_624;
        const OWNER: u64 = 12_044_502_819_693_133_824;
        const ACTIVE: u64 = 3_617_214_756_542_218_240;
        const PROD_MAJOR: u64 = 12_531_424_605_554_196_480;
        const PROD_MINOR: u64 = 12_531_424_609_916_272_640;

        // 1. global_property (chain_config from the genesis configuration).
        s.set_global_properties(chain_config_params_from_v0(&genesis.initial_configuration))
            .map_err(|e| ChainError::InternalError(format!("genesis global_property: {e:?}")))?;

        // 2. resource_limits_config — the C++ struct defaults (config.hpp): target =
        //    EOS_PERCENT(max, 10%), periods = 60_000ms/500ms = 120, max_multiplier 1000, contract
        //    99/100, expand 1000/999; windows = 24h/500ms = 172_800.
        let cpu = ElasticParams {
            target: 200_000,
            max: 2_000_000,
            periods: 120,
            max_multiplier: 1000,
            contract: (99, 100),
            expand: (1000, 999),
        };
        let net = ElasticParams {
            target: 104_857,
            max: 1_048_576,
            periods: 120,
            max_multiplier: 1000,
            contract: (99, 100),
            expand: (1000, 999),
        };
        s.seed_resource_config(cpu, net, 172_800, 172_800)
            .map_err(|e| ChainError::InternalError(format!("genesis resource_config: {e:?}")))?;

        // 3. resource_limits_state: virtual limits seeded to each resource's max (slow-start).
        s.initialize_resource_state(2_000_000, 1_048_576)
            .map_err(|e| ChainError::InternalError(format!("genesis resource_state: {e:?}")))?;

        // 4. native accounts. system_auth carries the genesis key; the producers' active authority
        //    delegates to pulse/active.
        let key_bytes = genesis.initial_key_packed().to_vec();
        let system_auth = build_auth_blob(1, &[(key_bytes, 1)], &[], &[]);
        let empty_auth = build_auth_blob(1, &[], &[], &[]);
        let active_producers_auth = build_auth_blob(1, &[], &[(PULSE, ACTIVE, 1)], &[]);

        self.genesis_native_account(
            PULSE,
            &system_auth,
            &system_auth,
            true,
            creation_slot,
            ts_us,
            Some(pulsevm_chaindb::GENESIS_PULSE_ABI),
            OWNER,
            ACTIVE,
        )?;
        self.genesis_native_account(
            PULSE_NULL,
            &empty_auth,
            &empty_auth,
            false,
            creation_slot,
            ts_us,
            None,
            OWNER,
            ACTIVE,
        )?;
        // The producers account's active permission is the parent of prod.major.
        let prods_active_id = self.genesis_native_account(
            PULSE_PRODS,
            &empty_auth,
            &active_producers_auth,
            false,
            creation_slot,
            ts_us,
            None,
            OWNER,
            ACTIVE,
        )?;

        // 5. prod.major (parent = producers active) then prod.minor (parent = prod.major), both
        //    carrying the active-producers authority.
        let major_id = self.genesis_permission(
            PULSE_PRODS,
            PROD_MAJOR,
            prods_active_id,
            &active_producers_auth,
            ts_us,
        )?;
        self.genesis_permission(
            PULSE_PRODS,
            PROD_MINOR,
            major_id,
            &active_producers_auth,
            ts_us,
        )?;

        Ok(())
    }

    /// Create one genesis permission in the arena (owner-authored cb_id from the
    /// replicated counter), returning its cb_id for parent links.
    fn genesis_permission(
        &self,
        owner: u64,
        perm_name: u64,
        parent_cb_id: i64,
        auth_blob: &[u8],
        ts_us: i64,
    ) -> Result<i64, ChainError> {
        let s = self.backend_ref()?;
        let cb_id = s
            .next_permission_id()
            .map_err(|e| ChainError::InternalError(format!("genesis next_permission_id: {e:?}")))?;
        s.create_permission(cb_id, parent_cb_id, owner, perm_name, ts_us, auth_blob)
            .map_err(|e| ChainError::InternalError(format!("genesis create_permission: {e:?}")))?;
        Ok(cb_id)
    }

    /// Reproduce C++ `create_native_account`: account + metadata + owner/active
    /// permissions + resource-limit init + the fixed genesis RAM billing.
    /// Returns the active permission's cb_id.
    fn genesis_native_account(
        &self,
        name: u64,
        owner_auth: &[u8],
        active_auth: &[u8],
        privileged: bool,
        creation_slot: u32,
        ts_us: i64,
        abi: Option<&[u8]>,
        owner_name: u64,
        active_name: u64,
    ) -> Result<i64, ChainError> {
        let s = self.backend_ref()?;
        s.create_account(name, creation_slot)
            .map_err(|e| ChainError::InternalError(format!("genesis create_account: {e:?}")))?;
        if let Some(abi) = abi {
            s.set_account_abi_raw(name, abi)
                .map_err(|e| ChainError::InternalError(format!("genesis set abi: {e:?}")))?;
        }
        s.create_account_metadata(name, privileged)
            .map_err(|e| ChainError::InternalError(format!("genesis metadata: {e:?}")))?;

        let _owner_id = self.genesis_permission(name, owner_name, 0, owner_auth, ts_us)?;
        let active_id =
            self.genesis_permission(name, active_name, _owner_id, active_auth, ts_us)?;

        s.initialize_account_resource_limits(name)
            .map_err(|e| ChainError::InternalError(format!("genesis init limits: {e:?}")))?;

        // ram_delta = overhead_per_account_ram_bytes (2048) +
        //   2 * billable_size_v<permission_object> + owner+active auth billable.
        let ram_delta = 2048i64
            + 2 * billable_size_v::<PermissionObject>() as i64
            + authority_blob_billable_size(owner_auth).ok_or_else(|| {
                ChainError::InternalError("invalid genesis owner authority encoding".into())
            })?
            + authority_blob_billable_size(active_auth).ok_or_else(|| {
                ChainError::InternalError("invalid genesis active authority encoding".into())
            })?;
        s.add_pending_ram_usage(name, ram_delta)
            .map_err(|e| ChainError::InternalError(format!("genesis ram: {e:?}")))?;
        // Genesis RAM usage is checked through the normal database path.
        Ok(active_id)
    }

    pub fn create_account(
        &mut self,
        account_name: u64,
        creation_date: u32,
    ) -> Result<(), ChainError> {
        self.backend
            .create_account(account_name, creation_date)
            .map_err(|e| {
                ChainError::InternalError(format!("arena create_account {account_name}: {e:?}"))
            })
    }

    pub fn create_account_metadata(
        &mut self,
        account_name: u64,
        is_privileged: bool,
    ) -> Result<(), ChainError> {
        self.backend
            .create_account_metadata(account_name, is_privileged)
            .map_err(|e| ChainError::InternalError(format!("arena create_account_metadata: {e:?}")))
    }

    pub fn set_privileged(&mut self, account: u64, is_privileged: bool) -> Result<(), ChainError> {
        let s = &self.backend;
        return s.set_privileged(account, is_privileged).map_err(|e| {
            ChainError::InternalError(format!("arena set_privileged {account}: {e:?}"))
        });
    }

    /// Decrement the code_object refcount for `(code_hash, vm_type, vm_version)`.
    /// Takes the hash and vm fields, not a chainbase `&CodeObject`: the object is
    /// re-found and unlinked inside the write scope, so setcode no longer holds a
    /// database reference across the update that follows.
    pub fn unlink_account_code(
        &mut self,
        code_hash: &[u8; 32],
        _vm_type: u8,
        _vm_version: u8,
    ) -> Result<(), ChainError> {
        self.backend
            .unlink_account_code(*code_hash)
            .map_err(|e| ChainError::InternalError(format!("arena unlink_account_code: {e:?}")))
    }

    /// Set (or clear) an account's contract code. Takes the account *name*, not a
    /// chainbase `&AccountMetadataObject`: the metadata object is re-found and
    /// mutated entirely inside the write scope, so no database-owned reference
    /// escapes to the caller (setcode used to hold one across validation).
    pub fn update_account_code(
        &mut self,
        account_name: u64,
        new_code: &[u8],
        head_block_num: u32,
        pending_block_time: &TimePoint,
        code_hash: &[u8; 32],
        vm_type: u8,
        vm_version: u8,
    ) -> Result<(), ChainError> {
        self.backend
            .update_account_code(
                account_name,
                new_code,
                *code_hash,
                head_block_num,
                pending_block_time.time_since_epoch().count(),
                vm_type,
                vm_version,
            )
            .map_err(|e| ChainError::InternalError(format!("arena update_account_code: {e:?}")))
    }

    /// Replace an account's ABI. Takes the account *name*; both the account and
    /// account_metadata objects are resolved inside the write scope.
    pub fn update_account_abi(&mut self, account_name: u64, abi: &[u8]) -> Result<(), ChainError> {
        let s = &self.backend;
        return s
            .update_account_abi(account_name, abi)
            .map_err(|e| ChainError::InternalError(format!("arena update_account_abi: {e:?}")));
    }

    pub fn initialize_account_resource_limits(
        &mut self,
        account_name: u64,
    ) -> Result<(), ChainError> {
        let s = &self.backend;
        return s
            .initialize_account_resource_limits(account_name)
            .map_err(|e| {
                ChainError::InternalError(format!(
                    "arena initialize_account_resource_limits: {e:?}"
                ))
            });
    }

    pub fn update_account_usage(
        &mut self,
        account: &Name,
        time_slot: u32,
    ) -> Result<(), ChainError> {
        self.account_usage(account.as_u64(), 0, 0, time_slot, false)
    }

    pub fn add_transaction_usage(
        &mut self,
        account: &Name,
        cpu_usage: u64,
        net_usage: u64,
        time_slot: u32,
        validate: bool,
    ) -> Result<(), ChainError> {
        self.account_usage(account.as_u64(), cpu_usage, net_usage, time_slot, validate)
    }

    /// Advance an account's net/cpu usage accumulators, decaying over the average
    /// windows read from chain config. When `validate` is true, reject usage that
    /// exceeds the account's remaining elastic allowance before mutating state.
    /// Every database error is propagated so accounting can never fail open.
    fn account_usage(
        &self,
        account: u64,
        cpu_usage: u64,
        net_usage: u64,
        time_slot: u32,
        validate: bool,
    ) -> Result<(), ChainError> {
        const MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER: u32 = 1000;

        let (net_window, cpu_window) =
            self.get_account_net_usage_average_window().and_then(|nw| {
                self.get_account_cpu_usage_average_window()
                    .map(|cw| (nw, cw))
            })?;

        let s = &self.backend;
        if validate {
            let (net_available, _) = s
                .account_net_limit(account, MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER)
                .ok_or_else(|| {
                    ChainError::InternalError(format!(
                        "resource state not found while billing account {account}"
                    ))
                })?;
            if net_available >= 0 && net_usage > net_available as u64 {
                return Err(ChainError::TransactionError(format!(
                    "transaction net usage is too high: {net_usage} > {net_available}"
                )));
            }

            let (cpu_available, _) = s
                .account_cpu_limit(account, MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER)
                .ok_or_else(|| {
                    ChainError::InternalError(format!(
                        "resource state not found while billing account {account}"
                    ))
                })?;
            if cpu_available >= 0 && cpu_usage > cpu_available as u64 {
                return Err(ChainError::TransactionError(format!(
                    "transaction CPU usage is too high: {cpu_usage} > {cpu_available}"
                )));
            }

            let (block_cpu_available, block_net_available) = s.block_limits().ok_or_else(|| {
                ChainError::InternalError(format!(
                    "resource state not found while billing account {account}"
                ))
            })?;
            if cpu_usage > block_cpu_available {
                return Err(ChainError::TransactionError(format!(
                    "block has insufficient CPU resources: {cpu_usage} > {block_cpu_available}"
                )));
            }
            if net_usage > block_net_available {
                return Err(ChainError::TransactionError(format!(
                    "block has insufficient NET resources: {net_usage} > {block_net_available}"
                )));
            }
        }

        s.add_transaction_usage(
            account, cpu_usage, net_usage, time_slot, net_window, cpu_window,
        )
        .map_err(|e| ChainError::InternalError(format!("arena add_transaction_usage: {e:?}")))?;
        s.add_block_usage(cpu_usage, net_usage)
            .map_err(|e| ChainError::InternalError(format!("arena add_block_usage: {e:?}")))?;
        Ok(())
    }

    pub fn add_pending_ram_usage(
        &mut self,
        account_name: u64,
        ram_bytes: i64,
    ) -> Result<(), ChainError> {
        let s = &self.backend;
        return s
            .add_pending_ram_usage(account_name, ram_bytes)
            .map_err(|e| ChainError::InternalError(format!("arena add_pending_ram_usage: {e:?}")));
    }

    pub fn verify_account_ram_usage(&mut self, account_name: u64) -> Result<(), ChainError> {
        // Reproduce chainbase's resource_limits check: an account whose RAM quota
        // is set (>= 0) may not use more than it. A negative quota is unlimited.
        let ram_bytes = self
            .backend
            .account_limits(account_name)
            .map(|(r, _, _)| r)
            .ok_or_else(|| {
                ChainError::InternalError(format!(
                    "resource limits not found for account: {}",
                    Name::new(account_name)
                ))
            })?;
        let raw_ram_usage = self
            .backend
            .account_ram_usage(account_name)
            .ok_or_else(|| {
                ChainError::InternalError(format!(
                    "resource usage not found for account: {}",
                    Name::new(account_name)
                ))
            })?;
        let ram_usage = i64::try_from(raw_ram_usage).map_err(|_| {
            ChainError::InternalError(format!(
                "RAM usage for account {} exceeds the supported range: {}",
                Name::new(account_name),
                raw_ram_usage
            ))
        })?;
        if ram_bytes >= 0 && ram_usage > ram_bytes {
            return Err(ChainError::InternalError(format!(
                "account {} has insufficient ram; needs {} bytes has {} bytes",
                Name::new(account_name),
                ram_usage,
                ram_bytes
            )));
        }
        Ok(())
    }

    pub fn get_account_ram_usage(&self, account_name: u64) -> Result<i64, ChainError> {
        self.backend
            .account_ram_usage(account_name)
            .map(|u| u as i64)
            .ok_or_else(|| {
                ChainError::InternalError(format!("resource usage not found: {account_name}"))
            })
    }

    pub fn get_account_net_usage_average_window(&self) -> Result<u32, ChainError> {
        let s = &self.backend;
        return s
            .usage_average_windows()
            .map(|(net, _cpu)| net)
            .ok_or_else(|| ChainError::InternalError("resource config not found".into()));
    }

    pub fn get_account_cpu_usage_average_window(&self) -> Result<u32, ChainError> {
        let s = &self.backend;
        return s
            .usage_average_windows()
            .map(|(_net, cpu)| cpu)
            .ok_or_else(|| ChainError::InternalError("resource config not found".into()));
    }

    /// Stored net/cpu usage `value_ex` for `account_name`, or `None` when
    /// the account is absent — for diffing against chainbase.
    pub fn arena_account_net_usage_value_ex(&self, account_name: u64) -> Option<u64> {
        self.backend.account_net_usage_value_ex(account_name)
    }

    pub fn arena_account_cpu_usage_value_ex(&self, account_name: u64) -> Option<u64> {
        self.backend.account_cpu_usage_value_ex(account_name)
    }

    pub fn get_cpu_limit_parameters(&self) -> Result<ElasticLimitParameters, ChainError> {
        let s = &self.backend;
        return s
            .resource_config_elastic()
            .map(|(cpu, _net)| from_elastic_params(&cpu))
            .ok_or_else(|| ChainError::InternalError("resource config not found".into()));
    }

    pub fn get_net_limit_parameters(&self) -> Result<ElasticLimitParameters, ChainError> {
        let s = &self.backend;
        return s
            .resource_config_elastic()
            .map(|(_cpu, net)| from_elastic_params(&net))
            .ok_or_else(|| ChainError::InternalError("resource config not found".into()));
    }

    /// Stored `(virtual_cpu_limit, virtual_net_limit)`, or `None` when
    /// the state row is absent — for diffing against
    /// chainbase's `get_virtual_cpu_limit`/`get_virtual_net_limit`.
    pub fn arena_virtual_limits(&self) -> Option<(u64, u64)> {
        self.backend.state_virtual_limits()
    }

    pub fn set_account_limits(
        &mut self,
        account_name: u64,
        ram_bytes: i64,
        net_weight: i64,
        cpu_weight: i64,
    ) -> Result<bool, ChainError> {
        let s = &self.backend;
        // Compute the "ram limit decreased" flag from the pre-write limit, as
        // chainbase does, before applying the arena write.
        let old_ram = s
            .account_limits(account_name)
            .map(|(r, _, _)| r)
            .unwrap_or(-1);
        s.set_account_limits(account_name, ram_bytes, net_weight, cpu_weight)
            .map_err(|e| ChainError::InternalError(format!("arena set_account_limits: {e:?}")))?;
        let decreased = ram_bytes >= 0 && (old_ram < 0 || ram_bytes < old_ram);
        return Ok(decreased);
    }

    pub fn get_account_limits(
        &self,
        account_name: u64,
        ram_bytes: &mut i64,
        net_weight: &mut i64,
        cpu_weight: &mut i64,
    ) -> Result<(), ChainError> {
        let s = &self.backend;
        let (r, n, c) = s.account_limits(account_name).ok_or_else(|| {
            ChainError::InternalError(format!("resource limits not found: {account_name}"))
        })?;
        *ram_bytes = r;
        *net_weight = n;
        *cpu_weight = c;
        return Ok(());
    }

    pub fn get_total_cpu_weight(&self) -> Result<u64, ChainError> {
        let s = &self.backend;
        return s
            .state_total_weights()
            .map(|(cpu, _net)| cpu)
            .ok_or_else(|| ChainError::InternalError("resource state not found".into()));
    }

    pub fn get_total_net_weight(&self) -> Result<u64, ChainError> {
        let s = &self.backend;
        return s
            .state_total_weights()
            .map(|(_cpu, net)| net)
            .ok_or_else(|| ChainError::InternalError("resource state not found".into()));
    }

    pub fn get_account_net_limit(
        &self,
        name: u64,
        greylist_limit: u32,
    ) -> Result<NetLimitResult, ChainError> {
        let s = &self.backend;
        let (limit, greylisted) = s.account_net_limit(name, greylist_limit).ok_or_else(|| {
            ChainError::InternalError(format!("resource state not found for {name}"))
        })?;
        return Ok(NetLimitResult { limit, greylisted });
    }

    pub fn get_account_cpu_limit(
        &self,
        name: u64,
        greylist_limit: u32,
    ) -> Result<CpuLimitResult, ChainError> {
        let s = &self.backend;
        let (limit, greylisted) = s.account_cpu_limit(name, greylist_limit).ok_or_else(|| {
            ChainError::InternalError(format!("resource state not found for {name}"))
        })?;
        return Ok(CpuLimitResult { limit, greylisted });
    }

    pub fn process_account_limit_updates(&mut self) -> Result<(), ChainError> {
        let s = &self.backend;
        return s.process_account_limit_updates().map_err(|e| {
            ChainError::InternalError(format!("arena process_account_limit_updates: {e:?}"))
        });
    }

    /// Stored effective limits `(ram_bytes, net_weight, cpu_weight)` for
    /// `account_name`, or `None` when the account is absent —
    /// for diffing against chainbase's `get_account_limits`.
    pub fn arena_account_limits(&self, account_name: u64) -> Option<(i64, i64, i64)> {
        self.backend.account_limits(account_name)
    }

    pub fn set_block_parameters(
        &mut self,
        cpu_limit_parameters: &ElasticLimitParameters,
        net_limit_parameters: &ElasticLimitParameters,
    ) -> Result<(), ChainError> {
        let s = &self.backend;
        return s
            .set_block_parameters(
                to_elastic_params(cpu_limit_parameters),
                to_elastic_params(net_limit_parameters),
            )
            .map_err(|e| ChainError::InternalError(format!("arena set_block_parameters: {e:?}")));
    }

    /// Arena database of resource_limits_config, `None`
    pub fn arena_resource_config_state_bytes(&self) -> Option<Vec<u8>> {
        Some(self.backend.resource_config_state_bytes())
    }

    pub fn process_block_usage(&mut self, block_num: u32) -> Result<(), ChainError> {
        let s = &self.backend;
        let (cpu, net) = s.resource_config_elastic().ok_or_else(|| {
            ChainError::InternalError("resource config not found for block usage".into())
        })?;
        return s
            .process_block_usage(block_num, cpu, net)
            .map_err(|e| ChainError::InternalError(format!("arena process_block_usage: {e:?}")));
    }

    /// Whether the contract table exists in the arena. Standalone-writes db_store
    /// bills table-creation RAM only on the first row, so it decides existence
    /// against the arena rather than dereferencing a chainbase table pointer.
    pub fn arena_table_exists(&self, code: u64, scope: u64, table: u64) -> bool {
        {
            Some(&self.backend)
                .map(|s| s.table_exists(code, scope, table))
                .unwrap_or(false)
        }
    }

    /// The payer to credit the table_id_object overhead when a table's last child
    /// is removed, or `None` if the table is absent.
    pub fn arena_table_payer(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        self.backend.table_payer(code, scope, table)
    }

    /// The `(payer, value)` of a contract row from the arena, or `None`.
    /// db_update/db_remove need the old payer and value size to bill RAM.
    pub fn arena_kv_row(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Option<(u64, Vec<u8>)> {
        self.backend.kv_row(code, scope, table, primary_key)
    }

    /// Author a contract row in the arena alone (no chainbase). The arena's
    /// create is find-or-create on the table, so it also creates the table if
    /// absent, updating `create_key_value_object` + the implicit table create.
    pub fn create_key_value_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        buffer: &[u8],
    ) -> Result<(), ChainError> {
        let s = &self.backend;
        s.create_key_value_object(code, scope, table, payer, primary_key, buffer)
            .map_err(|e| ChainError::InternalError(format!("arena create_key_value_object: {e:?}")))
    }

    /// Rewrite a contract row's value and payer in the arena alone (no chainbase).
    pub fn update_key_value_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        buffer: &[u8],
    ) -> Result<(), ChainError> {
        let s = &self.backend;
        s.update_key_value_object(code, scope, table, primary_key, payer, buffer)
            .map_err(|e| ChainError::InternalError(format!("arena update_key_value_object: {e:?}")))
    }

    /// Remove a contract row in the arena alone (no chainbase). The arena drops
    /// the row and auto-removes the table when it empties, matching chainbase.
    pub fn remove_key_value_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), ChainError> {
        let s = &self.backend;
        s.remove_key_value_object(code, scope, table, primary_key)
            .map_err(|e| ChainError::InternalError(format!("arena remove_key_value_object: {e:?}")))
    }

    // ----- secondary-index writes -------------------------------------------
    // These match create/update/remove_indexN_object but touch only the arena,
    // taking the row's `(code, scope, table, primary)` scalars instead of a
    // chainbase `&IndexNObject` pointer. The secondary key is converted to the
    // arena's stored form exactly as the former bridge paths do. `arena_idxN_
    // payer` serves the old payer db_idxN_update needs for its billing delta.

    fn backend_ref(&self) -> Result<&crate::backend::ChainDatabase, ChainError> {
        Ok(&self.backend)
    }

    pub fn create_index64_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .create_index64_object(code, scope, table, payer, primary_key, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("arena create_index64: {e:?}")))
    }

    pub fn update_index64_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .update_index64_object(code, scope, table, primary_key, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("arena update_index64: {e:?}")))
    }

    pub fn remove_index64_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .remove_index64_object(code, scope, table, primary_key)
            .map_err(|e| ChainError::InternalError(format!("arena remove_index64: {e:?}")))
    }

    pub fn arena_idx64_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        Some(&self.backend).and_then(|s| s.idx64_payer(code, scope, table, primary))
    }

    pub fn create_index128_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: u128,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .create_index128_object(code, scope, table, payer, primary_key, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("arena create_index128: {e:?}")))
    }

    pub fn update_index128_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: u128,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .update_index128_object(code, scope, table, primary_key, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("arena update_index128: {e:?}")))
    }

    pub fn remove_index128_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .remove_index128_object(code, scope, table, primary_key)
            .map_err(|e| ChainError::InternalError(format!("arena remove_index128: {e:?}")))
    }

    pub fn arena_idx128_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        Some(&self.backend).and_then(|s| s.idx128_payer(code, scope, table, primary))
    }

    pub fn create_index256_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: U256,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .create_index256_object(code, scope, table, payer, primary_key, secondary_key.value)
            .map_err(|e| ChainError::InternalError(format!("arena create_index256: {e:?}")))
    }

    pub fn update_index256_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: U256,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .update_index256_object(code, scope, table, primary_key, payer, secondary_key.value)
            .map_err(|e| ChainError::InternalError(format!("arena update_index256: {e:?}")))
    }

    pub fn remove_index256_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .remove_index256_object(code, scope, table, primary_key)
            .map_err(|e| ChainError::InternalError(format!("arena remove_index256: {e:?}")))
    }

    pub fn arena_idx256_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        Some(&self.backend).and_then(|s| s.idx256_payer(code, scope, table, primary))
    }

    pub fn create_idx_double_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .create_idx_double_object(code, scope, table, payer, primary_key, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("arena create_idx_double: {e:?}")))
    }

    pub fn update_idx_double_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .update_idx_double_object(code, scope, table, primary_key, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("arena update_idx_double: {e:?}")))
    }

    pub fn remove_idx_double_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .remove_idx_double_object(code, scope, table, primary_key)
            .map_err(|e| ChainError::InternalError(format!("arena remove_idx_double: {e:?}")))
    }

    pub fn arena_idx_double_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        Some(&self.backend).and_then(|s| s.idx_double_payer(code, scope, table, primary))
    }

    pub fn create_idx_long_double_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: Float128,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .create_idx_long_double_object(
                code,
                scope,
                table,
                payer,
                primary_key,
                (secondary_key.lo, secondary_key.hi),
            )
            .map_err(|e| ChainError::InternalError(format!("arena create_idx_long_double: {e:?}")))
    }

    pub fn update_idx_long_double_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: Float128,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .update_idx_long_double_object(
                code,
                scope,
                table,
                primary_key,
                payer,
                (secondary_key.lo, secondary_key.hi),
            )
            .map_err(|e| ChainError::InternalError(format!("arena update_idx_long_double: {e:?}")))
    }

    pub fn remove_idx_long_double_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), ChainError> {
        self.backend_ref()?
            .remove_idx_long_double_object(code, scope, table, primary_key)
            .map_err(|e| ChainError::InternalError(format!("arena remove_idx_long_double: {e:?}")))
    }

    pub fn arena_idx_long_double_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        Some(&self.backend).and_then(|s| s.idx_long_double_payer(code, scope, table, primary))
    }

    pub fn is_account(&self, account: u64) -> Result<bool, ChainError> {
        let s = &self.backend;
        return Ok(s.account_exists(account));
    }

    /// The `(code_sequence, abi_sequence)` stamped into an `ActionReceipt`, read
    /// as owned scalars from the Rust database. Both feed the receipt digest.
    /// Errors when the account has no metadata.
    pub fn account_metadata_code_abi_sequence(&self, name: u64) -> Result<(u64, u64), ChainError> {
        let s = &self.backend;
        return s.account_metadata(name).map(|t| (t.3, t.4)).ok_or_else(|| {
            ChainError::InternalError(format!("account metadata not found for account: {}", name))
        });
    }

    /// Whether `name` is a privileged account. A plain bool read off
    /// account_metadata. Errors when the account has no metadata.
    pub fn is_account_privileged(&self, name: u64) -> Result<bool, ChainError> {
        let s = &self.backend;
        return s.account_metadata_privileged(name).ok_or_else(|| {
            ChainError::InternalError(format!("account metadata not found for account: {}", name))
        });
    }

    /// The account's current `(code_hash, vm_type, vm_version)` — the fields
    /// setcode reads off `account_metadata` to decide whether code is deployed
    /// and to locate the old code object.
    pub fn account_code_hash_vm(&self, name: u64) -> Result<([u8; 32], u8, u8), ChainError> {
        let s = &self.backend;
        return s
            .account_metadata(name)
            .map(|t| (t.5, t.6, t.7))
            .ok_or_else(|| {
                ChainError::InternalError(format!(
                    "account metadata not found for account: {}",
                    name
                ))
            });
    }

    /// The byte size of the account's stored ABI — what setabi bills RAM against.
    /// A plain length read from the account row.
    pub fn account_abi_size(&self, name: u64) -> Result<usize, ChainError> {
        let s = &self.backend;
        return s
            .account_abi_size(name)
            .ok_or_else(|| ChainError::InternalError(format!("account not found: {}", name)));
    }

    pub fn delete_auth(&mut self, account: u64, permission_name: u64) -> Result<i64, ChainError> {
        // A permission with children cannot be removed — chainbase enforced this
        // via the by-parent index; the arena checks the same by name.
        let has_children = self
            .backend
            .permissions_of(account)
            .iter()
            .any(|(_perm, parent, _blob)| *parent == permission_name);
        if has_children {
            return Err(ChainError::InternalError(format!(
                "cannot delete permission '{}@{}' because it has child permissions",
                Name::new(account),
                Name::new(permission_name)
            )));
        }
        // deleteauth refunds `billable_size_v<permission_object>` plus the
        // authority's dynamic billable size (config.hpp / apply_pulse_deleteauth).
        let auth_blob = self
            .backend
            .permission_auth_blob(account, permission_name)
            .ok_or_else(|| {
                ChainError::InternalError(format!(
                    "permission authority not found for '{}@{}'",
                    Name::new(account),
                    Name::new(permission_name)
                ))
            })?;
        let auth_bill = authority_blob_billable_size(&auth_blob).ok_or_else(|| {
            ChainError::InternalError(format!(
                "invalid authority encoding for '{}@{}'",
                Name::new(account),
                Name::new(permission_name)
            ))
        })?;
        let old_size = billable_size_v::<PermissionObject>() as i64 + auth_bill;
        self.backend
            .remove_permission(account, permission_name)
            .map_err(|e| ChainError::InternalError(format!("arena delete_auth: {e:?}")))?;
        Ok(old_size)
    }

    pub fn link_auth(
        &mut self,
        account_name: u64,
        code_name: u64,
        requirement_name: u64,
        requirement_type: u64,
    ) -> Result<i64, ChainError> {
        // The link's message_type is the requirement_type and its
        // required_permission is the requirement_name. Creating a new link bills
        // `billable_size_v<permission_link_object>`; updating an existing one to a
        // different requirement is free; relinking the same requirement is an error
        // (apply_pulse_linkauth).
        let delta = match self
            .backend
            .permission_link(account_name, code_name, requirement_type)
        {
            Some(existing) if existing == requirement_name => {
                return Err(ChainError::ActionValidationError(
                    "attempting to update required authority, but new requirement is same as old"
                        .to_string(),
                ));
            }
            Some(_) => 0,
            None => PERMISSION_LINK_OBJECT_BILLABLE,
        };
        self.backend
            .link_auth(account_name, code_name, requirement_type, requirement_name)
            .map_err(|e| ChainError::ActionValidationError(format!("arena link_auth: {e:?}")))?;
        Ok(delta)
    }

    pub fn unlink_auth(
        &mut self,
        account_name: u64,
        code_name: u64,
        requirement_type: u64,
    ) -> Result<i64, ChainError> {
        // Removing an existing link refunds `billable_size_v<permission_link_object>`
        // (apply_pulse_unlinkauth); a missing link is a no-op.
        let existed = self
            .backend
            .permission_link(account_name, code_name, requirement_type)
            .is_some();
        self.backend
            .unlink_auth(account_name, code_name, requirement_type)
            .map_err(|e| ChainError::InternalError(format!("arena unlink_auth: {e:?}")))?;
        Ok(if existed {
            -PERMISSION_LINK_OBJECT_BILLABLE
        } else {
            0
        })
    }

    /// The wasm image for `(code_hash, vm_type, vm_version)` as owned bytes.
    ///
    /// This is the bytecode the VM compiles and runs, served from the arena as
    /// owned bytes.
    pub fn get_code_bytes_by_hash(
        &self,
        code_hash: &[u8; 32],
        vm_type: u8,
        vm_version: u8,
    ) -> Result<Vec<u8>, ChainError> {
        self.backend
            .code_by_hash(*code_hash, vm_type, vm_version)
            .ok_or_else(|| ChainError::InternalError("code object not found".to_string()))
    }

    /// Bump the receiver's `recv_sequence` and return the incremented value.
    ///
    /// Takes the account *name* and resolves and mutates the object entirely
    /// inside this method, so no database-bound reference escapes into execution.
    /// The returned sequence lands in the `ActionReceipt` digest.
    pub fn next_recv_sequence(&mut self, receiver: u64) -> Result<u64, ChainError> {
        let s = &self.backend;
        return s
            .next_recv_sequence(receiver)
            .map_err(|e| ChainError::InternalError(format!("arena next_recv_sequence: {e:?}")))?
            .ok_or_else(|| {
                ChainError::InternalError(format!(
                    "account metadata not found for account: {}",
                    Name::new(receiver)
                ))
            });
    }

    pub fn next_auth_sequence(&mut self, actor: u64) -> Result<u64, ChainError> {
        let s = &self.backend;
        s.next_auth_sequence(actor)
            .map_err(|e| ChainError::InternalError(format!("arena next_auth_sequence: {e:?}")))?;
        // The post-bump auth_sequence is what chainbase returns (++auth_sequence).
        return s.account_metadata(actor).map(|t| t.2).ok_or_else(|| {
            ChainError::InternalError(format!(
                "account metadata not found for account: {}",
                Name::new(actor)
            ))
        });
    }

    pub fn next_global_sequence(&mut self) -> Result<u64, ChainError> {
        let s = &self.backend;
        // Chainbase does ++global_action_sequence and returns it; the database
        // stores that post-increment value, so the arena authors the next by
        // advancing its own stored counter.
        let next = s
            .global_action_sequence()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ChainError::InternalError("global action sequence overflow".into()))?;
        s.set_global_action_sequence(next)
            .map_err(|e| ChainError::InternalError(format!("arena next_global_sequence: {e:?}")))?;
        return Ok(next);
    }

    pub fn get_global_action_sequence(&self) -> Result<u64, ChainError> {
        Ok(self.backend.global_action_sequence().unwrap_or(0))
    }

    /// The arena's `global_action_sequence`, or `None` when the singleton row is
    /// unwritten.
    pub fn arena_global_action_sequence(&self) -> Option<u64> {
        self.backend.global_action_sequence()
    }

    pub fn create_permission(
        &mut self,
        account: u64,
        name: u64,
        parent: u64,
        auth: &Authority,
        creation_time: &TimePoint,
    ) -> Result<(), ChainError> {
        let s = &self.backend;
        let authored = s
            .next_permission_id()
            .map_err(|e| ChainError::InternalError(format!("arena next_permission_id: {e:?}")))?;
        s.create_permission(
            authored,
            parent as i64,
            account,
            name,
            creation_time.elapsed.count,
            &encode_authority(auth),
        )
        .map_err(|e| ChainError::InternalError(format!("arena create_permission: {e:?}")))
    }

    pub fn modify_permission(
        &mut self,
        actor: u64,
        permission: u64,
        authority: &Authority,
        pending_block_time: &TimePoint,
    ) -> Result<(), ChainError> {
        let s = &self.backend;
        return s
            .modify_permission(
                actor,
                permission,
                &encode_authority(authority),
                pending_block_time.elapsed.count,
            )
            .map_err(|e| ChainError::InternalError(format!("arena modify_permission: {e:?}")));
    }

    pub fn update_permission_usage(
        &mut self,
        actor: u64,
        permission: u64,
        pending_block_time: &TimePoint,
    ) -> Result<(), ChainError> {
        let s = &self.backend;
        return s
            .update_permission_usage(actor, permission, pending_block_time.elapsed.count)
            .map_err(|e| {
                ChainError::InternalError(format!("arena update_permission_usage: {e:?}"))
            });
    }

    pub fn set_global_properties(&self, cfg: &ChainConfigV0) -> Result<(), ChainError> {
        self.backend
            .set_global_properties(chain_config_params_from_v0(cfg))
            .map_err(|e| ChainError::InternalError(format!("arena set_global_properties: {e:?}")))
    }

    /// `max_action_return_value_size` — a genesis build constant (256) that
    /// `setparams` never carries, so the arena database does not store it and
    /// serves the build constant directly.
    pub fn max_action_return_value_size(&self) -> Result<u32, ChainError> {
        return Ok(256);
    }

    /// The active runtime `chain_config`, served as an owned value from the
    /// arena's `global_property_object` representation.
    pub fn chain_config(&self) -> Result<ChainConfigV0, ChainError> {
        let s = &self.backend;
        let p = s
            .chain_config_params()
            .ok_or_else(|| ChainError::InternalError("arena chain_config not seeded".into()))?;
        return Ok(chain_config_v0_from_params(&p));
    }

    /// Arena database of the static global_property chain_config, `None` when
    /// the requested state is absent.
    pub fn arena_global_property_state_bytes(&self) -> Option<Vec<u8>> {
        Some(self.backend.global_property_state_bytes())
    }

    pub fn get_virtual_block_cpu_limit(&self) -> Result<u64, ChainError> {
        let s = &self.backend;
        return s
            .state_virtual_limits()
            .map(|(cpu, _net)| cpu)
            .ok_or_else(|| ChainError::InternalError("resource state not found".into()));
    }

    pub fn get_virtual_block_net_limit(&self) -> Result<u64, ChainError> {
        let s = &self.backend;
        return s
            .state_virtual_limits()
            .map(|(_cpu, net)| net)
            .ok_or_else(|| ChainError::InternalError("resource state not found".into()));
    }

    pub fn get_block_cpu_limit(&self) -> Result<u64, ChainError> {
        let s = &self.backend;
        return s
            .block_limits()
            .map(|(cpu, _net)| cpu)
            .ok_or_else(|| ChainError::InternalError("resource state not found".into()));
    }

    pub fn get_block_net_limit(&self) -> Result<u64, ChainError> {
        let s = &self.backend;
        return s
            .block_limits()
            .map(|(_cpu, net)| net)
            .ok_or_else(|| ChainError::InternalError("resource state not found".into()));
    }

    pub fn is_known_unexpired_transaction(&self, trx_id: &[u8; 32]) -> Result<bool, ChainError> {
        Ok(self.backend.transaction_exists(*trx_id))
    }

    pub fn record_transaction(
        &mut self,
        trx_id: &[u8; 32],
        expiration: u32,
    ) -> Result<(), ChainError> {
        self.backend
            .record_transaction(*trx_id, expiration)
            .map_err(|e| ChainError::InternalError(format!("arena record_transaction: {e:?}")))
    }

    /// Whether the arena holds a dedupe row for `trx_id`.
    pub fn arena_transaction_exists(&self, trx_id: &[u8; 32]) -> bool {
        self.backend.transaction_exists(*trx_id)
    }

    pub fn clear_expired_input_transactions(
        &mut self,
        cutoff: &TimePoint,
    ) -> Result<(), ChainError> {
        self.backend
            .clear_expired_input_transactions(cutoff.elapsed.count)
            .map_err(|e| {
                ChainError::InternalError(format!("arena clear_expired_input_transactions: {e:?}"))
            })
    }

    pub fn get_currency_balance_with_symbol(
        &self,
        code: u64,
        account: u64,
        symbol: &str,
    ) -> Result<String, ChainError> {
        // The arena formatter returns every balance in the scope; filter to the
        // requested symbol so the response matches nodeos' single-symbol query.
        let want = symbol_from_str(symbol)
            .ok_or_else(|| ChainError::InternalError(format!("invalid symbol: {symbol}")))?;
        let accounts = name_u64("accounts")?;
        let rows: Vec<Vec<u8>> = self
            .arena_table_range(code, account, accounts)
            .into_iter()
            .map(|(_pk, value)| value)
            .filter(|v| v.len() >= 16 && u64::from_le_bytes(v[8..16].try_into().unwrap()) == want)
            .collect();
        let value = pulsevm_rpc::format_currency_balance(&rows)
            .map_err(|e| ChainError::InternalError(format!("format currency_balance: {e}")))?;
        Ok(serde_json::to_string(&value).unwrap())
    }

    pub fn get_currency_balance_without_symbol(
        &self,
        code: u64,
        account: u64,
    ) -> Result<String, ChainError> {
        self.rpc_get_currency_balance(code, account)
    }

    pub fn get_currency_stats(&self, code: u64, symbol: &str) -> Result<String, ChainError> {
        self.rpc_get_currency_stats(code, symbol)
    }

    pub fn get_table_by_scope(
        &self,
        code: u64,
        table: u64,
        _lower_bound: &str,
        _upper_bound: &str,
        limit: u32,
        _reverse: bool,
    ) -> Result<String, ChainError> {
        // The arena formatter serves every scope of `(code, table)` up to `limit`;
        // the bound/reverse arguments were only honoured by the C++ formatter and
        // are not applied on the node's read path.
        self.rpc_get_table_by_scope(code, table, limit)
    }

    pub fn get_table_rows(
        &self,
        json: bool,
        code: u64,
        scope: &str,
        table: u64,
        // Accepted for RPC signature compatibility; the arena query keys off
        // key_type/index_position. table_key/encode_type honouring is a gap.
        _table_key: &str,
        lower_bound: &str,
        upper_bound: &str,
        limit: u32,
        key_type: &str,
        index_position: &str,
        _encode_type: &str,
        reverse: bool,
        show_payer: bool,
    ) -> Result<String, ChainError> {
        return self.rpc_get_table_rows(
            json,
            code,
            scope,
            table,
            lower_bound,
            upper_bound,
            limit,
            key_type,
            index_position,
            reverse,
            show_payer,
        );
    }

    pub fn get_account_info_without_core_symbol(
        &self,
        account: u64,
        head_block_num: u32,
        head_block_time: &TimePoint,
    ) -> Result<String, ChainError> {
        return self.rpc_get_account_info(
            account,
            head_block_num,
            head_block_time.time_since_epoch().count(),
            None,
        );
    }

    pub fn get_account_info_with_core_symbol(
        &self,
        account: u64,
        expected_core_symbol: &str,
        head_block_num: u32,
        head_block_time: &TimePoint,
    ) -> Result<String, ChainError> {
        return self.rpc_get_account_info(
            account,
            head_block_num,
            head_block_time.time_since_epoch().count(),
            Some(expected_core_symbol),
        );
    }

    // ---- Arena-backed RPC formatters ----------------------------------------
    //
    // These serve the read-only RPC endpoints off the arena, formatting through
    // pulsevm_rpc (and pulsevm_abi for the decoded row paths) so the responses
    // match nodeos without the C++ api.cpp. They replace the get_* formatters
    // above when the bridge is removed.

    /// `get_table_rows`: the rows of `(code, scope, table)` in primary order (up
    /// to `limit`), decoded through the contract's ABI in `json` mode or hex
    /// otherwise.
    pub fn rpc_get_table_rows(
        &self,
        json: bool,
        code: u64,
        scope: &str,
        table: u64,
        lower_bound: &str,
        upper_bound: &str,
        limit: u32,
        key_type: &str,
        index_position: &str,
        reverse: bool,
        show_payer: bool,
    ) -> Result<String, ChainError> {
        let scope = rpc_u64(scope, "scope")?;
        let (primary, index_table) = rpc_table_index(table, index_position)?;
        if !primary && key_type.is_empty() {
            return Err(ChainError::InternalError(
                "key type required for non-primary index".into(),
            ));
        }
        if !primary && !matches!(key_type, "i64" | "name") {
            return Err(ChainError::InternalError(format!(
                "unsupported secondary index type {key_type:?}"
            )));
        }

        // C++ constructs and validates the ABI even for raw output and empty
        // tables, including checking that the requested table is declared.
        let abi_bytes = self.arena_account_abi_bytes(code).ok_or_else(|| {
            ChainError::InternalError(format!(
                "failed to retrieve account for {}",
                Name::new(code)
            ))
        })?;
        let abi = pulsevm_abi::Abi::from_bytes(&abi_bytes)
            .map_err(|e| ChainError::InternalError(format!("abi decode: {e}")))?;
        let row_type = abi.table_row_type(table).ok_or_else(|| {
            ChainError::InternalError(format!(
                "table {} is not specified in the ABI",
                Name::new(table)
            ))
        })?;
        if primary
            && abi.table_index_type(table) != Some("i64")
            && !matches!(key_type, "i64" | "name")
        {
            return Err(ChainError::InternalError(format!(
                "invalid table index type {:?}",
                abi.table_index_type(table)
            )));
        }

        let lower = if lower_bound.is_empty() {
            u64::MIN
        } else {
            rpc_bound(lower_bound, key_type, "lower_bound")?
        };
        let upper = if upper_bound.is_empty() {
            u64::MAX
        } else {
            rpc_bound(upper_bound, key_type, "upper_bound")?
        };
        if upper < lower {
            let value = pulsevm_rpc::format_table_rows(
                json,
                Some(&abi),
                &row_type,
                &[],
                false,
                "",
                show_payer,
            )
            .map_err(|e| ChainError::InternalError(format!("format table_rows: {e}")))?;
            return Ok(serde_json::to_string(&value).unwrap());
        }

        let positioned: Vec<RpcPositionedRow> = if primary {
            self.arena_table_range_with_payer(code, scope, table)
                .into_iter()
                .collect()
        } else {
            self.arena_idx64_range_with_payer(code, scope, index_table)
                .into_iter()
                .filter_map(|(secondary, primary, payer)| {
                    self.arena_kv_get(code, scope, table, primary)
                        .map(|data| (secondary, payer, data))
                })
                .collect()
        };
        let (positioned, more, next_key) = rpc_table_page(positioned, lower, upper, reverse, limit);
        let rows: Vec<pulsevm_rpc::TableRow> = positioned
            .into_iter()
            .map(|(_, payer, data)| pulsevm_rpc::TableRow { payer, data })
            .collect();

        let value = pulsevm_rpc::format_table_rows(
            json,
            Some(&abi),
            &row_type,
            &rows,
            more,
            &next_key,
            show_payer,
        )
        .map_err(|e| ChainError::InternalError(format!("format table_rows: {e}")))?;
        Ok(serde_json::to_string(&value).unwrap())
    }

    /// `get_currency_balance`: every balance the token contract `code` holds for
    /// `account` (its `accounts` table rows, each a single asset).
    pub fn rpc_get_currency_balance(&self, code: u64, account: u64) -> Result<String, ChainError> {
        let accounts = name_u64("accounts")?;
        let rows: Vec<Vec<u8>> = self
            .arena_table_range(code, account, accounts)
            .into_iter()
            .map(|(_pk, value)| value)
            .collect();
        let value = pulsevm_rpc::format_currency_balance(&rows)
            .map_err(|e| ChainError::InternalError(format!("format currency_balance: {e}")))?;
        Ok(serde_json::to_string(&value).unwrap())
    }

    /// `get_currency_stats`: the `stat` row for `symbol` under token contract
    /// `code` (supply, max_supply, issuer).
    pub fn rpc_get_currency_stats(&self, code: u64, symbol: &str) -> Result<String, ChainError> {
        let stat = name_u64("stat")?;
        let scope = symbol_code_from_str(symbol);
        let rows: Vec<Vec<u8>> = self
            .arena_table_range(code, scope, stat)
            .into_iter()
            .map(|(_pk, value)| value)
            .collect();
        let value = pulsevm_rpc::format_currency_stats(&rows)
            .map_err(|e| ChainError::InternalError(format!("format currency_stats: {e}")))?;
        Ok(serde_json::to_string(&value).unwrap())
    }

    /// `get_table_by_scope`: every scope of contract `code` (optionally a single
    /// `table`, or all tables when `table == 0`), up to `limit`.
    pub fn rpc_get_table_by_scope(
        &self,
        code: u64,
        table: u64,
        limit: u32,
    ) -> Result<String, ChainError> {
        let bytes = self.arena_contract_table_state_bytes().unwrap_or_default();
        let mut rows: Vec<pulsevm_rpc::ScopeRow> = Vec::new();
        let mut p = 0;
        while p + 36 <= bytes.len() {
            let u = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
            let (rcode, rscope, rtable) = (u(p), u(p + 8), u(p + 16));
            let rpayer = u(p + 24);
            let rcount = u32::from_le_bytes(bytes[p + 32..p + 36].try_into().unwrap());
            p += 36;
            if rcode == code && (table == 0 || rtable == table) {
                rows.push(pulsevm_rpc::ScopeRow {
                    code: rcode,
                    scope: rscope,
                    table: rtable,
                    payer: rpayer,
                    count: rcount,
                });
            }
        }
        rows.truncate(limit as usize);
        let value = pulsevm_rpc::format_table_by_scope(&rows, "");
        Ok(serde_json::to_string(&value).unwrap())
    }

    /// `get_account`: the account's metadata, permissions, core-token balance and
    /// the system-contract sub-objects, composed from the arena. `expected_core_
    /// symbol` overrides the auto-detected core symbol (`None` = detect it from
    /// the system contract's rammarket).
    pub fn rpc_get_account_info(
        &self,
        account: u64,
        head_block_num: u32,
        head_block_time_micros: i64,
        expected_core_symbol: Option<&str>,
    ) -> Result<String, ChainError> {
        use pulsevm_rpc::{
            AccountInfo,
            KeyWeight,
            LinkedAction,
            Permission,
            PermissionLevelWeight,
            ResourceLimit,
            WaitWeight,
        };

        let created_slot = self.arena_account_creation_date(account).ok_or_else(|| {
            ChainError::InternalError(format!("account not found for get_account: {account}"))
        })?;
        let privileged = self
            .arena_account_metadata_privileged(account)
            .unwrap_or(false);
        let last_code_update = self.arena_account_last_code_update(account).unwrap_or(0);
        let created = block_slot_to_micros(created_slot);
        let ram_usage = self
            .arena_account_ram_usage(account)
            .map(|u| u as i64)
            .unwrap_or(0);
        let (ram_quota, net_weight, cpu_weight) =
            self.arena_account_limits(account).unwrap_or((-1, -1, -1));

        // Resource windows come wholly from the arena and project `current_used`
        // to the head-block slot. A never-used accumulator (slot 0) is reported
        // at the account creation time, matching nodeos.
        let usage_time = |slot: u32| {
            if slot == 0 {
                created
            } else {
                block_slot_to_micros(slot)
            }
        };
        let to_rpc_limit = |limit: pulsevm_chaindb::AccountResourceLimit| ResourceLimit {
            used: limit.used,
            available: limit.available,
            max: limit.max,
            last_usage_update_time: usage_time(limit.last_ordinal),
            current_used: limit.current_used,
        };
        let current_slot = micros_to_block_slot(head_block_time_micros);
        let default_limit = pulsevm_chaindb::AccountResourceLimit {
            used: -1,
            available: -1,
            max: -1,
            last_ordinal: 0,
            current_used: -1,
        };
        let (net_limit, cpu_limit) = (
            self.backend
                .account_net_limit_info(account, 1000, Some(current_slot))
                .map(|v| v.0)
                .unwrap_or(default_limit),
            self.backend
                .account_cpu_limit_info(account, 1000, Some(current_slot))
                .map(|v| v.0)
                .unwrap_or(default_limit),
        );
        let net_limit = to_rpc_limit(net_limit);
        let cpu_limit = to_rpc_limit(cpu_limit);

        let mut links_by_permission: std::collections::BTreeMap<u64, Vec<LinkedAction>> =
            self.backend.permission_links_of(account).into_iter().fold(
                std::collections::BTreeMap::new(),
                |mut links, (required, code, action)| {
                    links.entry(required).or_default().push(LinkedAction {
                        account: code,
                        action: (action != 0).then_some(action),
                    });
                    links
                },
            );
        let permissions = self
            .arena_permissions_of(account)
            .into_iter()
            .map(|(perm_name, parent, auth)| Permission {
                perm_name,
                parent,
                required_auth: pulsevm_rpc::Authority {
                    threshold: auth.threshold,
                    keys: auth
                        .keys
                        .iter()
                        .map(|k| KeyWeight {
                            key: k.key.to_string(),
                            weight: k.weight,
                        })
                        .collect(),
                    accounts: auth
                        .accounts
                        .iter()
                        .map(|a| PermissionLevelWeight {
                            actor: a.permission.actor,
                            permission: a.permission.permission,
                            weight: a.weight,
                        })
                        .collect(),
                    waits: auth
                        .waits
                        .iter()
                        .map(|w| WaitWeight {
                            wait_sec: w.wait_sec,
                            weight: w.weight,
                        })
                        .collect(),
                },
                linked_actions: links_by_permission.remove(&perm_name).unwrap_or_default(),
            })
            .collect();

        // Core-token liquid balance: the row keyed by the core symbol's code in
        // the token contract's `accounts` table scoped to the account.
        let core_symbol_packed =
            match expected_core_symbol {
                Some(s) => Some(symbol_from_str(s).ok_or_else(|| {
                    ChainError::InternalError(format!("invalid core symbol: {s}"))
                })?),
                None => self.extract_core_symbol(),
            };
        let core_liquid_balance = core_symbol_packed.and_then(|sym| {
            let token = name_u64("pulse.token").ok()?;
            let accounts = name_u64("accounts").ok()?;
            let row = self.arena_kv_get(token, account, accounts, sym >> 8)?;
            if row.len() < 16 || u64::from_le_bytes(row[8..16].try_into().ok()?) != sym {
                return None;
            }
            let arr = pulsevm_rpc::format_currency_balance(&[row]).ok()?;
            arr.as_array()?.first()?.as_str().map(|s| s.to_string())
        });

        // System-contract sub-objects, decoded against the system contract's ABI.
        let system = name_u64("pulse")?;
        let system_abi = self
            .arena_account_abi_bytes(system)
            .and_then(|b| pulsevm_abi::Abi::from_bytes(&b).ok());
        let decode_row = |scope: u64, table: &str, ty: &str| -> serde_json::Value {
            let Some(abi) = system_abi.as_ref() else {
                return serde_json::Value::Null;
            };
            let Ok(table) = name_u64(table) else {
                return serde_json::Value::Null;
            };
            match self.arena_kv_get(system, scope, table, account) {
                Some(bytes) => abi
                    .bin_to_json(ty, &mut &bytes[..])
                    .unwrap_or(serde_json::Value::Null),
                None => serde_json::Value::Null,
            }
        };

        let info = AccountInfo {
            account_name: account,
            head_block_num,
            head_block_time: head_block_time_micros,
            privileged,
            last_code_update,
            created,
            core_liquid_balance,
            ram_quota,
            net_weight,
            cpu_weight,
            net_limit,
            cpu_limit,
            ram_usage,
            permissions,
            total_resources: serde_json::Value::Null,
            self_delegated_bandwidth: decode_row(account, "delband", "DelegatedBandwidth"),
            refund_request: decode_row(account, "refunds", "RefundRequest"),
            voter_info: decode_row(system, "voters", "VoterInfo"),
            rex_info: decode_row(system, "rexbal", "RexBalance"),
            // A fixed default (fc's time_point epoch, 2000-01-01), matching nodeos.
            subjective_cpu_bill_limit: ResourceLimit {
                used: 0,
                available: 0,
                max: 0,
                last_usage_update_time: BLOCK_TIMESTAMP_EPOCH_MICROS,
                current_used: 0,
            },
            eosio_any_linked_actions: name_u64("pulse.any")
                .ok()
                .and_then(|any| links_by_permission.remove(&any))
                .unwrap_or_default(),
        };

        Ok(serde_json::to_string(&pulsevm_rpc::format_account_info(&info)).unwrap())
    }

    /// The system contract's core symbol (precision in the low byte, code above),
    /// read from its `rammarket` `RAMCORE` row. `None` if the market is absent.
    fn extract_core_symbol(&self) -> Option<u64> {
        let system = name_u64("pulse").ok()?;
        let rammarket = name_u64("rammarket").ok()?;
        // The RAMCORE row's primary key is string_to_symbol(4, "RAMCORE").
        let pk = (symbol_code_from_str("RAMCORE") << 8) | 4;
        let bytes = self.arena_kv_get(system, system, rammarket, pk)?;
        // ram_market_exchange_state: asset, asset, double, asset core_symbol,
        // double — the core symbol sits in the third asset's symbol half (offset
        // 16 + 16 + 8 amount = 40, symbol at 48).
        if bytes.len() >= 56 {
            Some(u64::from_le_bytes(bytes[48..56].try_into().ok()?))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use pulsevm_name::Name;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_database_creation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1024 * 1024 * 1024).unwrap();
        let _name = Name::from_str("test").unwrap();
        db.add_indices().unwrap();
    }

    // 64 MiB is a multiple of chainbase's 1 MiB sizing requirement and leaves
    // ample room for a handful of rows, while keeping the file cheap to copy in
    // a test.
    const TEST_DB_SIZE: u64 = 64 * 1024 * 1024;

    fn name_u64(s: &str) -> u64 {
        Name::from_str(s).unwrap().as_u64()
    }

    #[test]
    fn rpc_table_page_matches_inclusive_cpp_pagination() {
        let rows = [1u64, 2, 3, 4]
            .into_iter()
            .map(|key| (key, 9, vec![key as u8]));
        let (page, more, next) = rpc_table_page(rows, 2, 4, false, 2);
        assert_eq!(page.iter().map(|r| r.0).collect::<Vec<_>>(), [2, 3]);
        assert!(more);
        assert_eq!(next, "4");

        let rows = [1u64, 2, 3, 4]
            .into_iter()
            .map(|key| (key, 9, vec![key as u8]));
        let (page, more, next) = rpc_table_page(rows, 2, 4, true, 2);
        assert_eq!(page.iter().map(|r| r.0).collect::<Vec<_>>(), [4, 3]);
        assert!(more);
        assert_eq!(next, "2");

        let rows = [(7, 9, vec![])];
        let (page, more, next) = rpc_table_page(rows, 0, u64::MAX, false, 0);
        assert!(page.is_empty());
        assert!(more);
        assert_eq!(next, "7");
    }

    #[test]
    fn rpc_table_key_parsing_matches_cpp_forms() {
        assert_eq!(rpc_u64("42", "key").unwrap(), 42);
        assert_eq!(rpc_u64("alice", "key").unwrap(), name_u64("alice"));
        let eos = symbol_code_from_str("EOS");
        assert_eq!(rpc_u64("EOS", "key").unwrap(), eos);
        assert_eq!(rpc_u64("4,EOS", "key").unwrap(), (eos << 8) | 4);

        let table = name_u64("accounts");
        assert_eq!(rpc_table_index(table, "primary").unwrap(), (true, table));
        assert_eq!(rpc_table_index(table, "2").unwrap(), (false, table));
        assert_eq!(rpc_table_index(table, "third").unwrap(), (false, table | 1));
    }

    /// The arena reconstructs the whole authority from its stored blob: encoding
    /// an authority with a key, an account, and a wait, decoding it, and
    /// re-encoding must reproduce the exact blob (value equality — keys pack to
    /// their canonical bytes), and the decoded structure must match field for
    /// field. This is what lets the arena serve `PermissionObject::get_authority`.
    #[test]
    fn decode_authority_is_the_inverse_of_encode() {
        let key =
            K1PublicKey::from_string("PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H")
                .expect("parse pubkey");
        let auth = Authority {
            threshold: 2,
            keys: vec![KeyWeight { key, weight: 1 }],
            accounts: vec![PermissionLevelWeight {
                permission: PermissionLevel {
                    actor: name_u64("alice"),
                    permission: name_u64("active"),
                },
                weight: 3,
            }],
            waits: vec![WaitWeight {
                wait_sec: 604800,
                weight: 4,
            }],
        };

        let blob = encode_authority(&auth);
        let decoded = decode_authority(&blob).expect("decode");
        assert_eq!(
            encode_authority(&decoded),
            blob,
            "decode∘encode is not the identity"
        );

        assert_eq!(decoded.threshold, 2);
        assert_eq!(decoded.keys.len(), 1);
        assert_eq!(decoded.keys[0].weight, 1);
        assert_eq!(decoded.accounts.len(), 1);
        assert_eq!(decoded.accounts[0].permission.actor, name_u64("alice"));
        assert_eq!(
            decoded.accounts[0].permission.permission,
            name_u64("active")
        );
        assert_eq!(decoded.accounts[0].weight, 3);
        assert_eq!(decoded.waits.len(), 1);
        assert_eq!(decoded.waits[0].wait_sec, 604800);
        assert_eq!(decoded.waits[0].weight, 4);
    }

    /// The blob billable-size parser reproduces `shared_authority::get_billable_size`
    /// over all three components: a key (whose packed size it must skip exactly), an
    /// account weight, and a wait. A wrong key-length skip would misalign the
    /// account/wait parse and change the total, so this pins the offset math. The
    /// per-key packed size is taken from `packed_public_key_bytes` — the same
    /// `fc::raw::pack` the C++ `pack_size(key)` measures — and the weight constants
    /// from `billable_size_v`. (End-to-end equality against chainbase's own
    /// `get_billable_size` is covered under arena reads by the newaccount serve in
    /// `oracle_permission_authority_serves_from_arena`.)
    #[test]
    fn authority_blob_billable_size_matches_formula() {
        let key =
            K1PublicKey::from_string("PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H")
                .unwrap();
        let key_len = key.to_packed().len() as i64;
        let auth = Authority {
            threshold: 2,
            keys: vec![KeyWeight { key, weight: 1 }],
            accounts: vec![PermissionLevelWeight {
                permission: PermissionLevel {
                    actor: name_u64("bob"),
                    permission: name_u64("active"),
                },
                weight: 1,
            }],
            waits: vec![WaitWeight {
                wait_sec: 100,
                weight: 1,
            }],
        };

        let blob = encode_authority(&auth);
        let got = authority_blob_billable_size(&blob).expect("well-formed blob");
        let expected = (billable_size_v::<KeyWeight>() as i64 + key_len)
            + billable_size_v::<PermissionLevelWeight>() as i64
            + billable_size_v::<WaitWeight>() as i64;
        assert_eq!(got, expected, "billable size formula mismatch");

        // A truncated blob is rejected rather than under-counted.
        assert_eq!(authority_blob_billable_size(&blob[..blob.len() - 3]), None);
    }

    /// A truncated blob is rejected, not silently mis-decoded.
    #[test]
    fn decode_authority_rejects_truncated_blob() {
        // threshold + a key count of 1 but no key payload.
        let mut blob = 1u32.to_le_bytes().to_vec();
        blob.extend_from_slice(&1u32.to_le_bytes());
        assert!(decode_authority(&blob).is_err());
    }

    #[test]
    fn restore_rejects_corrupt_snapshot() {
        let src = TempDir::new().unwrap();
        let mut db = Database::new(src.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        db.add_indices().unwrap();

        let mut snap = db.snapshot_bytes().unwrap();
        let last = snap.len() - 1;
        snap[last] ^= 0xFF;

        let dst = TempDir::new().unwrap();
        let dst_path = dst.path().to_str().unwrap();
        assert!(restore_snapshot(dst_path, &snap).is_err());
        // The envelope is validated before anything touches disk.
        assert!(!Path::new(dst_path).join(SHARED_MEMORY_FILE).exists());
    }

    #[test]
    fn restore_from_bytes_swaps_live_state() {
        // Source arena: revision 3 with alice.
        let src = TempDir::new().unwrap();
        let mut a = Database::new(src.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        a.add_indices().unwrap();
        a.set_revision(3).unwrap();
        let alice = name_u64("alice");
        a.create_account(alice, 1).unwrap();
        let snap = a.snapshot_bytes().unwrap();

        // Target arena: different state (revision 9 with bob).
        let dst = TempDir::new().unwrap();
        let mut b = Database::new(dst.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        b.add_indices().unwrap();
        b.set_revision(9).unwrap();
        let bob = name_u64("bob");
        b.create_account(bob, 2).unwrap();

        // Restoring the source snapshot into the live target replaces its state.
        let header = b.restore_from_bytes(&snap).unwrap();
        assert_eq!(header.revision, 3);
        assert_eq!(b.revision(), 3);
        assert!(b.arena_account_exists(alice), "alice not restored");
        assert!(!b.arena_account_exists(bob), "bob's state survived");

        // The target is still a working database after the swap.
        let carol = name_u64("carol");
        b.create_account(carol, 3).unwrap();
        assert!(b.arena_account_exists(carol));
    }

    #[test]
    fn restore_from_bytes_rejects_corrupt_without_disturbing_db() {
        let src = TempDir::new().unwrap();
        let mut a = Database::new(src.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        a.add_indices().unwrap();
        a.set_revision(5).unwrap();
        let alice = name_u64("alice");
        a.create_account(alice, 1).unwrap();

        let mut snap = a.snapshot_bytes().unwrap();
        let last = snap.len() - 1;
        snap[last] ^= 0xFF;

        // A corrupt snapshot is rejected up front; the running database is
        // untouched and still holds its own state.
        assert!(a.restore_from_bytes(&snap).is_err());
        assert_eq!(a.revision(), 5);
        assert!(a.arena_account_exists(alice));
    }

    #[test]
    fn restore_rejects_envelope_payload_revision_mismatch_without_replacing_state() {
        let src = TempDir::new().unwrap();
        let mut source = Database::new(src.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        source.set_revision(3).unwrap();
        let mut snap = source.snapshot_bytes().unwrap();
        // The envelope checksum covers the payload, so changing only the clear
        // revision keeps this a checksum-valid transfer. Restore must compare it
        // with the revision inside the arena checkpoint.
        snap[8..16].copy_from_slice(&4i64.to_le_bytes());

        let dst = TempDir::new().unwrap();
        let dst_path = dst.path().to_str().unwrap();
        let mut target = Database::new(dst_path, TEST_DB_SIZE).unwrap();
        target.set_revision(9).unwrap();
        let alice = name_u64("alice");
        target.create_account(alice, 1).unwrap();
        target.close().unwrap();

        assert!(target.restore_from_bytes(&snap).is_err());
        assert_eq!(target.revision(), 9);
        assert!(target.arena_account_exists(alice));

        // The already-durable checkpoint was not overwritten either.
        let reopened = Database::new(dst_path, TEST_DB_SIZE).unwrap();
        assert_eq!(reopened.revision(), 9);
        assert!(reopened.arena_account_exists(alice));
    }

    #[test]
    fn bootstrap_restore_installs_the_checkpoint_database_opens() {
        let src = TempDir::new().unwrap();
        let mut source = Database::new(src.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        source.set_revision(7).unwrap();
        let alice = name_u64("alice");
        source.create_account(alice, 1).unwrap();
        let snap = source.snapshot_bytes().unwrap();

        let dst = TempDir::new().unwrap();
        let dst_path = dst.path().to_str().unwrap();
        let header = restore_snapshot(dst_path, &snap).unwrap();
        assert_eq!(header.revision, 7);

        let restored = Database::new(dst_path, TEST_DB_SIZE).unwrap();
        assert_eq!(restored.revision(), 7);
        assert!(restored.arena_account_exists(alice));
    }

    fn initialized_resource_db() -> (TempDir, Database) {
        let dir = TempDir::new().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        db.add_indices().unwrap();
        let genesis =
            pulsevm_chain_types::GenesisState::from_json(include_str!("../../../genesis.json"))
                .unwrap();
        db.initialize_database(&genesis).unwrap();
        (dir, db)
    }

    #[test]
    fn transaction_usage_validation_rejects_account_net_and_cpu_overages() {
        let (_dir, mut db) = initialized_resource_db();
        let alice = name_u64("alice");
        let bob = name_u64("bob");
        for account in [alice, bob] {
            db.create_account(account, 0).unwrap();
            db.initialize_account_resource_limits(account).unwrap();
        }

        // Give alice a tiny fraction of both weighted resources.
        db.set_account_limits(alice, -1, 1, 1).unwrap();
        db.set_account_limits(bob, -1, 10_000_000_000, 10_000_000_000)
            .unwrap();
        db.process_account_limit_updates().unwrap();

        let net = db.get_account_net_limit(alice, 1000).unwrap().limit;
        let cpu = db.get_account_cpu_limit(alice, 1000).unwrap().limit;
        assert!(net >= 0 && cpu >= 0);
        let block_net_before = db.get_block_net_limit().unwrap();
        let block_cpu_before = db.get_block_cpu_limit().unwrap();

        let net_err = db
            .add_transaction_usage(&Name::new(alice), 0, net as u64 + 1, 1, true)
            .unwrap_err();
        assert!(matches!(net_err, ChainError::TransactionError(_)));

        let cpu_err = db
            .add_transaction_usage(&Name::new(alice), cpu as u64 + 1, 0, 1, true)
            .unwrap_err();
        assert!(matches!(cpu_err, ChainError::TransactionError(_)));

        // Rejected billing must not alter either account or block usage.
        assert_eq!(db.get_account_net_limit(alice, 1000).unwrap().limit, net);
        assert_eq!(db.get_account_cpu_limit(alice, 1000).unwrap().limit, cpu);
        assert_eq!(db.get_block_net_limit().unwrap(), block_net_before);
        assert_eq!(db.get_block_cpu_limit().unwrap(), block_cpu_before);
    }

    #[test]
    fn account_usage_errors_do_not_fail_open() {
        let (_dir, mut db) = initialized_resource_db();
        let block_net_before = db.get_block_net_limit().unwrap();
        let unknown = Name::new(name_u64("missing"));

        assert!(db.update_account_usage(&unknown, 1).is_err());
        assert!(db.add_transaction_usage(&unknown, 1, 1, 1, true).is_err());
        assert!(db.verify_account_ram_usage(unknown.as_u64()).is_err());
        assert_eq!(db.get_block_net_limit().unwrap(), block_net_before);
    }

    #[test]
    fn transaction_usage_validation_rejects_block_cpu_and_net_overages() {
        let (_dir, mut db) = initialized_resource_db();
        let alice = name_u64("alice");
        db.create_account(alice, 0).unwrap();
        db.initialize_account_resource_limits(alice).unwrap();

        // Negative weights are unlimited at account scope, isolating the block
        // checks exercised by this test.
        let account = Name::new(alice);
        let block_cpu = db.get_block_cpu_limit().unwrap();
        let block_net = db.get_block_net_limit().unwrap();

        let cpu_err = db
            .add_transaction_usage(&account, block_cpu + 1, 0, 1, true)
            .unwrap_err();
        assert!(matches!(cpu_err, ChainError::TransactionError(_)));

        let net_err = db
            .add_transaction_usage(&account, 0, block_net + 1, 1, true)
            .unwrap_err();
        assert!(matches!(net_err, ChainError::TransactionError(_)));

        assert_eq!(db.get_block_cpu_limit().unwrap(), block_cpu);
        assert_eq!(db.get_block_net_limit().unwrap(), block_net);
    }
}

impl Database {
    /// Acquire a read view over the arena. The arena is `Arc`-backed with its own
    /// interior synchronization, so the view is a cheap clone that carries no
    /// borrow of `self`.
    pub fn read(&self) -> Result<DbRead<'_>, ChainError> {
        Ok(DbRead {
            backend: self.backend.clone(),
            _marker: std::marker::PhantomData,
        })
    }
}

/// Read view over the arena. Holds a cheap clone of the arena handle; the `'g`
/// lifetime is retained for source compatibility with call sites that name it.
pub struct DbRead<'g> {
    backend: crate::backend::ChainDatabase,
    _marker: std::marker::PhantomData<&'g ()>,
}

/// An owned snapshot of the consensus-visible fields execution reads off a
/// permission, standing in for a chainbase `&PermissionObject` reference the
/// arena can't hand back. Everything a caller used to pull off the object —
/// its id, parent id, authority billable size, and the `(owner, name)` needed
/// to name it and walk the satisfies tree — is captured here, so the read path
/// no longer borrows into chainbase memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermissionInfo {
    owner: u64,
    name: u64,
    id: i64,
    parent_id: i64,
    auth_billable_size: i64,
}

impl PermissionInfo {
    pub fn owner(&self) -> u64 {
        self.owner
    }

    pub fn name(&self) -> u64 {
        self.name
    }

    pub fn get_id(&self) -> i64 {
        self.id
    }

    pub fn get_parent_id(&self) -> i64 {
        self.parent_id
    }

    /// The RAM billed for this permission's authority.
    pub fn authority_billable_size(&self) -> i64 {
        self.auth_billable_size
    }

    /// Does this permission satisfy `other` — is it that same permission, its
    /// immediate parent, or an ancestor up its parent chain. Resolved by name; see
    /// [`DbRead::permission_satisfies_by_name`].
    pub fn satisfies(&self, other: &PermissionInfo, db: &DbRead<'_>) -> Result<bool, ChainError> {
        db.permission_satisfies_by_name(self.owner, self.name, other.owner, other.name)
    }
}

impl<'g> DbRead<'g> {
    /// The full authority for `(actor, permission)` as an owned value, or `None`
    /// if the permission doesn't exist.
    ///
    /// Authorization satisfaction reads the authority here as an owned value.
    /// `decode_authority` is the inverse of the canonical encoding stored in the
    /// permission row.
    pub fn permission_authority(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<Option<Authority>, ChainError> {
        let s = &self.backend;
        return match s.permission_auth_blob(actor, permission) {
            Some(blob) => Ok(Some(decode_authority(&blob)?)),
            None => Ok(None),
        };
    }

    /// The permission's consensus id. `newaccount` reads the owner permission's
    /// id here to parent the active permission on it.
    pub fn permission_id(&self, owner: u64, perm_name: u64) -> Result<Option<i64>, ChainError> {
        let s = &self.backend;
        return Ok(s.permission_cb_id(owner, perm_name));
    }

    /// The permission authority's `get_billable_size()` (the RAM a permission's
    /// authority is charged), computed from the arena's stored auth blob and
    /// served from the Rust database. newaccount bills this for the new
    /// owner/active permissions.
    pub fn permission_authority_billable_size(
        &self,
        owner: u64,
        perm_name: u64,
    ) -> Result<Option<i64>, ChainError> {
        let s = &self.backend;
        return Ok(s
            .permission_auth_blob(owner, perm_name)
            .and_then(|blob| authority_blob_billable_size(&blob)));
    }

    /// Resolve a permission to the owned [`PermissionInfo`] execution reads,
    /// without exposing an internal arena row reference.
    pub fn find_permission_info(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<Option<PermissionInfo>, ChainError> {
        let s = &self.backend;
        return Ok(Self::arena_permission_info(s, actor, permission));
    }

    /// Build a [`PermissionInfo`] purely from the arena database, or `None` if the
    /// permission is absent. Each field comes from the same arena accessor the
    /// value-based reads already use, so the snapshot is consistent with them.
    fn arena_permission_info(
        s: &crate::backend::ChainDatabase,
        owner: u64,
        name: u64,
    ) -> Option<PermissionInfo> {
        let id = s.permission_cb_id(owner, name)?;
        let (parent_id, _threshold) = s.permission(owner, name)?;
        let auth_billable_size = s
            .permission_auth_blob(owner, name)
            .and_then(|blob| authority_blob_billable_size(&blob))?;
        Some(PermissionInfo {
            owner,
            name,
            id,
            parent_id,
            auth_billable_size,
        })
    }

    /// Does permission `(owner_a, name_a)` satisfy `(owner_b, name_b)`. Named
    /// counterpart to [`permission_satisfies_other_permission`] that walks the
    /// arena's permission tree directly.
    pub fn permission_satisfies_by_name(
        &self,
        owner_a: u64,
        name_a: u64,
        owner_b: u64,
        name_b: u64,
    ) -> Result<bool, ChainError> {
        let s = &self.backend;
        return s
            .permission_satisfies(owner_a, name_a, owner_b, name_b)
            .ok_or_else(|| {
                ChainError::InternalError(
                    "permission_satisfies: permission absent from arena".to_string(),
                )
            });
    }

    /// The `last_used` microsecond timestamp of a permission, by name.
    pub fn permission_last_used_by_name(&self, owner: u64, name: u64) -> Result<i64, ChainError> {
        let s = &self.backend;
        return s.permission_last_used(owner, name).ok_or_else(|| {
            ChainError::InternalError(
                "permission_last_used: permission absent from arena".to_string(),
            )
        });
    }

    pub fn lookup_linked_permission(
        &self,
        account: u64,
        code: u64,
        requirement_type: u64,
    ) -> Result<Option<u64>, ChainError> {
        let s = &self.backend;
        return Ok(s.permission_link(account, code, requirement_type));
    }
}

impl Default for Database {
    fn default() -> Self {
        Self {
            path: String::new(),
            backend: crate::backend::ChainDatabase::new().expect("arena init"),
        }
    }
}

/// Install a physical snapshot into `db_path`, ready to be opened normally.
///
/// The envelope is validated (magic, version, checksum) before anything touches
/// disk, so a corrupt transfer is rejected here rather than surfacing as a
/// database-open failure. The payload is validated as an arena checkpoint in a
/// sibling temporary file and atomically installed as `arena_state.bin`.
///
/// The caller must hold no open handle to `db_path` — this replaces the arena
/// file wholesale. It is meant to run during bootstrap, before the controller
/// opens the database. Returns the decoded header (notably the revision) so the
/// caller can reconcile its block logs against the restored state.
pub fn restore_snapshot(
    db_path: &str,
    snapshot: &[u8],
) -> Result<crate::snapshot::SnapshotHeader, ChainError> {
    let (header, payload) = crate::snapshot::decode(snapshot)?;
    fs::create_dir_all(db_path)
        .map_err(|e| ChainError::InternalError(format!("restore: create {db_path}: {e}")))?;
    let dir = Path::new(db_path);
    let file = dir.join(ARENA_STATE_FILE);
    let staged = Database::stage_snapshot(dir, header, payload)?;
    staged.persist(&file).map_err(|e| {
        ChainError::InternalError(format!("restore: install {}: {}", file.display(), e.error))
    })?;
    Ok(header)
}
