use std::{
    fs,
    io::{
        Read,
        Seek,
        SeekFrom,
        Write,
    },
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        RwLock,
        RwLockWriteGuard,
    },
};

use cxx::UniquePtr;
use pulsevm_error::ChainError;
use pulsevm_name::Name;

use crate::{
    Authority,
    ChainConfigV0,
    ElasticLimitParameters,
    Float128,
    Index64IteratorCache,
    Index128IteratorCache,
    IndexDoubleIteratorCache,
    IndexLongDoubleIteratorCache,
    IndexLongDoubleObject,
    KeyValueObject,
    Ratio,
    bridge::ffi::{
        self,
        CxxDigest,
        CxxGenesisState,
        Index64Object,
        Index128Object,
        Index256Object,
        IndexDoubleObject,
        TableObject,
        U128,
        U256,
        get_account_info_with_core_symbol,
        get_account_info_without_core_symbol,
        get_currency_balance_with_symbol,
        get_currency_balance_without_symbol,
        get_currency_stats,
        get_table_by_scope,
        get_table_rows,
    },
    iterator_cache::{
        Index256IteratorCache,
        KeyValueIteratorCache,
    },
};
// The public `Database` methods speak the pure-Rust TimePoint; only the calls
// that actually descend into C++ (below) rebuild the bridge struct from it.
use pulsevm_chain_types::TimePoint;

/// Rebuild the cxx-bridge `TimePoint` from the pure-Rust one at a C++ boundary.
#[inline]
fn cxx_time_point(t: &TimePoint) -> ffi::TimePoint {
    ffi::TimePoint {
        elapsed: ffi::Microseconds {
            count: t.elapsed.count,
        },
    }
}

/// The inverse: a bridge `TimePoint` returned from C++ back into the pure-Rust one.
#[inline]
fn native_time_point(t: ffi::TimePoint) -> TimePoint {
    TimePoint {
        elapsed: pulsevm_chain_types::Microseconds {
            count: t.elapsed.count,
        },
    }
}

/// Rebuild the cxx-bridge `ElasticLimitParameters` from the pure-Rust one for a
/// C++ call.
#[inline]
fn cxx_elastic(p: &ElasticLimitParameters) -> ffi::ElasticLimitParameters {
    ffi::ElasticLimitParameters {
        target: p.target,
        max: p.max,
        periods: p.periods,
        max_multiplier: p.max_multiplier,
        contract_rate: ffi::Ratio {
            numerator: p.contract_rate.numerator,
            denominator: p.contract_rate.denominator,
        },
        expand_rate: ffi::Ratio {
            numerator: p.expand_rate.numerator,
            denominator: p.expand_rate.denominator,
        },
    }
}

/// The inverse: a bridge `ElasticLimitParameters` from C++ into the pure-Rust one.
#[inline]
fn native_elastic(p: ffi::ElasticLimitParameters) -> ElasticLimitParameters {
    ElasticLimitParameters {
        target: p.target,
        max: p.max,
        periods: p.periods,
        max_multiplier: p.max_multiplier,
        contract_rate: Ratio {
            numerator: p.contract_rate.numerator,
            denominator: p.contract_rate.denominator,
        },
        expand_rate: Ratio {
            numerator: p.expand_rate.numerator,
            denominator: p.expand_rate.denominator,
        },
    }
}

/// Rebuild the cxx-bridge `ChainConfigV0` from the pure-Rust one for a C++ call.
#[inline]
fn cxx_chain_config(c: &ChainConfigV0) -> ffi::ChainConfigV0 {
    ffi::ChainConfigV0 {
        max_block_net_usage: c.max_block_net_usage,
        target_block_net_usage_pct: c.target_block_net_usage_pct,
        max_transaction_net_usage: c.max_transaction_net_usage,
        base_per_transaction_net_usage: c.base_per_transaction_net_usage,
        net_usage_leeway: c.net_usage_leeway,
        context_free_discount_net_usage_num: c.context_free_discount_net_usage_num,
        context_free_discount_net_usage_den: c.context_free_discount_net_usage_den,
        max_block_cpu_usage: c.max_block_cpu_usage,
        target_block_cpu_usage_pct: c.target_block_cpu_usage_pct,
        max_transaction_cpu_usage: c.max_transaction_cpu_usage,
        min_transaction_cpu_usage: c.min_transaction_cpu_usage,
        max_transaction_lifetime: c.max_transaction_lifetime,
        deferred_trx_expiration_window: c.deferred_trx_expiration_window,
        max_transaction_delay: c.max_transaction_delay,
        max_inline_action_size: c.max_inline_action_size,
        max_inline_action_depth: c.max_inline_action_depth,
        max_authority_depth: c.max_authority_depth,
    }
}

/// Rebuild the cxx-bridge `Authority` from the pure-Rust one for a C++ call. Each
/// native `K1PublicKey` is repacked into a `CxxPublicKey`; the packed bytes are
/// identical, so this is a lossless re-parse (only fails on a corrupt key).
fn cxx_authority(auth: &Authority) -> Result<ffi::Authority, ChainError> {
    let mut keys = Vec::with_capacity(auth.keys.len());
    for k in &auth.keys {
        let key = ffi::parse_public_key_from_bytes(&k.key.to_packed())
            .map_err(|e| ChainError::InternalError(format!("authority key encode: {e}")))?;
        keys.push(ffi::KeyWeight {
            key,
            weight: k.weight,
        });
    }
    let accounts = auth
        .accounts
        .iter()
        .map(|a| ffi::PermissionLevelWeight {
            permission: ffi::PermissionLevel {
                actor: a.permission.actor,
                permission: a.permission.permission,
            },
            weight: a.weight,
        })
        .collect();
    let waits = auth
        .waits
        .iter()
        .map(|w| ffi::WaitWeight {
            wait_sec: w.wait_sec,
            weight: w.weight,
        })
        .collect();
    Ok(ffi::Authority {
        threshold: auth.threshold,
        keys,
        accounts,
        waits,
    })
}

/// The inverse: a bridge `Authority` (read out of chainbase) into the pure-Rust
/// one core consumes.
pub(crate) fn native_authority(auth: &ffi::Authority) -> Result<Authority, ChainError> {
    let mut keys = Vec::with_capacity(auth.keys.len());
    for k in &auth.keys {
        let packed = match k.key.as_ref() {
            Some(pk) => ffi::packed_public_key_bytes(pk),
            None => Vec::new(),
        };
        let key = K1PublicKey::from_packed(&packed)
            .map_err(|e| ChainError::InternalError(format!("authority key decode: {e}")))?;
        keys.push(KeyWeight {
            key,
            weight: k.weight,
        });
    }
    let accounts = auth
        .accounts
        .iter()
        .map(|a| PermissionLevelWeight {
            permission: PermissionLevel {
                actor: a.permission.actor,
                permission: a.permission.permission,
            },
            weight: a.weight,
        })
        .collect();
    let waits = auth
        .waits
        .iter()
        .map(|w| WaitWeight {
            wait_sec: w.wait_sec,
            weight: w.weight,
        })
        .collect();
    Ok(Authority {
        threshold: auth.threshold,
        keys,
        accounts,
        waits,
    })
}

// The pure-Rust authority sub-types back both the arena authority decoder and
// the native<->bridge Authority conversion the chainbase read/write path uses.
use crate::{
    KeyWeight,
    PermissionLevel,
    PermissionLevelWeight,
    WaitWeight,
};
#[cfg(feature = "arena-shadow")]
use pulsevm_billable_size::billable_size_v;
use pulsevm_crypto::k1::K1PublicKey;

/// Field-for-field snapshot of an `account_metadata_object` read back from the
/// arena mirror, matching the chainbase accessors used to diff it.
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

/// Copies a chainbase `digest_type` (sha256) into a fixed 32-byte array for the
/// arena mirror. A digest that is not 32 bytes is zero-padded/truncated, which
/// only degrades the mirror's fidelity, never chainbase.
fn digest_to_array(digest: &CxxDigest) -> [u8; 32] {
    let data = ffi::get_digest_data(digest);
    let mut out = [0u8; 32];
    let n = data.len().min(32);
    out[..n].copy_from_slice(&data[..n]);
    out
}

/// Converts the FFI elastic-limit parameters into the plain form the arena
/// mirror needs to run its own `update_elastic_limit`.
#[cfg(feature = "arena-shadow")]
fn to_elastic_params(p: &ElasticLimitParameters) -> crate::shadow::ElasticParams {
    crate::shadow::ElasticParams {
        target: p.target,
        max: p.max,
        periods: p.periods,
        max_multiplier: p.max_multiplier,
        contract: (p.contract_rate.numerator, p.contract_rate.denominator),
        expand: (p.expand_rate.numerator, p.expand_rate.denominator),
    }
}

/// Reverse of [`to_elastic_params`]: rebuilds the FFI `ElasticLimitParameters`
/// from the arena's plain params, so the resource-limit getters can serve the
/// config off the arena when chainbase is absent.
#[cfg(feature = "arena-shadow")]
fn from_elastic_params(p: &crate::shadow::ElasticParams) -> ElasticLimitParameters {
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

/// Reads the active `chain_config` from a chainbase `CxxChainConfig` into the
/// plain params the arena mirror stores. Only the fields both sides carry (see
/// [`crate::shadow::ChainConfigParams`]).
#[cfg(feature = "arena-shadow")]
fn chain_config_params_from_cxx(c: &ffi::CxxChainConfig) -> crate::shadow::ChainConfigParams {
    crate::shadow::ChainConfigParams {
        max_block_net_usage: c.get_max_block_net_usage(),
        target_block_net_usage_pct: c.get_target_block_net_usage_pct(),
        max_transaction_net_usage: c.get_max_transaction_net_usage(),
        base_per_transaction_net_usage: c.get_base_per_transaction_net_usage(),
        net_usage_leeway: c.get_net_usage_leeway(),
        context_free_discount_net_usage_num: c.get_context_free_discount_net_usage_num(),
        context_free_discount_net_usage_den: c.get_context_free_discount_net_usage_den(),
        max_block_cpu_usage: c.get_max_block_cpu_usage(),
        target_block_cpu_usage_pct: c.get_target_block_cpu_usage_pct(),
        max_transaction_cpu_usage: c.get_max_transaction_cpu_usage(),
        min_transaction_cpu_usage: c.get_min_transaction_cpu_usage(),
        max_transaction_lifetime: c.get_max_transaction_lifetime(),
        max_transaction_delay: c.get_max_transaction_delay(),
        max_inline_action_size: c.get_max_inline_action_size(),
        max_inline_action_depth: c.get_max_inline_action_depth(),
        max_authority_depth: c.get_max_authority_depth(),
    }
}

/// The runtime `chain_config` (as a `ChainConfigV0`) read straight off the
/// chainbase `global_property_object`. `deferred_trx_expiration_window` has no
/// stored field (deferred transactions are unsupported) and no consumer, so it
/// reports 0 — matching the `get_parameters_packed` intrinsic.
fn chain_config_v0_from_cxx(c: &ffi::CxxChainConfig) -> ChainConfigV0 {
    ChainConfigV0 {
        max_block_net_usage: c.get_max_block_net_usage(),
        target_block_net_usage_pct: c.get_target_block_net_usage_pct(),
        max_transaction_net_usage: c.get_max_transaction_net_usage(),
        base_per_transaction_net_usage: c.get_base_per_transaction_net_usage(),
        net_usage_leeway: c.get_net_usage_leeway(),
        context_free_discount_net_usage_num: c.get_context_free_discount_net_usage_num(),
        context_free_discount_net_usage_den: c.get_context_free_discount_net_usage_den(),
        max_block_cpu_usage: c.get_max_block_cpu_usage(),
        target_block_cpu_usage_pct: c.get_target_block_cpu_usage_pct(),
        max_transaction_cpu_usage: c.get_max_transaction_cpu_usage(),
        min_transaction_cpu_usage: c.get_min_transaction_cpu_usage(),
        max_transaction_lifetime: c.get_max_transaction_lifetime(),
        deferred_trx_expiration_window: 0,
        max_transaction_delay: c.get_max_transaction_delay(),
        max_inline_action_size: c.get_max_inline_action_size(),
        max_inline_action_depth: c.get_max_inline_action_depth(),
        max_authority_depth: c.get_max_authority_depth(),
    }
}

/// The runtime `chain_config` rebuilt from the arena's mirrored params — the same
/// 16 fields, `deferred_trx_expiration_window` reported 0 as above. Lets the
/// per-tx/per-block config reads serve off the arena with no chainbase object.
#[cfg(feature = "arena-shadow")]
fn chain_config_v0_from_params(p: &crate::shadow::ChainConfigParams) -> ChainConfigV0 {
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
/// so the mirror updates to exactly what chainbase was handed.
#[cfg(feature = "arena-shadow")]
fn chain_config_params_from_v0(cfg: &ChainConfigV0) -> crate::shadow::ChainConfigParams {
    crate::shadow::ChainConfigParams {
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
/// via `CxxSharedAuthority::to_authority`.
#[cfg(feature = "arena-shadow")]
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
/// mirror stores for `permission_object::auth` (a `shared_authority`). The exact
/// encoding is private to the mirror; it only has to be stable so equal
/// authorities hash equal.
#[cfg(feature = "arena-shadow")]
/// Build an authority blob in the exact [`encode_authority`] layout from plain
/// parts — used by the pure-Rust genesis, which has no FFI `Authority` object.
/// `keys` are `(packed_public_key_bytes, weight)`, `accounts` are
/// `(actor, permission, weight)`, `waits` are `(wait_sec, weight)`.
#[cfg(feature = "arena-shadow")]
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
#[cfg(feature = "arena-shadow")]
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

/// The `(code, scope, table)` triple of a contract table, packed into `u64`s for
/// the arena mirror, which keys its contract-table rows by this triple.
#[cfg(feature = "arena-shadow")]
fn table_key(table: &TableObject) -> (u64, u64, u64) {
    (
        table.get_code().to_uint64_t(),
        table.get_scope().to_uint64_t(),
        table.get_table().to_uint64_t(),
    )
}

#[derive(Clone)]
pub struct Database {
    inner: Arc<RwLock<UniquePtr<ffi::Database>>>,
    /// The directory and size the arena was opened with, kept so a snapshot can
    /// close the mapping, copy `shared_memory.bin`, and remap at the same path
    /// without threading the config back down from the controller.
    path: String,
    size: u64,
    /// The native pulsevm_arena mirror, shared across clones. Carried here so
    /// writes reach it through the same handle every apply/transaction context
    /// already uses (see `shadow.rs`). Only present in arena-shadow builds.
    #[cfg(feature = "arena-shadow")]
    shadow: Option<crate::shadow::ArenaShadow>,
}

/// chainbase's single memory-mapped arena file, relative to the database dir.
const SHARED_MEMORY_FILE: &str = "shared_memory.bin";

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
    pub fn new(path: &str, size: u64) -> Result<Self, String> {
        let db = ffi::open_database(path, ffi::DatabaseOpenFlags::ReadWrite, size);

        if db.is_null() {
            Err("Failed to open database".to_string())
        } else {
            Ok(Database {
                inner: Arc::new(RwLock::new(db)),
                path: path.to_string(),
                size,
                #[cfg(feature = "arena-shadow")]
                shadow: None,
            })
        }
    }

    // ----- arena shadow (differential testing; no-ops without the feature) ---

    /// Attaches a fresh arena mirror at chainbase's current revision. Every
    /// clone of this handle then shares it, so ported writes are mirrored.
    pub fn enable_shadow(&mut self) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        {
            let shadow = crate::shadow::ArenaShadow::new()
                .map_err(|e| ChainError::InternalError(format!("arena shadow init: {e:?}")))?;
            shadow
                .set_revision(self.revision())
                .map_err(|e| ChainError::InternalError(format!("arena set_revision: {e:?}")))?;
            self.shadow = Some(shadow);
        }
        Ok(())
    }

    /// The arena mirror's account_metadata privileged flag for `name`, or
    /// `None` if the mirror has no such row / shadowing is off — for diffing
    /// against chainbase's `find_account_metadata`.
    pub fn arena_account_metadata_privileged(&self, name: u64) -> Option<bool> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_metadata_privileged(name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = name;
            None
        }
    }

    /// Full account_metadata snapshot from the mirror, or `None` when shadowing
    /// is off / the row is absent — for field-for-field diffing against the
    /// chainbase `account_metadata_object` accessors.
    pub fn arena_account_metadata(&self, name: u64) -> Option<ArenaAccountMetadata> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
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
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = name;
            None
        }
    }

    /// Permission snapshot `(parent id, authority threshold)` from the mirror, or
    /// `None` when shadowing is off / the permission is absent — for diffing
    /// against chainbase's `find_permission_by_actor_and_permission`.
    pub fn arena_permission(&self, owner: u64, perm_name: u64) -> Option<(i64, u32)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.permission(owner, perm_name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (owner, perm_name);
            None
        }
    }

    /// The full authority for `(owner, perm_name)` reconstructed from the arena's
    /// stored `shared_authority` blob, or `None` when shadowing is off / the
    /// permission is absent. This is the whole authority the authorization checker
    /// consumes (threshold, keys, accounts, waits), not just the threshold, so it
    /// can eventually replace the chainbase `PermissionObject::get_authority` read.
    #[cfg(feature = "arena-shadow")]
    pub fn arena_permission_authority(&self, owner: u64, perm_name: u64) -> Option<Authority> {
        let blob = self
            .shadow
            .as_ref()
            .and_then(|s| s.permission_auth_blob(owner, perm_name))?;
        decode_authority(&blob).ok()
    }

    /// Every permission of `owner` as `(perm_name, parent_perm_name, authority)`
    /// in `(owner, perm_name)` order, for the RPC account formatter. Empty when
    /// shadowing is off.
    #[cfg(feature = "arena-shadow")]
    pub fn arena_permissions_of(&self, owner: u64) -> Vec<(u64, u64, Authority)> {
        let Some(s) = self.shadow.as_ref() else {
            return Vec::new();
        };
        s.permissions_of(owner)
            .into_iter()
            .filter_map(|(perm_name, parent_name, blob)| {
                decode_authority(&blob)
                    .ok()
                    .map(|auth| (perm_name, parent_name, auth))
            })
            .collect()
    }

    /// Required permission of the mirrored permission_link for `(account, code,
    /// message_type)`, or `None` when shadowing is off / the link is absent — for
    /// diffing against chainbase's `find_permission_link`.
    pub fn arena_permission_link(&self, account: u64, code: u64, message_type: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.permission_link(account, code, message_type))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (account, code, message_type);
            None
        }
    }

    /// Mirrored RAM usage for `account_name`, or `None` when shadowing is off /
    /// the account is absent — for diffing against chainbase's
    /// `get_account_ram_usage`.
    pub fn arena_account_ram_usage(&self, account_name: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_ram_usage(account_name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = account_name;
            None
        }
    }

    /// A contract table's rows as `(primary_key, payer, value)` in primary order,
    /// the read behind the RPC `get_table_rows`. Empty when shadowing is off.
    pub fn arena_table_range_with_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Vec<(u64, u64, Vec<u8>)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.table_range_with_payer(code, scope, table))
                .unwrap_or_default()
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table);
            Vec::new()
        }
    }

    /// An idx64 table's rows as `(secondary_key, primary_key, payer)`, ordered
    /// by secondary then primary. Empty when shadowing is off.
    pub fn arena_idx64_range_with_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Vec<(u64, u64, u64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.idx64_range_with_payer(code, scope, table))
                .unwrap_or_default()
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table);
            Vec::new()
        }
    }

    /// The account's creation-date block-timestamp slot, for the RPC account
    /// formatter's `created` field. `None` when shadowing is off / absent.
    pub fn arena_account_creation_date(&self, account_name: u64) -> Option<u32> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_creation_date(account_name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = account_name;
            None
        }
    }

    /// The account's stored ABI bytes (empty if it has none), for decoding the
    /// contract rows the RPC formatters return. `None` when shadowing is off /
    /// the account is absent.
    pub fn arena_account_abi_bytes(&self, account_name: u64) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_abi_bytes(account_name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = account_name;
            None
        }
    }

    /// The account's `last_code_update` (fc microseconds), for the RPC account
    /// formatter. `None` when shadowing is off / the metadata is absent.
    pub fn arena_account_last_code_update(&self, account_name: u64) -> Option<i64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_last_code_update(account_name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = account_name;
            None
        }
    }

    /// Canonical serialization of chainbase's whole account_metadata table in
    /// by_name order — hash it to get a cross-implementation state root for the
    /// account set.
    pub fn account_metadata_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .account_metadata_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// The arena mirror's canonical account_metadata serialization, or `None`
    /// when shadowing is off — byte-compatible with `account_metadata_state_bytes`
    /// so their hashes match iff the tables hold the same state.
    pub fn arena_account_metadata_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.account_metadata_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    /// Canonical serialization of chainbase's whole account_object table in
    /// by_name order — the account-table counterpart of
    /// `account_metadata_state_bytes`.
    pub fn account_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .account_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// The arena mirror's canonical account_object serialization, or `None` when
    /// shadowing is off.
    pub fn arena_account_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.account_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    /// Canonical serialization of chainbase's whole permission table in
    /// (owner, perm_name) order. The authority is reconstructed from each
    /// permission's `shared_authority` and re-encoded with the same
    /// `encode_authority` the mirror stores, so the two streams match without
    /// reimplementing the encoding in C++. Reserved perm 0 is skipped by the
    /// C++ key enumerator. Gated on the mirror feature since it reuses
    /// `encode_authority`.
    #[cfg(feature = "arena-shadow")]
    pub fn permission_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        let keys = guard
            .permission_keys_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        let mut out = Vec::new();
        for quad in keys.chunks_exact(32) {
            let owner = u64::from_le_bytes(quad[0..8].try_into().unwrap());
            let perm_name = u64::from_le_bytes(quad[8..16].try_into().unwrap());
            let parent = u64::from_le_bytes(quad[16..24].try_into().unwrap());
            let last_used = u64::from_le_bytes(quad[24..32].try_into().unwrap());
            let ptr = guard
                .find_permission_by_actor_and_permission(owner, perm_name)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
            if ptr.is_null() {
                continue;
            }
            // Safe: non-null, read-only, no mutation between the find and read.
            let perm = unsafe { &*ptr };
            let cb_id = perm.get_id() as u64;
            let auth = native_authority(&ffi::get_authority_from_shared_authority(
                perm.get_authority(),
            ))?;
            let auth_bytes = encode_authority(&auth);
            out.extend_from_slice(&owner.to_le_bytes());
            out.extend_from_slice(&perm_name.to_le_bytes());
            out.extend_from_slice(&cb_id.to_le_bytes());
            out.extend_from_slice(&parent.to_le_bytes());
            out.extend_from_slice(&last_used.to_le_bytes());
            out.extend_from_slice(&(auth_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&auth_bytes);
        }
        Ok(out)
    }

    /// The arena mirror's canonical permission serialization, or `None` when
    /// shadowing is off.
    pub fn arena_permission_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.permission_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn permission_link_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .permission_link_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn code_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .code_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn transaction_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .transaction_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn resource_usage_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .resource_usage_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn account_limits_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .account_limits_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn resource_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        // With a Rust genesis chainbase is never initialized, so its singleton
        // getters throw rather than return an empty row. The chainbase side of
        // the cross-impl serialization is unused in that mode (the arena is the
        // sole oracle), so hand back an empty blob instead.
        #[cfg(feature = "arena-shadow")]
        if self.arena_rust_genesis() {
            return Ok(Vec::new());
        }
        let guard = self.locked_read()?;
        guard
            .resource_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// Arena mirror canonical serializations for the remaining tables, `None`
    /// when shadowing is off — each byte-compatible with the chainbase method of
    /// the same name for the cross-impl root.
    pub fn arena_permission_link_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.permission_link_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn arena_code_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.code_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn arena_transaction_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.transaction_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn arena_resource_usage_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.resource_usage_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn arena_account_limits_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.account_limits_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn arena_resource_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.resource_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn contract_table_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .contract_table_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn contract_kv_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .contract_kv_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn arena_contract_table_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.contract_table_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn arena_contract_kv_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.contract_kv_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
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
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.kv_get(code, scope, table, primary_key))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary_key);
            None
        }
    }

    /// Serve a contract-table forward scan from the arena: `(primary_key, value)`
    /// for every row in `(code, scope, table)`, ascending by primary — the order
    /// a contract sees walking db_lowerbound_i64 -> db_next_i64. Empty when the
    /// table is absent or shadowing is off.
    pub fn arena_table_range(&self, code: u64, scope: u64, table: u64) -> Vec<(u64, Vec<u8>)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.table_range(code, scope, table))
                .unwrap_or_default()
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table);
            Vec::new()
        }
    }

    /// Inline read cross-check: confirm the arena would serve `expected` (the
    /// value the node is handing a contract) for `(code, scope, table, primary)`.
    /// No-op when shadowing is off. Tallies match/mismatch; see
    /// `arena_read_crosscheck_counts`.
    pub fn arena_crosscheck_kv(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        expected: &[u8],
    ) {
        #[cfg(feature = "arena-shadow")]
        {
            if let Some(s) = &self.shadow {
                s.crosscheck_kv(code, scope, table, primary, expected);
            }
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary, expected);
        }
    }

    /// Route contract reads through the arena instead of chainbase (the staged
    /// cutover switch). No-op when shadowing is off.
    pub fn enable_arena_reads(&self) {
        #[cfg(feature = "arena-shadow")]
        {
            if let Some(s) = &self.shadow {
                s.enable_reads();
            }
        }
    }

    pub fn arena_reads_enabled(&self) -> bool {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.reads_enabled())
                .unwrap_or(false)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            false
        }
    }

    /// Whether execution should resolve reads entirely from the arena, without
    /// consulting chainbase on the read path (arena-standalone mode). No-op false
    /// when shadowing is off.
    pub fn arena_standalone_reads(&self) -> bool {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.standalone_reads())
                .unwrap_or(false)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            false
        }
    }

    /// Apply writes to the arena only from now on, never touching chainbase. The
    /// arena becomes the authoritative write backend (no live oracle). No-op when
    /// shadowing is off.
    pub fn enable_arena_standalone_writes(&self) {
        #[cfg(feature = "arena-shadow")]
        {
            if let Some(s) = &self.shadow {
                s.enable_standalone_writes();
            }
        }
    }

    /// Whether genesis authors the arena directly instead of running C++ genesis
    /// and hydrating from it. No-op false when shadowing is off.
    pub fn arena_rust_genesis(&self) -> bool {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.rust_genesis())
                .unwrap_or(false)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            false
        }
    }

    /// Whether execution should apply writes to the arena only, skipping the
    /// chainbase write. No-op false when shadowing is off.
    pub fn arena_standalone_writes(&self) -> bool {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.standalone_writes())
                .unwrap_or(false)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            false
        }
    }

    /// (matches, mismatches) tallied by the inline read cross-check, or (0, 0)
    /// when shadowing is off.
    pub fn arena_read_crosscheck_counts(&self) -> (u64, u64) {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.read_crosscheck_counts())
                .unwrap_or((0, 0))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            (0, 0)
        }
    }

    /// Arena iterator positioning: the primary a cursor lands on. `lower_bound` =
    /// first primary >= key, `upper_bound` = first primary > key (also the
    /// db_next successor), `prev` = last primary < key. `None` = off the end.
    /// All return `None` when shadowing is off.
    pub fn arena_kv_lower_bound(&self, code: u64, scope: u64, table: u64, key: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.kv_lower_bound(code, scope, table, key))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, key);
            None
        }
    }

    pub fn arena_kv_table_exists(&self, code: u64, scope: u64, table: u64) -> bool {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.kv_table_exists(code, scope, table))
                .unwrap_or(false)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table);
            false
        }
    }

    pub fn arena_kv_upper_bound(&self, code: u64, scope: u64, table: u64, key: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.kv_upper_bound(code, scope, table, key))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, key);
            None
        }
    }

    pub fn arena_kv_prev(&self, code: u64, scope: u64, table: u64, key: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.kv_prev(code, scope, table, key))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, key);
            None
        }
    }

    /// Largest primary in the table — db_previous_i64's landing when stepping
    /// back from the end iterator. `None` if empty or shadowing is off.
    pub fn arena_kv_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.kv_last(code, scope, table))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table);
            None
        }
    }

    /// Arena idx64 secondary-index positioning, mirroring db_idx64_find_secondary
    /// (primary of the first row with that secondary), db_idx64_lowerbound /
    /// db_idx64_upperbound (`(primary, secondary)` landing), and
    /// db_idx64_find_primary (secondary stored for a primary). All `None` when
    /// shadowing is off.
    pub fn arena_idx64_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx64_find_secondary(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    pub fn arena_idx64_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
    ) -> Option<(u64, u64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx64_lower_bound(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    pub fn arena_idx64_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
    ) -> Option<(u64, u64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx64_upper_bound(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    pub fn arena_idx64_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx64_find_primary(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    /// Secondary-order next/previous/last for idx64 iterator-handle minting:
    /// `(primary, secondary)` of the row after/before the one keyed by `primary`,
    /// and the last row of the table (for previous from an end iterator). `None`
    /// when there is no such row or shadowing is off.
    pub fn arena_idx64_next(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<(u64, u64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx64_next(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    pub fn arena_idx64_previous(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<(u64, u64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx64_previous(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    /// Mirror an idx64 secondary-key update into the arena (the FFI
    /// `update_index64_object` only touches chainbase; the caller resolves the
    /// row's `(code, scope, table, primary)` from the iterator cache).
    pub fn arena_update_index64(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        payer: u64,
        secondary: u64,
    ) {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.update_index64_object(code, scope, table, primary, payer, secondary)
        {
            eprintln!("arena mirror of update_index64_object diverged: {e:?}");
        }
        #[cfg(not(feature = "arena-shadow"))]
        let _ = (code, scope, table, primary, payer, secondary);
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
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.update_index128_object(code, scope, table, primary, payer, secondary)
        {
            eprintln!("arena mirror of update_index128_object diverged: {e:?}");
        }
        #[cfg(not(feature = "arena-shadow"))]
        let _ = (code, scope, table, primary, payer, secondary);
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
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) =
                s.update_index256_object(code, scope, table, primary, payer, secondary.value)
        {
            eprintln!("arena mirror of update_index256_object diverged: {e:?}");
        }
        #[cfg(not(feature = "arena-shadow"))]
        let _ = (code, scope, table, primary, payer, secondary);
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
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) =
                s.update_idx_double_object(code, scope, table, primary, payer, secondary)
        {
            eprintln!("arena mirror of update_idx_double_object diverged: {e:?}");
        }
        #[cfg(not(feature = "arena-shadow"))]
        let _ = (code, scope, table, primary, payer, secondary);
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
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.update_idx_long_double_object(
                code,
                scope,
                table,
                primary,
                payer,
                (secondary.lo, secondary.hi),
            )
        {
            eprintln!("arena mirror of update_idx_long_double_object diverged: {e:?}");
        }
        #[cfg(not(feature = "arena-shadow"))]
        let _ = (code, scope, table, primary, payer, secondary);
    }

    pub fn arena_idx64_last(&self, code: u64, scope: u64, table: u64) -> Option<(u64, u64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx64_last(code, scope, table))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table);
            None
        }
    }

    pub fn arena_idx128_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u128,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx128_find_secondary(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    pub fn arena_idx128_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u128> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx128_find_primary(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    pub fn arena_idx128_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u128,
    ) -> Option<(u64, u128)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx128_lower_bound(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    pub fn arena_idx128_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u128,
    ) -> Option<(u64, u128)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx128_upper_bound(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
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
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().and_then(|s| {
                s.idx_double_find_secondary(code, scope, table, f64::from_bits(secondary_bits))
            })
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary_bits);
            None
        }
    }

    pub fn arena_idx_double_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx_double_find_primary(code, scope, table, primary))
                .map(|f| f.to_bits())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    pub fn arena_idx_double_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary_bits: u64,
    ) -> Option<(u64, u64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| {
                    s.idx_double_lower_bound(code, scope, table, f64::from_bits(secondary_bits))
                })
                .map(|(p, f)| (p, f.to_bits()))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary_bits);
            None
        }
    }

    pub fn arena_idx_double_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary_bits: u64,
    ) -> Option<(u64, u64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| {
                    s.idx_double_upper_bound(code, scope, table, f64::from_bits(secondary_bits))
                })
                .map(|(p, f)| (p, f.to_bits()))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary_bits);
            None
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
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx256_find_secondary(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    pub fn arena_idx256_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<[u8; 32]> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx256_find_primary(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    pub fn arena_idx256_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: [u8; 32],
    ) -> Option<(u64, [u8; 32])> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx256_lower_bound(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    pub fn arena_idx256_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: [u8; 32],
    ) -> Option<(u64, [u8; 32])> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx256_upper_bound(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    // idx_long_double: the intrinsic carries the float128 as (lo, hi) u64 words.
    pub fn arena_idx_long_double_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: (u64, u64),
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx_long_double_find_secondary(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    pub fn arena_idx_long_double_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<(u64, u64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx_long_double_find_primary(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    pub fn arena_idx_long_double_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: (u64, u64),
    ) -> Option<(u64, (u64, u64))> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx_long_double_lower_bound(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    pub fn arena_idx_long_double_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: (u64, u64),
    ) -> Option<(u64, (u64, u64))> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx_long_double_upper_bound(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    /// Secondary-order next/previous/last for iterator-handle minting on the
    /// idx128/256/double/long_double families. `next`/`previous` return the
    /// landing row's primary relative to the row keyed by `primary`; `last`
    /// returns the table's last row (for a `previous` off an end iterator). All
    /// `None` when there is no such row or shadowing is off.
    pub fn arena_idx128_next(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx128_next(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    pub fn arena_idx128_previous(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx128_previous(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    pub fn arena_idx128_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx128_last(code, scope, table))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table);
            None
        }
    }

    pub fn arena_idx256_next(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx256_next(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    pub fn arena_idx256_previous(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx256_previous(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    pub fn arena_idx256_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx256_last(code, scope, table))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table);
            None
        }
    }

    pub fn arena_idx_double_next(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx_double_next(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    pub fn arena_idx_double_previous(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx_double_previous(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    pub fn arena_idx_double_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx_double_last(code, scope, table))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table);
            None
        }
    }

    pub fn arena_idx_long_double_next(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx_long_double_next(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    pub fn arena_idx_long_double_previous(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx_long_double_previous(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    pub fn arena_idx_long_double_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx_long_double_last(code, scope, table))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table);
            None
        }
    }

    /// Tally an iterator-positioning cross-check (arena landing vs chainbase).
    pub fn arena_note_pos(&self, matched: bool) {
        #[cfg(feature = "arena-shadow")]
        {
            if let Some(s) = &self.shadow {
                s.note_pos(matched);
            }
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = matched;
        }
    }

    /// (matches, mismatches) tallied by iterator-positioning cross-checks.
    pub fn arena_pos_crosscheck_counts(&self) -> (u64, u64) {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.pos_crosscheck_counts())
                .unwrap_or((0, 0))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            (0, 0)
        }
    }

    /// Persistence round-trip at the mirror's current (real) state size:
    /// checkpoint the live mirror to `path`, load it into a fresh, empty mirror,
    /// and return `(state_roots_match, checkpoint_bytes)`. A `true` means the
    /// arena survived a full save/load with a byte-identical state root — the
    /// durability the primary store needs. Returns `None` when shadowing is off.
    pub fn arena_persistence_roundtrip(
        &self,
        path: &std::path::Path,
    ) -> Result<Option<(bool, u64)>, ChainError> {
        #[cfg(feature = "arena-shadow")]
        {
            let Some(cur) = &self.shadow else {
                return Ok(None);
            };
            cur.checkpoint(path)
                .map_err(|e| ChainError::InternalError(format!("arena checkpoint: {e:?}")))?;
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let fresh = crate::shadow::ArenaShadow::new()
                .map_err(|e| ChainError::InternalError(format!("arena new: {e:?}")))?;
            fresh
                .load(path)
                .map_err(|e| ChainError::InternalError(format!("arena load: {e:?}")))?;
            Ok(Some((cur.state_root() == fresh.state_root(), size)))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = path;
            Ok(None)
        }
    }

    /// Append the mirror's committed delta since the last flush to the WAL at
    /// `path`. Call once per accepted block for incremental durability. No-op
    /// when shadowing is off.
    pub fn arena_flush_delta(&self, path: &std::path::Path) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        {
            if let Some(s) = &self.shadow {
                s.flush_delta(path)
                    .map_err(|e| ChainError::InternalError(format!("arena flush_delta: {e:?}")))?;
            }
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = path;
        }
        Ok(())
    }

    /// Reconstruct a fresh mirror by replaying the WAL at `path` (no base
    /// checkpoint), and return whether its state root matches the live mirror —
    /// the crash-recovery guarantee for the incremental path. `None` when
    /// shadowing is off.
    pub fn arena_wal_reload_matches(
        &self,
        path: &std::path::Path,
    ) -> Result<Option<bool>, ChainError> {
        #[cfg(feature = "arena-shadow")]
        {
            let Some(cur) = &self.shadow else {
                return Ok(None);
            };
            let fresh = crate::shadow::ArenaShadow::new()
                .map_err(|e| ChainError::InternalError(format!("arena new: {e:?}")))?;
            fresh
                .replay_log(path)
                .map_err(|e| ChainError::InternalError(format!("arena replay_log: {e:?}")))?;
            Ok(Some(cur.state_root() == fresh.state_root()))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = path;
            Ok(None)
        }
    }

    /// Simulate a node restart: checkpoint the live mirror to `path`, then
    /// rebuild it in place from that checkpoint. After this the shadow holds
    /// reloaded-from-disk state (same object, restored revision) and keeps
    /// serving — so the caller can carry on applying blocks and confirm the
    /// mirror stays in lockstep with chainbase across the restart. `Ok(false)`
    /// when shadowing is off.
    pub fn arena_restart(&self, path: &std::path::Path) -> Result<bool, ChainError> {
        #[cfg(feature = "arena-shadow")]
        {
            let Some(cur) = &self.shadow else {
                return Ok(false);
            };
            cur.checkpoint(path)
                .map_err(|e| ChainError::InternalError(format!("arena checkpoint: {e:?}")))?;
            cur.reload_from(path)
                .map_err(|e| ChainError::InternalError(format!("arena reload: {e:?}")))?;
            Ok(true)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = path;
            Ok(false)
        }
    }

    /// (matches, mismatches) tallied by non-contract read cross-checks
    /// (accounts/permissions read during authorization and dispatch).
    pub fn arena_noncontract_crosscheck_counts(&self) -> (u64, u64) {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.noncontract_crosscheck_counts())
                .unwrap_or((0, 0))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            (0, 0)
        }
    }

    /// Whether the arena mirror holds an account_object for `name` — for diffing
    /// against chainbase's `find_account`.
    pub fn arena_account_exists(&self, name: u64) -> bool {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.account_exists(name))
                .unwrap_or(false)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = name;
            false
        }
    }

    /// State root of the mirrored subset, or `None` when shadowing is off. Only
    /// ported tables contribute, so it is comparable to chainbase for those.
    pub fn arena_state_root(&self) -> Option<[u8; 32]> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.state_root())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    /// Arena undo-session lifecycle, driven by the controller in lockstep with
    /// the chainbase session boundaries.
    pub fn arena_start_undo_session(&self) {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.start_undo_session();
        }
    }
    pub fn arena_squash(&self) {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.squash();
        }
    }
    pub fn arena_undo(&self) {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.undo();
        }
    }
    pub fn arena_commit(&self, revision: i64) {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.commit(revision);
        }
        #[cfg(not(feature = "arena-shadow"))]
        let _ = revision;
    }

    // Replace the inner database with null to call the destructors
    pub fn close(&self) -> Result<(), ChainError> {
        let mut db = self.locked_write()?;
        *db = UniquePtr::<ffi::Database>::null();
        Ok(())
    }

    /// Capture a physical snapshot of the current arena, wrapped in the
    /// transport envelope (see `snapshot`).
    ///
    /// There is no live msync in chainbase, so the only way to read a
    /// self-consistent `shared_memory.bin` is to drop the mapping first: the
    /// destructor flushes dirty pages and clears the on-disk dirty flag. We then
    /// read the clean file and remap exactly as a restart would. The write lock
    /// is held across the whole window, so no other thread ever observes the
    /// database in its momentarily-closed state, and we always remap — even if
    /// the read fails — so a snapshot error never leaves the node with a closed
    /// database.
    ///
    /// Call this only at a quiescent point (no open undo session): the copy
    /// reflects whatever is committed to the arena at that instant.
    pub fn snapshot_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let mut guard = self.locked_write()?;
        if guard.is_null() {
            return Err(ChainError::InternalError(
                "snapshot: database is not open".into(),
            ));
        }
        let revision = guard.revision();

        // Tear the mapping down: flushes and clears the dirty flag on disk.
        *guard = UniquePtr::<ffi::Database>::null();

        let file = Path::new(&self.path).join(SHARED_MEMORY_FILE);
        let snapshot = Self::read_sparse_snapshot(&file, revision);

        // Remap before propagating any read error, so the database is never
        // left closed behind us.
        let mut db = ffi::open_database(&self.path, ffi::DatabaseOpenFlags::ReadWrite, self.size);
        if db.is_null() {
            return Err(ChainError::InternalError(
                "snapshot: failed to reopen database after copy".into(),
            ));
        }
        db.pin_mut().add_indices();
        *guard = db;

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
        // Validate and locate the payload before touching the running database.
        let (header, payload) = crate::snapshot::decode(snapshot)?;

        let dir = Path::new(&self.path);
        let dest = dir.join(SHARED_MEMORY_FILE);
        let staged = dir.join("shared_memory.bin.restore-tmp");
        Self::write_sparse_snapshot(&staged, payload)?;

        let mut guard = self.locked_write()?;
        if guard.is_null() {
            let _ = fs::remove_file(&staged);
            return Err(ChainError::InternalError(
                "restore: database is not open".into(),
            ));
        }

        // Close the mapping so the backing file can be replaced, then swap the
        // staged snapshot in atomically.
        *guard = UniquePtr::<ffi::Database>::null();
        let swap = fs::rename(&staged, &dest);

        // Remap before propagating any error, so the database is never left
        // closed. On a failed swap the original file is untouched, so this
        // reopens the pre-restore state.
        let mut db = ffi::open_database(&self.path, ffi::DatabaseOpenFlags::ReadWrite, self.size);
        if db.is_null() {
            return Err(ChainError::InternalError(
                "restore: failed to reopen database".into(),
            ));
        }
        db.pin_mut().add_indices();
        *guard = db;

        swap.map_err(|e| {
            ChainError::InternalError(format!("restore: swap into {}: {e}", dest.display()))
        })?;
        Ok(header)
    }

    pub fn commit(&mut self, revision: i64) -> Result<(), ChainError> {
        self.inner
            .write()?
            .pin_mut()
            .commit(revision)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn undo(&mut self) -> Result<(), ChainError> {
        self.inner
            .write()?
            .pin_mut()
            .undo()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn revision(&self) -> i64 {
        self.locked_read().unwrap().revision()
    }

    pub fn set_revision(&mut self, revision: i64) -> Result<(), ChainError> {
        self.inner
            .write()?
            .pin_mut()
            .set_revision(revision)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn add_indices(&mut self) -> Result<(), ChainError> {
        self.locked_write()?.pin_mut().add_indices();
        Ok(())
    }

    #[cfg_attr(not(feature = "arena-shadow"), allow(unused_variables))]
    pub fn initialize_database(
        &mut self,
        genesis: &CxxGenesisState,
        rust_genesis: &pulsevm_chain_types::GenesisState,
    ) -> Result<(), ChainError> {
        // Pure-Rust genesis: author the arena directly and never touch chainbase —
        // the last chainbase write removed. Gated while it is validated against
        // block-1 golden roots (see `initialize_genesis_arena`).
        #[cfg(feature = "arena-shadow")]
        if self.arena_rust_genesis() {
            return self.initialize_genesis_arena(rust_genesis);
        }
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .initialize_database(genesis)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        // Genesis creates the resource_limits state singleton inside C++, out of
        // reach of the per-write mirror hooks, so seed the mirror's copy here
        // with the same slow-start virtual limits (each resource's max).
        #[cfg(feature = "arena-shadow")]
        if self.shadow.is_some() {
            match (
                self.chainbase_cpu_limit_parameters(),
                self.chainbase_net_limit_parameters(),
            ) {
                (Ok(cpu), Ok(net)) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.initialize_resource_state(cpu.max, net.max)
                    {
                        eprintln!("arena mirror of resource state init diverged: {e:?}");
                    }
                }
                _ => eprintln!("arena mirror could not read limit parameters at init"),
            }
            // Genesis creates its native accounts inside C++, below the mirror
            // hooks, so seed their account_metadata into the mirror from
            // chainbase once here. Later accounts flow through the live path.
            match self.account_metadata_state_bytes() {
                Ok(bytes) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.hydrate_account_metadata(&bytes)
                    {
                        eprintln!("arena mirror could not hydrate genesis account_metadata: {e:?}");
                    }
                }
                Err(e) => eprintln!("arena mirror could not read genesis account_metadata: {e:?}"),
            }
            match self.account_state_bytes() {
                Ok(bytes) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.hydrate_accounts(&bytes)
                    {
                        eprintln!("arena mirror could not hydrate genesis accounts: {e:?}");
                    }
                }
                Err(e) => eprintln!("arena mirror could not read genesis accounts: {e:?}"),
            }
            match self.permission_state_bytes() {
                Ok(bytes) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.hydrate_permissions(&bytes)
                    {
                        eprintln!("arena mirror could not hydrate genesis permissions: {e:?}");
                    }
                }
                Err(e) => eprintln!("arena mirror could not read genesis permissions: {e:?}"),
            }
            // Genesis native accounts get resource_usage (billed ram) and
            // resource_limits rows inside create_native_account; seed them.
            match self.resource_usage_state_bytes() {
                Ok(bytes) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.hydrate_resource_usage(&bytes)
                    {
                        eprintln!("arena mirror could not hydrate genesis resource_usage: {e:?}");
                    }
                }
                Err(e) => eprintln!("arena mirror could not read genesis resource_usage: {e:?}"),
            }
            match self.account_limits_state_bytes() {
                Ok(bytes) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.hydrate_account_limits(&bytes)
                    {
                        eprintln!("arena mirror could not hydrate genesis resource_limits: {e:?}");
                    }
                }
                Err(e) => eprintln!("arena mirror could not read genesis resource_limits: {e:?}"),
            }
            // Genesis creates the static global_property_object (chain_config) in
            // C++, below the mirror hooks; seed it once from chainbase. Later
            // setparams calls flow through the live path.
            match self.read_chain_config_params() {
                Ok(params) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.set_global_properties(params)
                    {
                        eprintln!("arena mirror could not seed genesis global_property: {e:?}");
                    }
                }
                Err(e) => eprintln!("arena mirror could not read genesis global_property: {e:?}"),
            }
            // Genesis creates resource_limits_config_object (elastic cpu/net params
            // + averaging windows) in C++; seed it once from chainbase. Later
            // set_block_parameters updates the elastic params in lockstep.
            match (
                self.chainbase_cpu_limit_parameters(),
                self.chainbase_net_limit_parameters(),
                self.chainbase_account_cpu_usage_average_window(),
                self.chainbase_account_net_usage_average_window(),
            ) {
                (Ok(cpu), Ok(net), Ok(cpu_w), Ok(net_w)) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.seed_resource_config(
                            to_elastic_params(&cpu),
                            to_elastic_params(&net),
                            cpu_w,
                            net_w,
                        )
                    {
                        eprintln!("arena mirror could not seed genesis resource_config: {e:?}");
                    }
                }
                _ => eprintln!("arena mirror could not read genesis resource_config params"),
            }
        }
        Ok(())
    }

    /// Author the entire genesis state directly on the arena, reproducing C++
    /// `initialize_database` (database.cpp) without a chainbase bootstrap. Every
    /// value is derived from the genesis state or from the fixed genesis
    /// constants, and the whole thing is pinned by the block-1 golden roots.
    #[cfg(feature = "arena-shadow")]
    fn initialize_genesis_arena(
        &self,
        genesis: &pulsevm_chain_types::GenesisState,
    ) -> Result<(), ChainError> {
        use crate::shadow::ElasticParams;

        let s = self.shadow_ref()?;

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
    #[cfg(feature = "arena-shadow")]
    fn genesis_permission(
        &self,
        owner: u64,
        perm_name: u64,
        parent_cb_id: i64,
        auth_blob: &[u8],
        ts_us: i64,
    ) -> Result<i64, ChainError> {
        let s = self.shadow_ref()?;
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
    #[cfg(feature = "arena-shadow")]
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
        let s = self.shadow_ref()?;
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
            + 2 * billable_size_v::<ffi::PermissionObject>() as i64
            + authority_blob_billable_size(owner_auth).unwrap_or(0)
            + authority_blob_billable_size(active_auth).unwrap_or(0);
        s.add_pending_ram_usage(name, ram_delta)
            .map_err(|e| ChainError::InternalError(format!("genesis ram: {e:?}")))?;
        // verify_account_ram_usage is a no-op under standalone writes.
        Ok(active_id)
    }

    pub fn create_account(
        &mut self,
        account_name: u64,
        creation_date: u32,
    ) -> Result<*const ffi::AccountObject, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            // Arena is authoritative: apply the write there and skip chainbase.
            // The caller discards the returned pointer, so null is fine.
            s.create_account(account_name, creation_date).map_err(|e| {
                ChainError::InternalError(format!("arena create_account {account_name}: {e:?}"))
            })?;
            return Ok(std::ptr::null());
        }
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_account(account_name, creation_date)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const ffi::AccountObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_account(account_name, creation_date)
        {
            eprintln!("arena mirror of account {account_name} diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn find_account(&self, account_name: u64) -> Result<*const ffi::AccountObject, ChainError> {
        let guard = self.locked_read()?;
        let account = guard
            .find_account(account_name)
            .map_err(|e| ChainError::InternalError(format!("failed to get account: {}", e)))?;

        Ok(account)
    }

    /// Whether `account_name` exists, decided under the read guard so no pointer
    /// escapes the lock. Prefer this to `find_account(..).is_null()` at call sites
    /// that only need existence.
    pub fn account_exists(&self, account_name: u64) -> Result<bool, ChainError> {
        Ok(self.read()?.find_account(account_name)?.is_some())
    }

    pub fn get_account(
        &self,
        account_name: u64,
    ) -> Result<&'static ffi::AccountObject, ChainError> {
        let guard = self.locked_read()?;
        let account = guard
            .find_account(account_name)
            .map_err(|e| ChainError::InternalError(format!("failed to get account: {}", e)))?;

        if account.is_null() {
            return Err(ChainError::InternalError(format!(
                "account not found: {}",
                account_name
            )));
        }

        Ok(unsafe { &*account })
    }

    pub fn create_account_metadata(
        &mut self,
        account_name: u64,
        is_privileged: bool,
    ) -> Result<*const ffi::AccountMetadataObject, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            s.create_account_metadata(account_name, is_privileged)
                .map_err(|e| {
                    ChainError::InternalError(format!("arena create_account_metadata: {e:?}"))
                })?;
            return Ok(std::ptr::null());
        }
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_account_metadata(account_name, is_privileged)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const ffi::AccountMetadataObject
        };
        // Mirror after releasing the chainbase lock, so the two locks are never
        // held at once. Chainbase is authoritative; a mirror error is logged.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_account_metadata(account_name, is_privileged)
        {
            eprintln!("arena mirror of account_metadata {account_name} diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn find_account_metadata(
        &self,
        account_name: u64,
    ) -> Result<*const ffi::AccountMetadataObject, ChainError> {
        let guard = self.locked_read()?;

        guard.find_account_metadata(account_name).map_err(|e| {
            ChainError::InternalError(format!("failed to find account metadata: {}", e))
        })
    }

    pub fn set_privileged(&mut self, account: u64, is_privileged: bool) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            return s.set_privileged(account, is_privileged).map_err(|e| {
                ChainError::InternalError(format!("arena set_privileged {account}: {e:?}"))
            });
        }
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .set_privileged(account, is_privileged)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.set_privileged(account, is_privileged)
        {
            eprintln!("arena mirror of set_privileged {account} diverged: {e:?}");
        }
        Ok(())
    }

    pub fn get_account_metadata(
        &self,
        account_name: u64,
    ) -> Result<&'static ffi::AccountMetadataObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard.find_account_metadata(account_name).map_err(|e| {
            ChainError::InternalError(format!("failed to find account metadata: {}", e))
        })?;

        if res.is_null() {
            return Err(ChainError::InternalError(format!(
                "account metadata not found for account: {}",
                account_name
            )));
        }

        Ok(unsafe { &*res })
    }

    /// Decrement the code_object refcount for `(code_hash, vm_type, vm_version)`.
    /// Takes the hash and vm fields, not a chainbase `&CodeObject`: the object is
    /// re-found and unlinked inside the write scope, so setcode no longer holds a
    /// database reference across the update that follows.
    pub fn unlink_account_code(
        &mut self,
        code_hash: &CxxDigest,
        vm_type: u8,
        vm_version: u8,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let hash = digest_to_array(code_hash);
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            return s.unlink_account_code(hash).map_err(|e| {
                ChainError::InternalError(format!("arena unlink_account_code: {e:?}"))
            });
        }
        {
            let mut guard = self.locked_write()?;
            // Resolve the code object under this guard, then drop the borrow to a
            // raw pointer so its reference is confined to the C++ call rather than
            // passed in by the caller.
            let obj_ptr: *const ffi::CodeObject = {
                let obj = guard
                    .get_code_object_by_hash(code_hash, vm_type, vm_version)
                    .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))?;
                obj as *const ffi::CodeObject
            };
            guard
                .pin_mut()
                .unlink_account_code(unsafe { &*obj_ptr })
                .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.unlink_account_code(hash)
        {
            eprintln!("arena mirror of unlink_account_code diverged: {e:?}");
        }
        Ok(())
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
        code_hash: &CxxDigest,
        vm_type: u8,
        vm_version: u8,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            return s
                .update_account_code(
                    account_name,
                    new_code,
                    digest_to_array(code_hash),
                    head_block_num,
                    pending_block_time.time_since_epoch().count(),
                    vm_type,
                    vm_version,
                )
                .map_err(|e| {
                    ChainError::InternalError(format!("arena update_account_code: {e:?}"))
                });
        }
        {
            let mut guard = self.locked_write()?;
            let obj = guard
                .find_account_metadata(account_name)
                .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))?;
            if obj.is_null() {
                return Err(ChainError::ActionValidationError(format!(
                    "account metadata not found for account: {}",
                    account_name
                )));
            }
            guard
                .pin_mut()
                .update_account_code(
                    unsafe { &*obj },
                    new_code,
                    head_block_num,
                    &cxx_time_point(pending_block_time),
                    code_hash,
                    vm_type,
                    vm_version,
                )
                .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let hash = digest_to_array(code_hash);
            if let Err(e) = s.update_account_code(
                account_name,
                new_code,
                hash,
                head_block_num,
                pending_block_time.time_since_epoch().count(),
                vm_type,
                vm_version,
            ) {
                eprintln!("arena mirror of update_account_code diverged: {e:?}");
            }
        }
        Ok(())
    }

    pub fn update_account_abi(&mut self, account_name: u64, abi: &[u8]) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            return s.update_account_abi(account_name, abi).map_err(|e| {
                ChainError::InternalError(format!("arena update_account_abi: {e:?}"))
            });
        }
        {
            let mut guard = self.locked_write()?;
            let account = guard
                .find_account(account_name)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
            let account_metadata = guard
                .find_account_metadata(account_name)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
            if account.is_null() || account_metadata.is_null() {
                return Err(ChainError::InternalError(format!(
                    "account not found: {}",
                    account_name
                )));
            }
            guard
                .pin_mut()
                .update_account_abi(unsafe { &*account }, unsafe { &*account_metadata }, abi)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.update_account_abi(account_name, abi)
        {
            eprintln!("arena mirror of update_account_abi diverged: {e:?}");
        }
        Ok(())
    }

    pub fn create_undo_session(
        &mut self,
        enabled: bool,
    ) -> Result<cxx::UniquePtr<ffi::UndoSession>, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .create_undo_session(enabled)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn initialize_resource_limits(&mut self) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .initialize_resource_limits()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn initialize_account_resource_limits(
        &mut self,
        account_name: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            return s
                .initialize_account_resource_limits(account_name)
                .map_err(|e| {
                    ChainError::InternalError(format!(
                        "arena initialize_account_resource_limits: {e:?}"
                    ))
                });
        }
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .initialize_account_resource_limits(account_name)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.initialize_account_resource_limits(account_name)
        {
            eprintln!("arena mirror of initialize_account_resource_limits diverged: {e:?}");
        }
        Ok(())
    }

    pub fn update_account_usage(
        &mut self,
        account: &Name,
        time_slot: u32,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            let _ = s;
            self.mirror_account_usage(account.as_u64(), 0, 0, time_slot);
            return Ok(());
        }
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .update_account_usage(account.as_u64(), time_slot)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        self.mirror_account_usage(account.as_u64(), 0, 0, time_slot);
        Ok(())
    }

    pub fn add_transaction_usage(
        &mut self,
        account: &Name,
        cpu_usage: u64,
        net_usage: u64,
        time_slot: u32,
        validate: bool,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            let _ = s;
            self.mirror_account_usage(account.as_u64(), cpu_usage, net_usage, time_slot);
            return Ok(());
        }
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .add_transaction_usage(account.as_u64(), cpu_usage, net_usage, time_slot, validate)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        self.mirror_account_usage(account.as_u64(), cpu_usage, net_usage, time_slot);
        Ok(())
    }

    /// Replays a net/cpu usage advance onto the arena mirror, pulling the average
    /// windows from chainbase config so the accumulator decay matches. Best
    /// effort: a divergence is logged, never propagated.
    #[cfg(feature = "arena-shadow")]
    fn mirror_account_usage(&self, account: u64, cpu_usage: u64, net_usage: u64, time_slot: u32) {
        if self.shadow.is_none() {
            return;
        }
        let windows = self.get_account_net_usage_average_window().and_then(|nw| {
            self.get_account_cpu_usage_average_window()
                .map(|cw| (nw, cw))
        });
        let (net_window, cpu_window) = match windows {
            Ok(w) => w,
            Err(e) => {
                eprintln!("arena mirror could not read usage windows: {e:?}");
                return;
            }
        };
        if let Some(s) = &self.shadow {
            if let Err(e) = s.add_transaction_usage(
                account, cpu_usage, net_usage, time_slot, net_window, cpu_window,
            ) {
                eprintln!("arena mirror of add_transaction_usage diverged: {e:?}");
            }
            // The same call also folds the usage into the block's pending totals
            // on the state singleton (the block-accounting half in chainbase).
            if let Err(e) = s.add_block_usage(cpu_usage, net_usage) {
                eprintln!("arena mirror of block usage diverged: {e:?}");
            }
        }
    }

    pub fn add_pending_ram_usage(
        &mut self,
        account_name: u64,
        ram_bytes: i64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            return s
                .add_pending_ram_usage(account_name, ram_bytes)
                .map_err(|e| {
                    ChainError::InternalError(format!("arena add_pending_ram_usage: {e:?}"))
                });
        }
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .add_pending_ram_usage(account_name, ram_bytes)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.add_pending_ram_usage(account_name, ram_bytes)
        {
            eprintln!("arena mirror of add_pending_ram_usage diverged: {e:?}");
        }
        Ok(())
    }

    pub fn verify_account_ram_usage(&mut self, account_name: u64) -> Result<(), ChainError> {
        // A read-only check that chainbase resolves against its own rows. Under
        // standalone writes chainbase holds no post-genesis state, so the check
        // can't run there; the arena's own limit enforcement will cover it once
        // ported. Skipping is sound for replaying already-valid history.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            let _ = (s, account_name);
            return Ok(());
        }
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .verify_account_ram_usage(account_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_ram_usage(&self, account_name: u64) -> Result<i64, ChainError> {
        let guard = self.locked_read()?;

        guard
            .get_account_ram_usage(account_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_net_usage_average_window(&self) -> Result<u32, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s
                .usage_average_windows()
                .map(|(net, _cpu)| net)
                .ok_or_else(|| ChainError::InternalError("resource config not found".into()));
        }
        let guard = self.locked_read()?;
        guard
            .get_account_net_usage_average_window()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_cpu_usage_average_window(&self) -> Result<u32, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s
                .usage_average_windows()
                .map(|(_net, cpu)| cpu)
                .ok_or_else(|| ChainError::InternalError("resource config not found".into()));
        }
        let guard = self.locked_read()?;
        guard
            .get_account_cpu_usage_average_window()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_net_usage_value_ex(&self, account_name: u64) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_account_net_usage_value_ex(account_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_cpu_usage_value_ex(&self, account_name: u64) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_account_cpu_usage_value_ex(account_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// Mirrored net/cpu usage `value_ex` for `account_name`, or `None` when
    /// shadowing is off / the account is absent — for diffing against chainbase.
    pub fn arena_account_net_usage_value_ex(&self, account_name: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_net_usage_value_ex(account_name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = account_name;
            None
        }
    }

    pub fn arena_account_cpu_usage_value_ex(&self, account_name: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_cpu_usage_value_ex(account_name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = account_name;
            None
        }
    }

    pub fn get_virtual_cpu_limit(&self) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_virtual_cpu_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_virtual_net_limit(&self) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_virtual_net_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_cpu_limit_parameters(&self) -> Result<ElasticLimitParameters, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s
                .resource_config_elastic()
                .map(|(cpu, _net)| from_elastic_params(&cpu))
                .ok_or_else(|| ChainError::InternalError("resource config not found".into()));
        }
        let guard = self.locked_read()?;
        guard
            .get_cpu_limit_parameters()
            .map(native_elastic)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_net_limit_parameters(&self) -> Result<ElasticLimitParameters, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s
                .resource_config_elastic()
                .map(|(_cpu, net)| from_elastic_params(&net))
                .ok_or_else(|| ChainError::InternalError("resource config not found".into()));
        }
        let guard = self.locked_read()?;
        guard
            .get_net_limit_parameters()
            .map(native_elastic)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// Chainbase-direct reads of the resource-limits config, bypassing the
    /// standalone arena inversion in the public getters. Used only by the
    /// genesis-time mirror seeding, which copies the freshly-built chainbase
    /// config *into* the arena — the arena isn't populated yet, so the public
    /// getters (which would read the arena under standalone_reads) must not be
    /// used there.
    #[cfg(feature = "arena-shadow")]
    fn chainbase_cpu_limit_parameters(&self) -> Result<ElasticLimitParameters, ChainError> {
        let guard = self.inner.read()?;
        guard
            .get_cpu_limit_parameters()
            .map(native_elastic)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    #[cfg(feature = "arena-shadow")]
    fn chainbase_net_limit_parameters(&self) -> Result<ElasticLimitParameters, ChainError> {
        let guard = self.inner.read()?;
        guard
            .get_net_limit_parameters()
            .map(native_elastic)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    #[cfg(feature = "arena-shadow")]
    fn chainbase_account_cpu_usage_average_window(&self) -> Result<u32, ChainError> {
        let guard = self.inner.read()?;
        guard
            .get_account_cpu_usage_average_window()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    #[cfg(feature = "arena-shadow")]
    fn chainbase_account_net_usage_average_window(&self) -> Result<u32, ChainError> {
        let guard = self.inner.read()?;
        guard
            .get_account_net_usage_average_window()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// Mirrored `(virtual_cpu_limit, virtual_net_limit)`, or `None` when
    /// shadowing is off / the state row is absent — for diffing against
    /// chainbase's `get_virtual_cpu_limit`/`get_virtual_net_limit`.
    pub fn arena_virtual_limits(&self) -> Option<(u64, u64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().and_then(|s| s.state_virtual_limits())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn set_account_limits(
        &mut self,
        account_name: u64,
        ram_bytes: i64,
        net_weight: i64,
        cpu_weight: i64,
    ) -> Result<bool, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            // Compute the "ram limit decreased" flag from the pre-write limit, as
            // chainbase does, before applying the arena write.
            let old_ram = s
                .account_limits(account_name)
                .map(|(r, _, _)| r)
                .unwrap_or(-1);
            s.set_account_limits(account_name, ram_bytes, net_weight, cpu_weight)
                .map_err(|e| {
                    ChainError::InternalError(format!("arena set_account_limits: {e:?}"))
                })?;
            let decreased = ram_bytes >= 0 && (old_ram < 0 || ram_bytes < old_ram);
            return Ok(decreased);
        }
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .set_account_limits(account_name, ram_bytes, net_weight, cpu_weight)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.set_account_limits(account_name, ram_bytes, net_weight, cpu_weight)
        {
            eprintln!("arena mirror of set_account_limits diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn get_account_limits(
        &self,
        account_name: u64,
        ram_bytes: &mut i64,
        net_weight: &mut i64,
        cpu_weight: &mut i64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            let (r, n, c) = s.account_limits(account_name).ok_or_else(|| {
                ChainError::InternalError(format!("resource limits not found: {account_name}"))
            })?;
            *ram_bytes = r;
            *net_weight = n;
            *cpu_weight = c;
            return Ok(());
        }
        let guard = self.locked_read()?;

        guard
            .get_account_limits(account_name, ram_bytes, net_weight, cpu_weight)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_total_cpu_weight(&self) -> Result<u64, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s
                .state_total_weights()
                .map(|(cpu, _net)| cpu)
                .ok_or_else(|| ChainError::InternalError("resource state not found".into()));
        }
        let guard = self.locked_read()?;

        guard
            .get_total_cpu_weight()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_total_net_weight(&self) -> Result<u64, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s
                .state_total_weights()
                .map(|(_cpu, net)| net)
                .ok_or_else(|| ChainError::InternalError("resource state not found".into()));
        }
        let guard = self.locked_read()?;

        guard
            .get_total_net_weight()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_net_limit(
        &self,
        name: u64,
        greylist_limit: u32,
    ) -> Result<ffi::NetLimitResult, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            let (limit, greylisted) =
                s.account_net_limit(name, greylist_limit).ok_or_else(|| {
                    ChainError::InternalError(format!("resource state not found for {name}"))
                })?;
            return Ok(ffi::NetLimitResult { limit, greylisted });
        }
        let guard = self.locked_read()?;

        guard
            .get_account_net_limit(name, greylist_limit)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_cpu_limit(
        &self,
        name: u64,
        greylist_limit: u32,
    ) -> Result<ffi::CpuLimitResult, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            let (limit, greylisted) =
                s.account_cpu_limit(name, greylist_limit).ok_or_else(|| {
                    ChainError::InternalError(format!("resource state not found for {name}"))
                })?;
            return Ok(ffi::CpuLimitResult { limit, greylisted });
        }
        let guard = self.locked_read()?;

        guard
            .get_account_cpu_limit(name, greylist_limit)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn process_account_limit_updates(&mut self) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            return s.process_account_limit_updates().map_err(|e| {
                ChainError::InternalError(format!("arena process_account_limit_updates: {e:?}"))
            });
        }
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .process_account_limit_updates()
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.process_account_limit_updates()
        {
            eprintln!("arena mirror of process_account_limit_updates diverged: {e:?}");
        }
        Ok(())
    }

    /// Mirrored effective limits `(ram_bytes, net_weight, cpu_weight)` for
    /// `account_name`, or `None` when shadowing is off / the account is absent —
    /// for diffing against chainbase's `get_account_limits`.
    pub fn arena_account_limits(&self, account_name: u64) -> Option<(i64, i64, i64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_limits(account_name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = account_name;
            None
        }
    }

    pub fn set_block_parameters(
        &mut self,
        cpu_limit_parameters: &ElasticLimitParameters,
        net_limit_parameters: &ElasticLimitParameters,
    ) -> Result<(), ChainError> {
        // Chainbase-free (standalone writes / Rust genesis): the resource-state
        // read and write paths are all arena-served now, so update the arena
        // config alone and skip the chainbase write.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.rust_genesis()
        {
            return s
                .set_block_parameters(
                    to_elastic_params(cpu_limit_parameters),
                    to_elastic_params(net_limit_parameters),
                )
                .map_err(|e| {
                    ChainError::InternalError(format!("arena set_block_parameters: {e:?}"))
                });
        }
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();

            pinned
                .set_block_parameters(
                    &cxx_elastic(cpu_limit_parameters),
                    &cxx_elastic(net_limit_parameters),
                )
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }

        // Mirror the elastic cpu/net params into the arena resource_limits_config
        // (the averaging windows are genesis constants, left as seeded).
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.set_block_parameters(
                to_elastic_params(cpu_limit_parameters),
                to_elastic_params(net_limit_parameters),
            )
        {
            eprintln!("arena mirror of set_block_parameters diverged: {e:?}");
        }

        Ok(())
    }

    /// Canonical serialization of the chainbase `resource_limits_config_object` —
    /// byte-compatible with the arena mirror's `resource_config_state_bytes`.
    #[cfg(feature = "arena-shadow")]
    pub fn resource_config_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        // Chainbase absent under a Rust genesis; its side of the cross-impl
        // serialization is unused there (see resource_state_bytes).
        if self.arena_rust_genesis() {
            return Ok(Vec::new());
        }
        let cpu = to_elastic_params(&self.chainbase_cpu_limit_parameters()?);
        let net = to_elastic_params(&self.chainbase_net_limit_parameters()?);
        let cpu_window = self.chainbase_account_cpu_usage_average_window()?;
        let net_window = self.chainbase_account_net_usage_average_window()?;
        Ok(crate::shadow::serialize_resource_config(
            &cpu, &net, cpu_window, net_window,
        ))
    }

    /// Arena mirror of resource_limits_config, `None` when shadowing is off.
    pub fn arena_resource_config_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.resource_config_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn process_block_usage(&mut self, block_num: u32) -> Result<(), ChainError> {
        // Chainbase absent: fold the block usage on the arena alone, sourcing the
        // elastic params from the arena config rather than the (empty) chainbase.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            let (cpu, net) = s.resource_config_elastic().ok_or_else(|| {
                ChainError::InternalError("resource config not found for block usage".into())
            })?;
            return s.process_block_usage(block_num, cpu, net).map_err(|e| {
                ChainError::InternalError(format!("arena process_block_usage: {e:?}"))
            });
        }
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .process_block_usage(block_num)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if self.shadow.is_some() {
            match (
                self.get_cpu_limit_parameters(),
                self.get_net_limit_parameters(),
            ) {
                (Ok(cpu), Ok(net)) => {
                    let (cpu, net) = (to_elastic_params(&cpu), to_elastic_params(&net));
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.process_block_usage(block_num, cpu, net)
                    {
                        eprintln!("arena mirror of process_block_usage diverged: {e:?}");
                    }
                }
                _ => eprintln!("arena mirror could not read limit parameters for block usage"),
            }
        }
        Ok(())
    }

    pub fn find_table(
        &self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<*const TableObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .find_table(code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn get_table(
        &self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<*const TableObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .find_table(code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        if res.is_null() {
            return Err(ChainError::InternalError(format!(
                "table not found for code: {} scope: {} table: {}",
                code, scope, table
            )));
        }

        Ok(res)
    }

    pub fn create_table(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
    ) -> Result<*const TableObject, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_table(code, scope, table, payer)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const TableObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_table(code, scope, table, payer)
        {
            eprintln!("arena mirror of create_table diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn db_find_i64(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        id: u64,
        keyval_cache: &mut KeyValueIteratorCache,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        { pinned.db_find_i64(code, scope, table, id, keyval_cache.pin_mut()) }
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_key_value_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        buffer: &[u8],
    ) -> Result<*const KeyValueObject, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_key_value_object(table, payer, id, buffer)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const KeyValueObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_key_value_object(key.0, key.1, key.2, payer, id, buffer)
        {
            eprintln!("arena mirror of create_key_value_object diverged: {e:?}");
        }
        Ok(res)
    }

    /// Whether the contract table exists in the arena. Standalone-writes db_store
    /// bills table-creation RAM only on the first row, so it decides existence
    /// against the arena rather than dereferencing a chainbase table pointer.
    pub fn arena_table_exists(&self, code: u64, scope: u64, table: u64) -> bool {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.table_exists(code, scope, table))
                .unwrap_or(false)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table);
            false
        }
    }

    /// The `(payer, value)` of a contract row from the arena, or `None`. Under
    /// standalone writes db_update/db_remove resolve the row's key from the arena
    /// cache and need its old payer and value size to author the RAM delta.
    pub fn arena_kv_row(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Option<(u64, Vec<u8>)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.kv_row(code, scope, table, primary_key))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary_key);
            None
        }
    }

    /// Author a contract row in the arena alone (no chainbase). The arena's
    /// create is find-or-create on the table, so it also creates the table if
    /// absent, mirroring `create_key_value_object` + the implicit table create.
    #[cfg(feature = "arena-shadow")]
    pub fn create_key_value_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        buffer: &[u8],
    ) -> Result<(), ChainError> {
        let s = self.shadow.as_ref().ok_or_else(|| {
            ChainError::InternalError("standalone writes require the arena shadow".into())
        })?;
        s.create_key_value_object(code, scope, table, payer, primary_key, buffer)
            .map_err(|e| ChainError::InternalError(format!("arena create_key_value_object: {e:?}")))
    }

    /// Rewrite a contract row's value and payer in the arena alone (no chainbase).
    #[cfg(feature = "arena-shadow")]
    pub fn update_key_value_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        buffer: &[u8],
    ) -> Result<(), ChainError> {
        let s = self.shadow.as_ref().ok_or_else(|| {
            ChainError::InternalError("standalone writes require the arena shadow".into())
        })?;
        s.update_key_value_object(code, scope, table, primary_key, payer, buffer)
            .map_err(|e| ChainError::InternalError(format!("arena update_key_value_object: {e:?}")))
    }

    /// Remove a contract row in the arena alone (no chainbase). The arena drops
    /// the row and auto-removes the table when it empties, matching chainbase.
    #[cfg(feature = "arena-shadow")]
    pub fn remove_key_value_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), ChainError> {
        let s = self.shadow.as_ref().ok_or_else(|| {
            ChainError::InternalError("standalone writes require the arena shadow".into())
        })?;
        s.remove_key_value_object(code, scope, table, primary_key)
            .map_err(|e| ChainError::InternalError(format!("arena remove_key_value_object: {e:?}")))
    }

    pub fn create_index64_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: u64,
    ) -> Result<*const Index64Object, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_index64_object(table, payer, id, secondary_key)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const Index64Object
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_index64_object(key.0, key.1, key.2, payer, id, secondary_key)
        {
            eprintln!("arena mirror of create_index64_object diverged: {e:?}");
        }
        Ok(res)
    }

    // ----- secondary-index writes to the arena alone (standalone writes) -----
    // These mirror create/update/remove_indexN_object but touch only the arena,
    // taking the row's `(code, scope, table, primary)` scalars instead of a
    // chainbase `&IndexNObject` pointer. The secondary key is converted to the
    // arena's stored form exactly as the mirroring FFI paths do. `arena_idxN_
    // payer` serves the old payer db_idxN_update needs for its billing delta.

    #[cfg(feature = "arena-shadow")]
    fn shadow_ref(&self) -> Result<&crate::shadow::ArenaShadow, ChainError> {
        self.shadow.as_ref().ok_or_else(|| {
            ChainError::InternalError("standalone writes require the arena shadow".into())
        })
    }

    #[cfg(feature = "arena-shadow")]
    pub fn create_index64_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
            .create_index64_object(code, scope, table, payer, primary_key, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("arena create_index64: {e:?}")))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn update_index64_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
            .update_index64_object(code, scope, table, primary_key, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("arena update_index64: {e:?}")))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn remove_index64_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
            .remove_index64_object(code, scope, table, primary_key)
            .map_err(|e| ChainError::InternalError(format!("arena remove_index64: {e:?}")))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn arena_idx64_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        self.shadow
            .as_ref()
            .and_then(|s| s.idx64_payer(code, scope, table, primary))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn create_index128_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: u128,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
            .create_index128_object(code, scope, table, payer, primary_key, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("arena create_index128: {e:?}")))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn update_index128_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: u128,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
            .update_index128_object(code, scope, table, primary_key, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("arena update_index128: {e:?}")))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn remove_index128_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
            .remove_index128_object(code, scope, table, primary_key)
            .map_err(|e| ChainError::InternalError(format!("arena remove_index128: {e:?}")))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn arena_idx128_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        self.shadow
            .as_ref()
            .and_then(|s| s.idx128_payer(code, scope, table, primary))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn create_index256_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: U256,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
            .create_index256_object(code, scope, table, payer, primary_key, secondary_key.value)
            .map_err(|e| ChainError::InternalError(format!("arena create_index256: {e:?}")))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn update_index256_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: U256,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
            .update_index256_object(code, scope, table, primary_key, payer, secondary_key.value)
            .map_err(|e| ChainError::InternalError(format!("arena update_index256: {e:?}")))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn remove_index256_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
            .remove_index256_object(code, scope, table, primary_key)
            .map_err(|e| ChainError::InternalError(format!("arena remove_index256: {e:?}")))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn arena_idx256_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        self.shadow
            .as_ref()
            .and_then(|s| s.idx256_payer(code, scope, table, primary))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn create_idx_double_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
            .create_idx_double_object(code, scope, table, payer, primary_key, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("arena create_idx_double: {e:?}")))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn update_idx_double_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
            .update_idx_double_object(code, scope, table, primary_key, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("arena update_idx_double: {e:?}")))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn remove_idx_double_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
            .remove_idx_double_object(code, scope, table, primary_key)
            .map_err(|e| ChainError::InternalError(format!("arena remove_idx_double: {e:?}")))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn arena_idx_double_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        self.shadow
            .as_ref()
            .and_then(|s| s.idx_double_payer(code, scope, table, primary))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn create_idx_long_double_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary_key: u64,
        secondary_key: Float128,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
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

    #[cfg(feature = "arena-shadow")]
    pub fn update_idx_long_double_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
        payer: u64,
        secondary_key: Float128,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
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

    #[cfg(feature = "arena-shadow")]
    pub fn remove_idx_long_double_object_standalone(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Result<(), ChainError> {
        self.shadow_ref()?
            .remove_idx_long_double_object(code, scope, table, primary_key)
            .map_err(|e| ChainError::InternalError(format!("arena remove_idx_long_double: {e:?}")))
    }

    #[cfg(feature = "arena-shadow")]
    pub fn arena_idx_long_double_payer(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        self.shadow
            .as_ref()
            .and_then(|s| s.idx_long_double_payer(code, scope, table, primary))
    }

    pub fn update_key_value_object(
        &mut self,
        obj: &KeyValueObject,
        payer: u64,
        buffer: &[u8],
    ) -> Result<(), ChainError> {
        // Resolve the row's table (code, scope, table) + primary before the write,
        // so the arena mirror can locate the row the FFI reaches by opaque handle.
        #[cfg(feature = "arena-shadow")]
        let key = {
            let guard = self.locked_read()?;
            let t = guard.get_table_by_kv(obj);
            (
                t.get_code().to_uint64_t(),
                t.get_scope().to_uint64_t(),
                t.get_table().to_uint64_t(),
                obj.get_primary_key(),
            )
        };
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .update_key_value_object(obj, payer, buffer)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.update_key_value_object(key.0, key.1, key.2, key.3, payer, buffer)
        {
            eprintln!("arena mirror of update_key_value_object diverged: {e:?}");
        }
        Ok(())
    }

    pub fn update_index64_object(
        &mut self,
        obj: &Index64Object,
        payer: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_index64_object(obj, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn remove_table(&mut self, table: &TableObject) -> Result<(), ChainError> {
        // Read the key before removal, while the object is still valid.
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .remove_table(table)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.remove_table(key.0, key.1, key.2)
        {
            eprintln!("arena mirror of remove_table diverged: {e:?}");
        }
        Ok(())
    }

    pub fn is_account(&self, account: u64) -> Result<bool, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return Ok(s.account_exists(account));
        }
        let chainbase = {
            let guard = self.locked_read()?;
            guard
                .is_account(account)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };

        // Existence gates authorization/dispatch and is a plain bool (not a
        // chainbase object reference), so it can be served from the arena.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = s.account_exists(account);
            s.note_noncontract(arena == chainbase);
            if s.reads_enabled() {
                return Ok(arena);
            }
        }

        Ok(chainbase)
    }

    /// The `(code_sequence, abi_sequence)` stamped into an `ActionReceipt`, read
    /// as owned scalars off account_metadata (not the chainbase object
    /// reference), so they serve from the arena under PULSEVM_ARENA_READS. Both
    /// feed the receipt digest, so the arena must agree. Errors when the account
    /// has no metadata, matching `get_account_metadata`.
    pub fn account_metadata_code_abi_sequence(&self, name: u64) -> Result<(u64, u64), ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s.account_metadata(name).map(|t| (t.3, t.4)).ok_or_else(|| {
                ChainError::InternalError(format!(
                    "account metadata not found for account: {}",
                    name
                ))
            });
        }
        let chainbase = {
            let guard = self.locked_read()?;
            let res = guard.find_account_metadata(name).map_err(|e| {
                ChainError::InternalError(format!("failed to find account metadata: {}", e))
            })?;
            if res.is_null() {
                return Err(ChainError::InternalError(format!(
                    "account metadata not found for account: {}",
                    name
                )));
            }
            let m = unsafe { &*res };
            (m.get_code_sequence(), m.get_abi_sequence())
        };

        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            // account_metadata tuple: (priv, recv, auth, code_seq, abi_seq, ...).
            let arena = s.account_metadata(name).map(|t| (t.3, t.4));
            s.note_noncontract(arena == Some(chainbase));
            if s.reads_enabled()
                && let Some(v) = arena
            {
                return Ok(v);
            }
        }

        Ok(chainbase)
    }

    /// Whether `name` is a privileged account. A plain bool read off
    /// account_metadata (not the chainbase object reference), so it serves from
    /// the arena under PULSEVM_ARENA_READS. Errors when the account has no
    /// metadata, matching `get_account_metadata`.
    pub fn is_account_privileged(&self, name: u64) -> Result<bool, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s.account_metadata_privileged(name).ok_or_else(|| {
                ChainError::InternalError(format!(
                    "account metadata not found for account: {}",
                    name
                ))
            });
        }
        let chainbase = {
            let guard = self.locked_read()?;
            let res = guard.find_account_metadata(name).map_err(|e| {
                ChainError::InternalError(format!("failed to find account metadata: {}", e))
            })?;
            if res.is_null() {
                return Err(ChainError::InternalError(format!(
                    "account metadata not found for account: {}",
                    name
                )));
            }
            unsafe { &*res }.is_privileged()
        };

        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = s.account_metadata_privileged(name);
            s.note_noncontract(arena == Some(chainbase));
            if s.reads_enabled()
                && let Some(p) = arena
            {
                return Ok(p);
            }
        }

        Ok(chainbase)
    }

    /// The account's current `(code_hash, vm_type, vm_version)` — the fields
    /// setcode reads off `account_metadata` to decide whether code is deployed
    /// and to locate the old code object. Served from the arena under
    /// PULSEVM_ARENA_READS (cross-checked), so setcode needs no chainbase object.
    pub fn account_code_hash_vm(&self, name: u64) -> Result<([u8; 32], u8, u8), ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
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
        let chainbase = {
            let guard = self.locked_read()?;
            let res = guard.find_account_metadata(name).map_err(|e| {
                ChainError::InternalError(format!("failed to find account metadata: {}", e))
            })?;
            if res.is_null() {
                return Err(ChainError::InternalError(format!(
                    "account metadata not found for account: {}",
                    name
                )));
            }
            let m = unsafe { &*res };
            (
                digest_to_array(m.get_code_hash()),
                m.get_vm_type(),
                m.get_vm_version(),
            )
        };

        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = s.account_metadata(name).map(|t| (t.5, t.6, t.7));
            s.note_noncontract(arena == Some(chainbase));
            if s.reads_enabled()
                && let Some(v) = arena
            {
                return Ok(v);
            }
        }

        Ok(chainbase)
    }

    /// The byte size of the account's stored ABI — what setabi bills RAM against.
    /// A plain length read off the account_object, served from the arena under
    /// PULSEVM_ARENA_READS (cross-checked) so setabi needs no chainbase object.
    pub fn account_abi_size(&self, name: u64) -> Result<usize, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s
                .account_abi_size(name)
                .ok_or_else(|| ChainError::InternalError(format!("account not found: {}", name)));
        }
        let chainbase = {
            let guard = self.locked_read()?;
            let res = guard
                .find_account(name)
                .map_err(|e| ChainError::InternalError(format!("failed to get account: {}", e)))?;
            if res.is_null() {
                return Err(ChainError::InternalError(format!(
                    "account not found: {}",
                    name
                )));
            }
            unsafe { &*res }.get_abi().size()
        };

        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = s.account_abi_size(name);
            s.note_noncontract(arena == Some(chainbase));
            if s.reads_enabled()
                && let Some(v) = arena
            {
                return Ok(v);
            }
        }

        Ok(chainbase)
    }

    pub fn find_permission(&self, id: i64) -> Result<*const ffi::PermissionObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .find_permission(id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn find_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<*const ffi::PermissionObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn find_permission_link(
        &self,
        account_name: u64,
        code_name: u64,
        message_type: u64,
    ) -> Result<*const ffi::PermissionLinkObject, ChainError> {
        let guard = self.locked_read()?;
        guard
            .find_permission_link(account_name, code_name, message_type)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<*const ffi::PermissionObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        if res.is_null() {
            return Err(ChainError::InternalError(format!(
                "permission not found for actor: {} permission: {}",
                pulsevm_name::Name::new(actor),
                pulsevm_name::Name::new(permission)
            )));
        }

        Ok(res)
    }

    pub fn delete_auth(&mut self, account: u64, permission_name: u64) -> Result<i64, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .delete_auth(account, permission_name)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        // delete_auth removes the permission (and its usage row) in C++.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.remove_permission(account, permission_name)
        {
            eprintln!("arena mirror of delete_auth {account} diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn link_auth(
        &mut self,
        account_name: u64,
        code_name: u64,
        requirement_name: u64,
        requirement_type: u64,
    ) -> Result<i64, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .link_auth(account_name, code_name, requirement_name, requirement_type)
                .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))?
        };
        // In C++ the link's message_type is the requirement_type and its
        // required_permission is the requirement_name.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.link_auth(account_name, code_name, requirement_type, requirement_name)
        {
            eprintln!("arena mirror of link_auth diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn unlink_auth(
        &mut self,
        account_name: u64,
        code_name: u64,
        requirement_type: u64,
    ) -> Result<i64, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .unlink_auth(account_name, code_name, requirement_type)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.unlink_auth(account_name, code_name, requirement_type)
        {
            eprintln!("arena mirror of unlink_auth diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn get_code_object_by_hash(
        &self,
        code_hash: &CxxDigest,
        vm_type: u8,
        vm_version: u8,
    ) -> Result<*const ffi::CodeObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .get_code_object_by_hash(code_hash, vm_type, vm_version)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    /// The wasm image for `(code_hash, vm_type, vm_version)` as owned bytes.
    ///
    /// This is the bytecode the VM compiles and runs. Returning it by value
    /// (rather than a `*const CodeObject` whose `get_code()` borrows chainbase)
    /// is what lets the arena own contract code: under `PULSEVM_ARENA_READS` the
    /// image is served from the arena, cross-checked byte-for-byte against
    /// chainbase's `code_object::code` every time.
    pub fn get_code_bytes_by_hash(
        &self,
        code_hash: &CxxDigest,
        vm_type: u8,
        vm_version: u8,
    ) -> Result<Vec<u8>, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s
                .code_by_hash(digest_to_array(code_hash), vm_type, vm_version)
                .ok_or_else(|| ChainError::InternalError("code object not found".to_string()));
        }
        let chainbase = {
            let guard = self.locked_read()?;
            // The bridge returns a reference (Err, never null, when absent).
            let res = guard
                .get_code_object_by_hash(code_hash, vm_type, vm_version)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
            res.get_code().as_slice().to_vec()
        };

        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = s.code_by_hash(digest_to_array(code_hash), vm_type, vm_version);
            s.note_noncontract(arena.as_deref() == Some(chainbase.as_slice()));
            if s.reads_enabled()
                && let Some(bytes) = arena
            {
                return Ok(bytes);
            }
        }

        Ok(chainbase)
    }

    /// Bump the receiver's `recv_sequence` and return the incremented value.
    ///
    /// Takes the account *name*, not a chainbase `&AccountMetadataObject`: the
    /// object is resolved and mutated entirely inside this method, so no
    /// database-bound reference escapes into execution (the caller held one
    /// across the whole action, including the wasm run, only to hand it here).
    /// The returned sequence lands in the `ActionReceipt` digest, so the arena
    /// must produce the same value; under `PULSEVM_ARENA_READS` it is served
    /// from the arena.
    pub fn next_recv_sequence(&mut self, receiver: u64) -> Result<u64, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
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
        let chainbase = {
            let mut guard = self.locked_write()?;
            let ptr = guard.find_account_metadata(receiver).map_err(|e| {
                ChainError::InternalError(format!("failed to find account metadata: {}", e))
            })?;
            if ptr.is_null() {
                return Err(ChainError::InternalError(format!(
                    "account metadata not found for account: {}",
                    Name::new(receiver)
                )));
            }
            // Non-null; the reference is used only under this guard and never escapes.
            let obj = unsafe { &*ptr };
            let pinned = guard.pin_mut();
            pinned
                .next_recv_sequence(obj)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            match s.next_recv_sequence(receiver) {
                Ok(arena) => {
                    s.note_noncontract(arena == Some(chainbase));
                    if s.reads_enabled()
                        && let Some(v) = arena
                    {
                        return Ok(v);
                    }
                }
                Err(e) => eprintln!("arena mirror of next_recv_sequence diverged: {e:?}"),
            }
        }
        Ok(chainbase)
    }

    pub fn next_auth_sequence(&mut self, actor: u64) -> Result<u64, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            s.next_auth_sequence(actor).map_err(|e| {
                ChainError::InternalError(format!("arena next_auth_sequence: {e:?}"))
            })?;
            // The post-bump auth_sequence is what chainbase returns (++auth_sequence).
            return s.account_metadata(actor).map(|t| t.2).ok_or_else(|| {
                ChainError::InternalError(format!(
                    "account metadata not found for account: {}",
                    Name::new(actor)
                ))
            });
        }
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .next_auth_sequence(actor)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.next_auth_sequence(actor)
        {
            eprintln!("arena mirror of next_auth_sequence diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn next_global_sequence(&mut self) -> Result<u64, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            // Chainbase does ++global_action_sequence and returns it; the mirror
            // stores that post-increment value, so the arena authors the next by
            // advancing its own stored counter.
            let next = s.global_action_sequence().unwrap_or(0) + 1;
            s.set_global_action_sequence(next).map_err(|e| {
                ChainError::InternalError(format!("arena next_global_sequence: {e:?}"))
            })?;
            return Ok(next);
        }
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .next_global_sequence()
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.set_global_action_sequence(res)
        {
            eprintln!("arena mirror of next_global_sequence diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn get_global_action_sequence(&self) -> Result<u64, ChainError> {
        // Chainbase absent under a Rust genesis; serve the arena's own counter so
        // the cross-impl serialization has a value rather than a thrown singleton.
        #[cfg(feature = "arena-shadow")]
        if self.arena_rust_genesis() {
            return Ok(self
                .shadow
                .as_ref()
                .and_then(|s| s.global_action_sequence())
                .unwrap_or(0));
        }
        let guard = self.locked_read()?;
        guard
            .get_global_action_sequence()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// Mirrored `global_action_sequence`, or `None` when shadowing is off / the
    /// singleton row is unwritten — for diffing against chainbase.
    pub fn arena_global_action_sequence(&self) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.global_action_sequence())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn db_remove_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<i64, ChainError> {
        // Resolve the row's (code, scope, table, primary) through the cache
        // before it is deleted; a mirror-resolution error must never abort the
        // authoritative removal, so it is swallowed to `None`.
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_remove_i64(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_key_value_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_remove_i64 diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn db_idx64_remove(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx64_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_index64_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx64_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx64_find_secondary(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_find_primary(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_lowerbound(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_upperbound(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_end(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_next(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_previous(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_index128_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: u128,
    ) -> Result<*const Index128Object, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_index128_object(table, payer, id, secondary_key.into())
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const Index128Object
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_index128_object(key.0, key.1, key.2, payer, id, secondary_key)
        {
            eprintln!("arena mirror of create_index128_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_index128_object(
        &mut self,
        obj: &Index128Object,
        payer: u64,
        secondary_key: u128,
    ) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_index128_object(obj, payer, secondary_key.into())
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx128_remove(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx128_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_index128_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx128_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx128_find_secondary(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: u128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let secondary_key_u128: U128 = secondary_key.into();

        let res = pinned
            .db_idx128_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key_u128,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx128_find_primary(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u128,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let mut secondary_u128: U128 = (*secondary).into();
        let res = pinned
            .db_idx128_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                &mut secondary_u128,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        *secondary = secondary_u128.into();
        Ok(res)
    }

    pub fn db_idx128_lowerbound(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let mut secondary_key_u128: U128 = (*secondary_key).into();

        let res = pinned
            .db_idx128_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                &mut secondary_key_u128,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        *secondary_key = secondary_key_u128.into();
        Ok(res)
    }

    pub fn db_idx128_upperbound(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let mut secondary_key_u128: U128 = (*secondary_key).into();
        let res = pinned
            .db_idx128_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                &mut secondary_key_u128,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        *secondary_key = secondary_key_u128.into();
        Ok(res)
    }

    pub fn db_idx128_end(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx128_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx128_next(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx128_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx128_previous(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx128_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_index256_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: U256,
    ) -> Result<*const Index256Object, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        #[cfg(feature = "arena-shadow")]
        let sec_bytes = secondary_key.value;
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_index256_object(table, payer, id, secondary_key)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const Index256Object
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_index256_object(key.0, key.1, key.2, payer, id, sec_bytes)
        {
            eprintln!("arena mirror of create_index256_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_index256_object(
        &mut self,
        obj: &Index256Object,
        payer: u64,
        secondary_key: U256,
    ) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_index256_object(obj, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx256_remove(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx256_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_index256_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx256_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx256_find_secondary(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: U256,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx256_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx256_find_primary(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut U256,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx256_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx256_lowerbound(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut U256,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx256_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx256_upperbound(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut U256,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx256_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx256_end(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx256_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx256_next(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx256_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx256_previous(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx256_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_idx_double_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: u64,
    ) -> Result<*const IndexDoubleObject, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_idx_double_object(table, payer, id, secondary_key)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const IndexDoubleObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) =
                s.create_idx_double_object(key.0, key.1, key.2, payer, id, secondary_key)
        {
            eprintln!("arena mirror of create_idx_double_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_idx_double_object(
        &mut self,
        obj: &IndexDoubleObject,
        payer: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_idx_double_object(obj, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_double_remove(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx_double_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_idx_double_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx_double_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx_double_find_secondary(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx_double_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_double_find_primary(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx_double_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_double_lowerbound(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx_double_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_double_upperbound(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx_double_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_double_end(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_double_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_double_next(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_double_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_double_previous(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_double_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_idx_long_double_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: Float128,
    ) -> Result<*const IndexLongDoubleObject, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        #[cfg(feature = "arena-shadow")]
        let (sec_lo, sec_hi) = (secondary_key.lo, secondary_key.hi);
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_idx_long_double_object(table, payer, id, secondary_key)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const IndexLongDoubleObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) =
                s.create_idx_long_double_object(key.0, key.1, key.2, payer, id, (sec_lo, sec_hi))
        {
            eprintln!("arena mirror of create_idx_long_double_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_idx_long_double_object(
        &mut self,
        obj: &IndexLongDoubleObject,
        payer: u64,
        secondary_key: Float128,
    ) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_idx_long_double_object(obj, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_long_double_remove(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx_long_double_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_idx_long_double_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx_long_double_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx_long_double_find_secondary(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: Float128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx_long_double_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_long_double_find_primary(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut Float128,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx_long_double_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_long_double_lowerbound(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut Float128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx_long_double_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_long_double_upperbound(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut Float128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx_long_double_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_long_double_end(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_long_double_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_long_double_next(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_long_double_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_long_double_previous(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_long_double_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_next_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_next_i64(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_previous_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_previous_i64(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_end_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_end_i64(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_lowerbound_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        id: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_lowerbound_i64(keyval_cache.pin_mut(), code, scope, table, id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_upperbound_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        id: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_upperbound_i64(keyval_cache.pin_mut(), code, scope, table, id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn remove_permission(
        &mut self,
        permission: &ffi::PermissionObject,
    ) -> Result<(), ChainError> {
        // Read the key before removal, while the object is still valid.
        #[cfg(feature = "arena-shadow")]
        let owner_perm = (
            permission.get_owner().to_uint64_t(),
            permission.get_name().to_uint64_t(),
        );
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .remove_permission(permission)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.remove_permission(owner_perm.0, owner_perm.1)
        {
            eprintln!("arena mirror of remove_permission diverged: {e:?}");
        }
        Ok(())
    }
    pub fn create_permission(
        &mut self,
        account: u64,
        name: u64,
        parent: u64,
        auth: &Authority,
        creation_time: &TimePoint,
    ) -> Result<*const ffi::PermissionObject, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            // The arena already authors the permission id; here it also owns the
            // write. The caller re-reads the id/size by name, so null is fine.
            let authored = s.next_permission_id().map_err(|e| {
                ChainError::InternalError(format!("arena next_permission_id: {e:?}"))
            })?;
            s.create_permission(
                authored,
                parent as i64,
                account,
                name,
                creation_time.elapsed.count,
                &encode_authority(auth),
            )
            .map_err(|e| ChainError::InternalError(format!("arena create_permission: {e:?}")))?;
            return Ok(std::ptr::null());
        }
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_permission(
                    account,
                    name,
                    parent,
                    &cxx_authority(auth)?,
                    &cxx_time_point(creation_time),
                )
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const ffi::PermissionObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let auth_bytes = encode_authority(auth);
            // Authority flip: the arena authors the permission id from its own
            // replicated counter, and chainbase only verifies it assigned the same.
            // The id is what the mirror stores and what execution consumes (parent
            // links, get_id, satisfies), so it now originates in the arena rather
            // than being copied from chainbase's `res.get_id()`.
            let authored = s.next_permission_id().unwrap_or(0);
            let chainbase_id = unsafe { res.as_ref() }.map(|p| p.get_id()).unwrap_or(0);
            if authored != chainbase_id {
                eprintln!("arena-authored permission id {authored} != chainbase {chainbase_id}");
            }
            if let Err(e) = s.create_permission(
                authored,
                parent as i64,
                account,
                name,
                creation_time.elapsed.count,
                &auth_bytes,
            ) {
                eprintln!("arena mirror of create_permission diverged: {e:?}");
            }
        }
        Ok(res)
    }

    pub fn permission_satisfies_other_permission(
        &self,
        permission: &ffi::PermissionObject,
        other_permission: &ffi::PermissionObject,
    ) -> Result<bool, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .permission_satisfies_other_permission(permission, other_permission)
            .map_err(|e| ChainError::TransactionError(format!("{}", e)))?;

        Ok(res)
    }

    /// Null-checked `Pin<&mut ffi::Database>` from a write guard. `UniquePtr::pin_mut`
    /// panics on a null pointer; `as_mut` lets us return an error instead.
    fn db_mut<'a>(
        guard: &'a mut RwLockWriteGuard<'_, UniquePtr<ffi::Database>>,
    ) -> Result<Pin<&'a mut ffi::Database>, ChainError> {
        guard
            .as_mut()
            .ok_or_else(|| ChainError::InternalError("Database pointer is null".to_owned()))
    }

    /// A permission's authority as an owned value, or `None` if it doesn't exist.
    ///
    /// Handing back an owned `Authority` rather than a database-bound reference is
    /// what lets a caller read a permission, drop the read lock, edit the
    /// authority, and write it back with [`Database::modify_permission`] — no
    /// reference held across the mutation and no lock held while editing, so a
    /// read-modify-write on one permission never has to nest a read inside a
    /// write.
    pub fn permission_authority(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<Option<Authority>, ChainError> {
        let guard = self.locked_read()?;
        let perm = guard
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        // The pointer is only dereferenced while the read guard is alive, and the
        // authority is copied out before it is dropped.
        let authority = match unsafe { perm.as_ref() } {
            Some(p) => Some(native_authority(
                &ffi::get_authority_from_shared_authority(p.get_authority()),
            )?),
            None => None,
        };
        Ok(authority)
    }

    pub fn modify_permission(
        &mut self,
        actor: u64,
        permission: u64,
        authority: &Authority,
        pending_block_time: &TimePoint,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            return s
                .modify_permission(
                    actor,
                    permission,
                    &encode_authority(authority),
                    pending_block_time.elapsed.count,
                )
                .map_err(|e| ChainError::InternalError(format!("arena modify_permission: {e:?}")));
        }
        {
            let mut guard = self.locked_write()?;
            // Lookup and mutation both happen inside C++, so no database-owned
            // PermissionObject reference is held across the write.
            let modified = Self::db_mut(&mut guard)?
                .modify_permission_by_actor_and_permission(
                    actor,
                    permission,
                    &cxx_authority(authority)?,
                    &cxx_time_point(pending_block_time),
                )
                .map_err(|e| ChainError::InternalError(e.to_string()))?;
            if !modified {
                return Err(ChainError::PermissionNotFound(
                    Name::new(actor).to_string(),
                    Name::new(permission).to_string(),
                ));
            }
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let auth_bytes = encode_authority(authority);
            if let Err(e) = s.modify_permission(
                actor,
                permission,
                &auth_bytes,
                pending_block_time.elapsed.count,
            ) {
                eprintln!("arena mirror of modify_permission diverged: {e:?}");
            }
        }
        Ok(())
    }

    pub fn update_permission_usage(
        &mut self,
        actor: u64,
        permission: u64,
        pending_block_time: &TimePoint,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_writes()
        {
            return s
                .update_permission_usage(actor, permission, pending_block_time.elapsed.count)
                .map_err(|e| {
                    ChainError::InternalError(format!("arena update_permission_usage: {e:?}"))
                });
        }
        {
            let mut guard = self.locked_write()?;
            // Resolve and modify under one write guard; the resolved pointer never
            // escapes this method, so no shared reference is held across the mutation.
            let perm = guard
                .find_permission_by_actor_and_permission(actor, permission)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
            if perm.is_null() {
                return Err(ChainError::InternalError(format!(
                    "permission not found for actor: {} permission: {}",
                    Name::new(actor),
                    Name::new(permission)
                )));
            }
            let perm = unsafe { &*perm };
            let pinned = guard.pin_mut();

            pinned
                .update_permission_usage(perm, &cxx_time_point(pending_block_time))
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) =
                s.update_permission_usage(actor, permission, pending_block_time.elapsed.count)
        {
            eprintln!("arena mirror of update_permission_usage diverged: {e:?}");
        }
        Ok(())
    }

    pub fn get_permission_last_used(
        &self,
        permission: &ffi::PermissionObject,
    ) -> Result<TimePoint, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .get_permission_last_used(permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(native_time_point(res))
    }

    pub fn lookup_linked_permission(
        &self,
        account: u64,
        code: u64,
        requirement_type: u64,
    ) -> Result<Option<u64>, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .lookup_linked_permission(account, code, requirement_type)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        if res.is_null() {
            return Ok(None);
        }

        Ok(Some(unsafe { &*res }.to_uint64_t()))
    }

    pub fn get_global_properties(&self) -> Result<*const ffi::GlobalPropertyObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .get_global_properties()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn set_global_properties(&self, cfg: &ChainConfigV0) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();

            pinned
                .set_global_properties(&cxx_chain_config(cfg))
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }

        // Mirror the same chain_config into the arena (drops the chainbase lock
        // first — the shadow takes its own).
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.set_global_properties(chain_config_params_from_v0(cfg))
        {
            eprintln!("arena mirror of set_global_properties diverged: {e:?}");
        }

        Ok(())
    }

    /// Reads the active chain_config from chainbase into the mirror's param form.
    #[cfg(feature = "arena-shadow")]
    fn read_chain_config_params(&self) -> Result<crate::shadow::ChainConfigParams, ChainError> {
        let guard = self.locked_read()?;
        let gpo = guard
            .get_global_properties()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(chain_config_params_from_cxx(gpo.get_chain_config()))
    }

    /// `max_action_return_value_size` — a genesis build constant (256) that
    /// `setparams` never carries, so the arena mirror does not store it. Served as
    /// the constant when off chainbase, else read from the chainbase config.
    pub fn max_action_return_value_size(&self) -> Result<u32, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return Ok(256);
        }
        let guard = self.inner.read()?;
        let gpo = guard
            .get_global_properties()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(gpo.get_chain_config().get_max_action_return_value_size())
    }

    /// The active runtime `chain_config`, served from the arena when execution is
    /// off chainbase (standalone reads) and from the chainbase `global_property_
    /// object` otherwise. This is the owned-value replacement for
    /// `get_global_properties()?.get_chain_config()` on the per-tx/per-block hot
    /// paths, so those callers hold no chainbase object.
    pub fn chain_config(&self) -> Result<ChainConfigV0, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            let p = s
                .chain_config_params()
                .ok_or_else(|| ChainError::InternalError("arena chain_config not seeded".into()))?;
            return Ok(chain_config_v0_from_params(&p));
        }
        let guard = self.inner.read()?;
        let gpo = guard
            .get_global_properties()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(chain_config_v0_from_cxx(gpo.get_chain_config()))
    }

    /// Canonical serialization of the chainbase static `global_property_object`
    /// chain_config — byte-compatible with the arena mirror's
    /// `global_property_state_bytes`, for the cross-impl root.
    #[cfg(feature = "arena-shadow")]
    pub fn global_property_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        // Chainbase absent under a Rust genesis; its side of the cross-impl
        // serialization is unused there (see resource_state_bytes).
        if self.arena_rust_genesis() {
            return Ok(Vec::new());
        }
        Ok(self.read_chain_config_params()?.to_state_bytes())
    }

    /// Arena mirror of the static global_property chain_config, `None` when
    /// shadowing is off.
    pub fn arena_global_property_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.global_property_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn get_virtual_block_cpu_limit(&self) -> Result<u64, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s
                .state_virtual_limits()
                .map(|(cpu, _net)| cpu)
                .ok_or_else(|| ChainError::InternalError("resource state not found".into()));
        }
        let guard = self.locked_read()?;
        guard
            .get_virtual_block_cpu_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_virtual_block_net_limit(&self) -> Result<u64, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s
                .state_virtual_limits()
                .map(|(_cpu, net)| net)
                .ok_or_else(|| ChainError::InternalError("resource state not found".into()));
        }
        let guard = self.locked_read()?;
        guard
            .get_virtual_block_net_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_block_cpu_limit(&self) -> Result<u64, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s
                .block_limits()
                .map(|(cpu, _net)| cpu)
                .ok_or_else(|| ChainError::InternalError("resource state not found".into()));
        }
        let guard = self.locked_read()?;
        guard
            .get_block_cpu_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_block_net_limit(&self) -> Result<u64, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s
                .block_limits()
                .map(|(_cpu, net)| net)
                .ok_or_else(|| ChainError::InternalError("resource state not found".into()));
        }
        let guard = self.locked_read()?;
        guard
            .get_block_net_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn is_known_unexpired_transaction(
        &self,
        trx_id: &ffi::CxxDigest,
    ) -> Result<bool, ChainError> {
        let guard = self.locked_read()?;

        guard
            .is_known_unexpired_transaction(trx_id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn record_transaction(
        &mut self,
        trx_id: &ffi::CxxDigest,
        expiration: u32,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .record_transaction(trx_id, expiration)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let id = digest_to_array(trx_id);
            if let Err(e) = s.record_transaction(id, expiration) {
                eprintln!("arena mirror of record_transaction diverged: {e:?}");
            }
        }
        Ok(())
    }

    /// Whether the arena mirror holds a dedupe row for `trx_id` — for diffing
    /// against chainbase's `is_known_unexpired_transaction`. Uses the same
    /// digest-to-bytes conversion `record_transaction` mirrors with.
    pub fn arena_transaction_exists(&self, trx_id: &ffi::CxxDigest) -> bool {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.transaction_exists(digest_to_array(trx_id)))
                .unwrap_or(false)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = trx_id;
            false
        }
    }

    pub fn clear_expired_input_transactions(
        &mut self,
        cutoff: &TimePoint,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .clear_expired_input_transactions(&cxx_time_point(cutoff))
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.clear_expired_input_transactions(cutoff.elapsed.count)
        {
            eprintln!("arena mirror of clear_expired_input_transactions diverged: {e:?}");
        }
        Ok(())
    }

    pub fn get_currency_balance_with_symbol(
        &self,
        code: u64,
        account: u64,
        symbol: &str,
    ) -> Result<String, ChainError> {
        let guard = self.locked_read()?;

        get_currency_balance_with_symbol(guard.as_ref().unwrap(), code, account, symbol)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_currency_balance_without_symbol(
        &self,
        code: u64,
        account: u64,
    ) -> Result<String, ChainError> {
        let guard = self.locked_read()?;

        get_currency_balance_without_symbol(guard.as_ref().unwrap(), code, account)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_currency_stats(&self, code: u64, symbol: &str) -> Result<String, ChainError> {
        let guard = self.locked_read()?;

        get_currency_stats(guard.as_ref().unwrap(), code, symbol)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_table_by_scope(
        &self,
        code: u64,
        table: u64,
        lower_bound: &str,
        upper_bound: &str,
        limit: u32,
        reverse: bool,
    ) -> Result<String, ChainError> {
        let guard = self.locked_read()?;

        get_table_by_scope(
            guard.as_ref().unwrap(),
            code,
            table,
            lower_bound,
            upper_bound,
            limit,
            reverse,
        )
        .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_table_rows(
        &self,
        json: bool,
        code: u64,
        scope: &str,
        table: u64,
        table_key: &str,
        lower_bound: &str,
        upper_bound: &str,
        limit: u32,
        key_type: &str,
        index_position: &str,
        encode_type: &str,
        reverse: bool,
        show_payer: bool,
    ) -> Result<String, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if self.arena_standalone_reads() {
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
        let chainbase = {
            let guard = self.locked_read()?;
            get_table_rows(
                guard.as_ref().unwrap(),
                json,
                code,
                scope,
                table,
                table_key,
                lower_bound,
                upper_bound,
                limit,
                key_type,
                index_position,
                encode_type,
                reverse,
                show_payer,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = self.rpc_get_table_rows(
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
            let matches = arena.as_ref().ok().is_some_and(|value| {
                serde_json::from_str::<serde_json::Value>(value).ok()
                    == serde_json::from_str::<serde_json::Value>(&chainbase).ok()
            });
            s.note_noncontract(matches);
            if s.reads_enabled() {
                return arena;
            }
        }
        Ok(chainbase)
    }

    pub fn get_account_info_without_core_symbol(
        &self,
        account: u64,
        head_block_num: u32,
        head_block_time: &TimePoint,
    ) -> Result<String, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if self.arena_standalone_reads() {
            return self.rpc_get_account_info(
                account,
                head_block_num,
                head_block_time.time_since_epoch().count(),
                None,
            );
        }
        let chainbase = {
            let guard = self.locked_read()?;
            get_account_info_without_core_symbol(
                guard.as_ref().unwrap(),
                account,
                head_block_num,
                &cxx_time_point(head_block_time),
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = self.rpc_get_account_info(
                account,
                head_block_num,
                head_block_time.time_since_epoch().count(),
                None,
            );
            let matches = arena.as_ref().ok().is_some_and(|value| {
                serde_json::from_str::<serde_json::Value>(value).ok()
                    == serde_json::from_str::<serde_json::Value>(&chainbase).ok()
            });
            s.note_noncontract(matches);
            if s.reads_enabled() {
                return arena;
            }
        }
        Ok(chainbase)
    }

    pub fn get_account_info_with_core_symbol(
        &self,
        account: u64,
        expected_core_symbol: &str,
        head_block_num: u32,
        head_block_time: &TimePoint,
    ) -> Result<String, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if self.arena_standalone_reads() {
            return self.rpc_get_account_info(
                account,
                head_block_num,
                head_block_time.time_since_epoch().count(),
                Some(expected_core_symbol),
            );
        }
        let chainbase = {
            let guard = self.locked_read()?;
            get_account_info_with_core_symbol(
                guard.as_ref().unwrap(),
                account,
                expected_core_symbol,
                head_block_num,
                &cxx_time_point(head_block_time),
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = self.rpc_get_account_info(
                account,
                head_block_num,
                head_block_time.time_since_epoch().count(),
                Some(expected_core_symbol),
            );
            let matches = arena.as_ref().ok().is_some_and(|value| {
                serde_json::from_str::<serde_json::Value>(value).ok()
                    == serde_json::from_str::<serde_json::Value>(&chainbase).ok()
            });
            s.note_noncontract(matches);
            if s.reads_enabled() {
                return arena;
            }
        }
        Ok(chainbase)
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
    #[cfg(feature = "arena-shadow")]
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
        let (net_limit, cpu_limit) = match self.shadow.as_ref() {
            Some(s) => (
                s.account_net_limit_info(account, 1000, Some(current_slot))
                    .map(|v| v.0)
                    .unwrap_or(default_limit),
                s.account_cpu_limit_info(account, 1000, Some(current_slot))
                    .map(|v| v.0)
                    .unwrap_or(default_limit),
            ),
            None => (default_limit, default_limit),
        };
        let net_limit = to_rpc_limit(net_limit);
        let cpu_limit = to_rpc_limit(cpu_limit);

        let mut links_by_permission: std::collections::BTreeMap<u64, Vec<LinkedAction>> = self
            .shadow
            .as_ref()
            .map(|s| s.permission_links_of(account))
            .unwrap_or_default()
            .into_iter()
            .fold(
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
    #[cfg(feature = "arena-shadow")]
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

    pub fn pack_deltas(&self, full_snapshot: bool) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;

        guard
            .pack_deltas(full_snapshot)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::string_to_name;

    use super::*;

    #[test]
    fn test_database_creation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1 * 1024 * 1024 * 1024).unwrap();
        let name = string_to_name("test").unwrap();
        db.add_indices();
    }

    // The hazard the guard API introduced, and the reason `check_reentry`
    // exists. Binding chainbase references to a guard stops them dangling; it
    // also means holding one across a call that locks again is a deadlock, not
    // a compile error. `Database` is an `Arc` handle and `read(&self)` borrows
    // immutably, so nothing in the type system objects — and the re-entry
    // usually arrives through a call that never names the database.
    //
    // Without the check, each of these blocks forever. `onblock_consumes_min_
    // transaction_cpu_usage` did exactly this and took CI to its six-hour limit
    // on both architectures, twice, reporting nothing.
    #[test]
    fn a_write_while_holding_a_read_view_is_refused_rather_than_deadlocking() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1 * 1024 * 1024 * 1024).unwrap();
        db.add_indices().unwrap();

        // Through a *clone*, which is how this happens in practice and why the
        // borrow checker does not catch it. `Database` is an `Arc` handle: the
        // two values are distinct owners of one lock, so `&self` on one and
        // `&mut self` on the other never conflict. In the real failure the
        // clone was several frames away, inside `Controller`.
        let mut other = db.clone();
        let view = db.read().unwrap();
        let err = match other.create_undo_session(true) {
            Err(e) => e,
            Ok(_) => panic!("a mutator under a held read view must be refused"),
        };
        assert!(
            format!("{err:?}").contains("re-entered"),
            "expected a re-entry refusal, got {err:?}"
        );
        drop(view);

        // And the same call succeeds once the view is gone, so the check is
        // refusing the pattern rather than the call.
        assert!(other.create_undo_session(true).is_ok());
    }

    #[test]
    fn a_second_view_while_holding_a_write_view_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1 * 1024 * 1024 * 1024).unwrap();
        db.add_indices().unwrap();

        let other = db.clone();
        let view = db.write().unwrap();
        assert!(
            other.read().is_err(),
            "a read under a held write view must be refused"
        );
        assert!(
            other.write().is_err(),
            "a second write view must be refused"
        );
        drop(view);

        assert!(other.read().is_ok());
    }

    // Guards must stop counting when they drop, or the first one poisons every
    // later acquisition on the thread and the check becomes the outage.
    #[test]
    fn the_count_is_released_with_the_view() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1 * 1024 * 1024 * 1024).unwrap();
        db.add_indices().unwrap();

        for _ in 0..3 {
            let view = db.read().unwrap();
            drop(view);
            let view = db.write().unwrap();
            drop(view);
        }
        assert!(db.create_undo_session(true).is_ok());
    }

    #[test]
    fn test_pack_deltas() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1 * 1024 * 1024 * 1024).unwrap();
        let name = string_to_name("test").unwrap();
        db.add_indices().unwrap();
        let mut session = db.create_undo_session(true).unwrap();
        let _account = db.create_account(name.to_uint64_t(), 0).unwrap();
        session.pin_mut().push().unwrap();
        let deltas = db.pack_deltas(false).unwrap();
        let hex_deltas = hex::encode(deltas);
        assert_eq!(
            hex_deltas,
            "0100076163636f756e7401010e00000000000090b1ca0000000000"
        );
    }

    // 64 MiB is a multiple of chainbase's 1 MiB sizing requirement and leaves
    // ample room for a handful of rows, while keeping the file cheap to copy in
    // a test.
    const TEST_DB_SIZE: u64 = 64 * 1024 * 1024;

    fn name_u64(s: &str) -> u64 {
        string_to_name(s).unwrap().to_uint64_t()
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
    #[cfg(feature = "arena-shadow")]
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
    #[cfg(feature = "arena-shadow")]
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
    #[cfg(feature = "arena-shadow")]
    #[test]
    fn decode_authority_rejects_truncated_blob() {
        // threshold + a key count of 1 but no key payload.
        let mut blob = 1u32.to_le_bytes().to_vec();
        blob.extend_from_slice(&1u32.to_le_bytes());
        assert!(decode_authority(&blob).is_err());
    }

    #[test]
    fn snapshot_round_trips_state() {
        let src = TempDir::new().unwrap();
        let src_path = src.path().to_str().unwrap();

        let mut db = Database::new(src_path, TEST_DB_SIZE).unwrap();
        db.add_indices().unwrap();
        // Stamp the revision before any undo activity — chainbase refuses to set
        // it while an undo stack exists. Then write committed rows directly.
        db.set_revision(7).unwrap();

        let alice = name_u64("alice");
        let bob = name_u64("bob");
        db.create_account(alice, 1).unwrap();
        db.create_account(bob, 2).unwrap();

        let snap = db.snapshot_bytes().unwrap();
        assert_eq!(crate::snapshot::peek_header(&snap).unwrap().revision, 7);

        // The source database keeps working after the close/reopen cycle.
        assert!(!db.find_account(alice).unwrap().is_null());

        // Restore into a fresh directory and open it as a node would on restart.
        let dst = TempDir::new().unwrap();
        let dst_path = dst.path().to_str().unwrap();
        let header = restore_snapshot(dst_path, &snap).unwrap();
        assert_eq!(header.revision, 7);

        let mut db2 = Database::new(dst_path, TEST_DB_SIZE).unwrap();
        db2.add_indices().unwrap();
        assert_eq!(db2.revision(), 7);
        assert!(!db2.find_account(alice).unwrap().is_null());
        assert!(!db2.find_account(bob).unwrap().is_null());
        assert!(db2.find_account(name_u64("carol")).unwrap().is_null());

        // A file copy is faithful, so restore -> snapshot is a fixpoint: the
        // payload out of the restored arena matches the payload that went in.
        let snap2 = db2.snapshot_bytes().unwrap();
        let payload = &snap[crate::snapshot::HEADER_LEN..];
        let payload2 = &snap2[crate::snapshot::HEADER_LEN..];
        assert_eq!(payload, payload2);
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
    fn snapshot_on_closed_db_errors() {
        let db = Database::default();
        assert!(db.snapshot_bytes().is_err());
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
        assert!(
            !b.find_account(alice).unwrap().is_null(),
            "alice not restored"
        );
        assert!(
            b.find_account(bob).unwrap().is_null(),
            "bob's state survived"
        );

        // The target is still a working database after the swap.
        let carol = name_u64("carol");
        b.create_account(carol, 3).unwrap();
        assert!(!b.find_account(carol).unwrap().is_null());
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
        assert!(!a.find_account(alice).unwrap().is_null());
    }
}

thread_local! {
    /// Database guards this thread is currently holding, as `(reads, writes)`.
    ///
    /// Binding chainbase references to a guard removed one hazard and created
    /// another. A raw `*const CodeObject` could dangle, which the guard fixes;
    /// but a guard is a *held lock*, and `std::sync::RwLock` is not reentrant,
    /// so code that keeps one alive across a call that locks again does not
    /// fail — it stops, forever. The compiler cannot see it: `Database` is an
    /// `Arc` handle, `read(&self)` borrows immutably, and the re-entry usually
    /// arrives through something that never mentions the database at all
    /// (`controller.run_onblock(..)`), holding its own clone of the handle.
    ///
    /// So the invariant is enforced here instead. Every acquisition checks what
    /// this thread already holds and returns an error naming the problem rather
    /// than blocking on a lock only this thread can release.
    static HELD: std::cell::Cell<(u32, u32)> = const { std::cell::Cell::new((0, 0)) };
}

/// Counts one held guard for the thread, and uncounts it on drop.
struct LockScope {
    write: bool,
}

impl LockScope {
    fn enter(write: bool) -> Self {
        HELD.with(|held| {
            let (r, w) = held.get();
            held.set(if write { (r, w + 1) } else { (r + 1, w) });
        });
        LockScope { write }
    }
}

impl Drop for LockScope {
    fn drop(&mut self) {
        HELD.with(|held| {
            let (r, w) = held.get();
            held.set(if self.write {
                (r, w.saturating_sub(1))
            } else {
                (r.saturating_sub(1), w)
            });
        });
    }
}

/// The two acquisitions that can only ever deadlock, refused up front.
///
/// Read-while-read is left alone: it is what the current code does on a single
/// thread and it completes. It is not *safe* — a writer queued between the two
/// reads blocks both, because this `RwLock` is fair — but rejecting it would
/// reject working paths, so it is a known hazard rather than an error here.
fn check_reentry(want_write: bool) -> Result<(), ChainError> {
    let (reads, writes) = HELD.with(|held| held.get());
    if writes > 0 || (want_write && reads > 0) {
        return Err(ChainError::InternalError(format!(
            "database lock re-entered on this thread: asking for a {} while holding {} read \
             guard(s) and {} write guard(s). std::sync::RwLock is not reentrant, so this would \
             deadlock rather than fail. Narrow the scope of the outer guard — take what you need \
             out of it in a block, drop it, and only then call back into the database.",
            if want_write { "write" } else { "read" },
            reads,
            writes,
        )));
    }
    Ok(())
}

impl Database {
    /// The write lock, refusing re-entry instead of hanging on it.
    ///
    /// Every `&mut self` method on `Database` goes through here, so a caller
    /// holding a view and calling any mutator gets an error naming the call.
    fn locked_write(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, UniquePtr<ffi::Database>>, ChainError> {
        check_reentry(true)?;
        Ok(self.inner.write()?)
    }

    /// The read lock, refusing only the acquisition that cannot succeed: a read
    /// taken while this thread holds the exclusive lock.
    fn locked_read(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, UniquePtr<ffi::Database>>, ChainError> {
        check_reentry(false)?;
        Ok(self.inner.read()?)
    }

    /// Acquire a read view. The lock is held for the lifetime of the returned
    /// `DbRead`, and every reference it hands out is bound to `&self`, so a
    /// chainbase reference can never outlive the lock or escape the view.
    pub fn read(&self) -> Result<DbRead<'_>, ChainError> {
        let guard = self.locked_read()?;
        Ok(DbRead {
            guard,
            _scope: LockScope::enter(false),
            #[cfg(feature = "arena-shadow")]
            shadow: self.shadow.clone(),
        })
    }

    /// Acquire a write view. Exposes the same reads as [`DbRead`] plus mutation,
    /// all under a single write lock, so reads and the mutations that depend on
    /// them share one guard instead of re-locking.
    pub fn write(&self) -> Result<DbWrite<'_>, ChainError> {
        let guard = self.locked_write()?;
        Ok(DbWrite {
            guard,
            _scope: LockScope::enter(true),
        })
    }
}

/// Read view over the chainbase database. Holds an [`RwLockReadGuard`] for its
/// lifetime; references returned by its methods borrow `&self` and therefore
/// cannot outlive the held lock.
pub struct DbRead<'g> {
    guard: std::sync::RwLockReadGuard<'g, UniquePtr<ffi::Database>>,
    /// Counts this guard against the thread while it lives. Declared after
    /// `guard` only for readability; drop order does not matter, since the
    /// count and the lock are released in the same scope either way.
    _scope: LockScope,
    // The arena mirror, so reads served here can be cross-checked against it
    // during execution. A cheap Arc clone; `None` when shadowing is off.
    #[cfg(feature = "arena-shadow")]
    shadow: Option<crate::shadow::ArenaShadow>,
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

    /// The RAM the permission's authority is billed — what
    /// `get_authority().get_billable_size()` returned off the chainbase object.
    pub fn authority_billable_size(&self) -> i64 {
        self.auth_billable_size
    }

    /// Does this permission satisfy `other` — is it that same permission, its
    /// immediate parent, or an ancestor up its parent chain. Resolved by name so
    /// no chainbase object reference is required; see
    /// [`DbRead::permission_satisfies_by_name`].
    pub fn satisfies(&self, other: &PermissionInfo, db: &DbRead<'_>) -> Result<bool, ChainError> {
        db.permission_satisfies_by_name(self.owner, self.name, other.owner, other.name)
    }
}

impl<'g> DbRead<'g> {
    fn db(&self) -> &ffi::Database {
        &self.guard
    }

    pub fn find_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<Option<&ffi::PermissionObject>, ChainError> {
        let res = self
            .db()
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        let res = unsafe { res.as_ref() };

        // The arena must answer this authorization read the same way: same
        // existence, same parent in the permission tree, same authority
        // threshold. Consensus depends on it — every transaction authorizes here.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let chainbase = res.map(|p| {
                let threshold =
                    ffi::get_authority_from_shared_authority(p.get_authority()).threshold;
                (p.get_parent_id(), threshold)
            });
            s.note_noncontract(s.permission(actor, permission) == chainbase);
        }

        Ok(res)
    }

    /// The full authority for `(actor, permission)` as an owned value, or `None`
    /// if the permission doesn't exist.
    ///
    /// Authorization satisfaction reads the authority here, so unlike the raw
    /// `find_permission_by_actor_and_permission` (which hands back a chainbase
    /// object reference the arena can't produce), this returns an owned
    /// `Authority` and is served from the arena under `PULSEVM_ARENA_READS`. The
    /// cross-check is on the canonical encoding rather than on `SharedPtr`
    /// identity: the mirror stored `encode_authority(auth)`, so re-encoding
    /// chainbase's authority must reproduce the same bytes — and since
    /// `decode_authority` is the inverse of `encode_authority`, serving
    /// `decode_authority(arena_blob)` yields exactly chainbase's authority.
    pub fn permission_authority(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<Option<Authority>, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return match s.permission_auth_blob(actor, permission) {
                Some(blob) => Ok(Some(decode_authority(&blob)?)),
                None => Ok(None),
            };
        }
        let chainbase = self
            .db()
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        let chainbase = match unsafe { chainbase.as_ref() } {
            Some(p) => Some(native_authority(
                &ffi::get_authority_from_shared_authority(p.get_authority()),
            )?),
            None => None,
        };

        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena_blob = s.permission_auth_blob(actor, permission);
            let chainbase_blob = chainbase.as_ref().map(encode_authority);
            s.note_noncontract(arena_blob == chainbase_blob);
            if s.reads_enabled() {
                return match arena_blob {
                    Some(blob) => Ok(Some(decode_authority(&blob)?)),
                    None => Ok(None),
                };
            }
        }

        Ok(chainbase)
    }

    /// The permission's chainbase id, served from the arena's `cb_id` under
    /// `PULSEVM_ARENA_READS`. newaccount reads the owner permission's id here to
    /// parent the active permission on it; the mirror stores that same id, so the
    /// value it serves is identical.
    pub fn permission_id(&self, owner: u64, perm_name: u64) -> Result<Option<i64>, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return Ok(s.permission_cb_id(owner, perm_name));
        }
        let chainbase = self
            .db()
            .find_permission_by_actor_and_permission(owner, perm_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        let chainbase = unsafe { chainbase.as_ref() }.map(|p| p.get_id());

        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = s.permission_cb_id(owner, perm_name);
            s.note_noncontract(arena == chainbase);
            if s.reads_enabled() {
                return Ok(arena);
            }
        }

        Ok(chainbase)
    }

    /// The permission authority's `get_billable_size()` (the RAM a permission's
    /// authority is charged), computed from the arena's stored auth blob and
    /// served under `PULSEVM_ARENA_READS`. newaccount bills this for the new
    /// owner/active permissions.
    pub fn permission_authority_billable_size(
        &self,
        owner: u64,
        perm_name: u64,
    ) -> Result<Option<i64>, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return Ok(s
                .permission_auth_blob(owner, perm_name)
                .and_then(|blob| authority_blob_billable_size(&blob)));
        }
        let chainbase = self
            .db()
            .find_permission_by_actor_and_permission(owner, perm_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        let chainbase =
            unsafe { chainbase.as_ref() }.map(|p| p.get_authority().get_billable_size() as i64);

        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = s
                .permission_auth_blob(owner, perm_name)
                .and_then(|blob| authority_blob_billable_size(&blob));
            s.note_noncontract(arena == chainbase);
            if s.reads_enabled() {
                return Ok(arena);
            }
        }

        Ok(chainbase)
    }

    /// Resolve a permission to the owned [`PermissionInfo`] execution reads,
    /// replacing the chainbase `&PermissionObject` reference. In the default
    /// build chainbase stays authoritative and every field is cross-checked
    /// against the arena; under `PULSEVM_ARENA_READS` the arena's value is
    /// served, and under `PULSEVM_ARENA_ONLY` chainbase is never consulted.
    pub fn find_permission_info(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<Option<PermissionInfo>, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return Ok(Self::arena_permission_info(s, actor, permission));
        }

        let chainbase = self
            .db()
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        let chainbase = unsafe { chainbase.as_ref() }.map(|p| PermissionInfo {
            owner: actor,
            name: permission,
            id: p.get_id(),
            parent_id: p.get_parent_id(),
            auth_billable_size: p.get_authority().get_billable_size() as i64,
        });

        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = Self::arena_permission_info(s, actor, permission);
            s.note_noncontract(arena == chainbase);
            if s.reads_enabled() {
                return Ok(arena);
            }
        }

        Ok(chainbase)
    }

    /// Build a [`PermissionInfo`] purely from the arena mirror, or `None` if the
    /// permission is absent. Each field comes from the same arena accessor the
    /// value-based reads already use, so the snapshot is consistent with them.
    #[cfg(feature = "arena-shadow")]
    fn arena_permission_info(
        s: &crate::shadow::ArenaShadow,
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
    /// counterpart to [`permission_satisfies_other_permission`] that needs no
    /// chainbase object references: in the default build it re-finds the two
    /// objects and defers to the object-based check (which itself cross-checks
    /// the arena); under `PULSEVM_ARENA_ONLY` it walks the arena's permission
    /// tree directly.
    pub fn permission_satisfies_by_name(
        &self,
        owner_a: u64,
        name_a: u64,
        owner_b: u64,
        name_b: u64,
    ) -> Result<bool, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s
                .permission_satisfies(owner_a, name_a, owner_b, name_b)
                .ok_or_else(|| {
                    ChainError::InternalError(
                        "permission_satisfies: permission absent from arena".to_string(),
                    )
                });
        }

        let a = self
            .db()
            .find_permission_by_actor_and_permission(owner_a, name_a)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        let b = self
            .db()
            .find_permission_by_actor_and_permission(owner_b, name_b)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        let a = unsafe { a.as_ref() }.ok_or_else(|| {
            ChainError::InternalError(format!(
                "permission_satisfies: permission {}/{} not found",
                Name::new(owner_a),
                Name::new(name_a)
            ))
        })?;
        let b = unsafe { b.as_ref() }.ok_or_else(|| {
            ChainError::InternalError(format!(
                "permission_satisfies: permission {}/{} not found",
                Name::new(owner_b),
                Name::new(name_b)
            ))
        })?;
        self.permission_satisfies_other_permission(a, b)
    }

    /// The `last_used` microsecond timestamp of a permission, by name. Default
    /// build reads it off the chainbase object and cross-checks the arena; under
    /// `PULSEVM_ARENA_ONLY` the arena's usage row answers directly.
    pub fn permission_last_used_by_name(&self, owner: u64, name: u64) -> Result<i64, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return s.permission_last_used(owner, name).ok_or_else(|| {
                ChainError::InternalError(
                    "permission_last_used: permission absent from arena".to_string(),
                )
            });
        }

        let ptr = self
            .db()
            .find_permission_by_actor_and_permission(owner, name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        let p = unsafe { ptr.as_ref() }.ok_or_else(|| {
            ChainError::InternalError(format!(
                "permission_last_used: permission {}/{} not found",
                Name::new(owner),
                Name::new(name)
            ))
        })?;
        let chainbase = self.get_permission_last_used(p)?.time_since_epoch().count();

        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = s.permission_last_used(owner, name);
            s.note_noncontract(arena == Some(chainbase));
            if s.reads_enabled()
                && let Some(us) = arena
            {
                return Ok(us);
            }
        }

        Ok(chainbase)
    }

    pub fn find_permission(&self, id: i64) -> Result<Option<&ffi::PermissionObject>, ChainError> {
        let res = self
            .db()
            .find_permission(id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(unsafe { res.as_ref() })
    }

    pub fn find_account(
        &self,
        account_name: u64,
    ) -> Result<Option<&ffi::AccountObject>, ChainError> {
        let res = self
            .db()
            .find_account(account_name)
            .map_err(|e| ChainError::InternalError(format!("failed to get account: {}", e)))?;
        let res = unsafe { res.as_ref() };

        // Account existence gates authorization and dispatch; the arena must
        // agree on whether the account is there.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.note_noncontract(s.account_exists(account_name) == res.is_some());
        }

        Ok(res)
    }

    pub fn find_account_metadata(
        &self,
        account_name: u64,
    ) -> Result<Option<&ffi::AccountMetadataObject>, ChainError> {
        let res = self.db().find_account_metadata(account_name).map_err(|e| {
            ChainError::InternalError(format!("failed to find account metadata: {}", e))
        })?;
        let res = unsafe { res.as_ref() };

        // The privileged flag changes execution (privileged contracts skip some
        // checks), so the arena must reproduce it (and existence).
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let chainbase = res.map(|m| m.is_privileged());
            s.note_noncontract(s.account_metadata_privileged(account_name) == chainbase);
        }

        Ok(res)
    }

    pub fn get_global_properties(&self) -> Result<&ffi::GlobalPropertyObject, ChainError> {
        let res = self
            .db()
            .get_global_properties()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    /// Like [`find_account`] but errors when absent. The returned reference borrows
    /// the held guard, so it cannot outlive the lock.
    pub fn get_account(&self, account_name: u64) -> Result<&ffi::AccountObject, ChainError> {
        self.find_account(account_name)?.ok_or_else(|| {
            ChainError::InternalError(format!("account not found: {}", account_name))
        })
    }

    /// Like [`find_account_metadata`] but errors when absent.
    pub fn get_account_metadata(
        &self,
        account_name: u64,
    ) -> Result<&ffi::AccountMetadataObject, ChainError> {
        self.find_account_metadata(account_name)?.ok_or_else(|| {
            ChainError::InternalError(format!(
                "account metadata not found for account: {}",
                account_name
            ))
        })
    }

    pub fn get_code_object_by_hash(
        &self,
        code_hash: &CxxDigest,
        vm_type: u8,
        vm_version: u8,
    ) -> Result<&ffi::CodeObject, ChainError> {
        self.db()
            .get_code_object_by_hash(code_hash, vm_type, vm_version)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// Like [`find_permission_by_actor_and_permission`] but errors when absent.
    pub fn get_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<&ffi::PermissionObject, ChainError> {
        self.find_permission_by_actor_and_permission(actor, permission)?
            .ok_or_else(|| {
                ChainError::InternalError(format!(
                    "permission not found for actor: {} permission: {}",
                    Name::new(actor),
                    Name::new(permission)
                ))
            })
    }

    pub fn permission_satisfies_other_permission(
        &self,
        permission: &ffi::PermissionObject,
        other_permission: &ffi::PermissionObject,
    ) -> Result<bool, ChainError> {
        let chainbase = self
            .db()
            .permission_satisfies_other_permission(permission, other_permission)
            .map_err(|e| ChainError::TransactionError(format!("{}", e)))?;

        // The arena walks the same owner/id/parent tree. The two `PermissionObject`
        // refs are only used to name the permissions — `(owner, name)` — so the
        // arena can answer without a chainbase object reference and, under
        // `PULSEVM_ARENA_READS`, this consensus-critical authorization check is
        // served from it.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = s.permission_satisfies(
                permission.get_owner().to_uint64_t(),
                permission.get_name().to_uint64_t(),
                other_permission.get_owner().to_uint64_t(),
                other_permission.get_name().to_uint64_t(),
            );
            s.note_noncontract(arena == Some(chainbase));
            if s.reads_enabled()
                && let Some(a) = arena
            {
                return Ok(a);
            }
        }

        Ok(chainbase)
    }

    pub fn get_permission_last_used(
        &self,
        permission: &ffi::PermissionObject,
    ) -> Result<TimePoint, ChainError> {
        self.db()
            .get_permission_last_used(permission)
            .map(native_time_point)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn lookup_linked_permission(
        &self,
        account: u64,
        code: u64,
        requirement_type: u64,
    ) -> Result<Option<u64>, ChainError> {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && s.standalone_reads()
        {
            return Ok(s.permission_link(account, code, requirement_type));
        }
        let res = self
            .db()
            .lookup_linked_permission(account, code, requirement_type)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        let linked = if res.is_null() {
            None
        } else {
            Some(unsafe { &*res }.to_uint64_t())
        };

        // linkauth resolution feeds authorization: the arena must resolve the
        // same linked permission (or agree there's none). This read returns a
        // plain permission name (not a chainbase object reference), so unlike the
        // account/permission object reads it can be served from the arena.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let arena = s.permission_link(account, code, requirement_type);
            s.note_noncontract(arena == linked);
            if s.reads_enabled() {
                return Ok(arena);
            }
        }

        Ok(linked)
    }
}

/// Write view over the chainbase database. Wraps a write guard and exposes the
/// same reads as [`DbRead`] (via [`DbWrite::reads`]) plus mutating operations.
pub struct DbWrite<'g> {
    guard: std::sync::RwLockWriteGuard<'g, UniquePtr<ffi::Database>>,
    _scope: LockScope,
}

impl<'g> DbWrite<'g> {
    fn db(&self) -> &ffi::Database {
        &self.guard
    }

    pub fn find_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<Option<&ffi::PermissionObject>, ChainError> {
        let res = self
            .db()
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(unsafe { res.as_ref() })
    }
}

impl Default for Database {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(UniquePtr::null())),
            path: String::new(),
            size: 0,
            #[cfg(feature = "arena-shadow")]
            shadow: None,
        }
    }
}

unsafe impl Send for Database {}
unsafe impl Sync for Database {}

/// Install a physical snapshot into `db_path`, ready to be opened normally.
///
/// The envelope is validated (magic, version, checksum) before anything touches
/// disk, so a corrupt transfer is rejected here rather than surfacing as a
/// chainbase open failure. The payload is written verbatim as
/// `shared_memory.bin`; the snapshot was taken from a cleanly-closed mapping, so
/// its dirty flag is clear and the directory opens without `allow_dirty`.
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
    let file = Path::new(db_path).join(SHARED_MEMORY_FILE);
    Database::write_sparse_snapshot(&file, payload)?;
    Ok(header)
}
