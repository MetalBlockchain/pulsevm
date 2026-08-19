//! Deterministic CPU cost of each host intrinsic, in the same point unit the
//! metering middleware charges wasm operators with (see `COST_FUNCTION` in
//! `wasm_runtime`). A host intrinsic runs native Rust that the wasm metering
//! can't see, so each one bills its own work through [`WasmContext::charge`]
//! using the amounts here; without it a contract pays the flat `Call` cost of 2
//! whether it hashes one byte or a megabyte.
//!
//! These amounts are consensus state. Metered points become billed CPU, which is
//! committed to the block, so every node MUST charge from this identical table;
//! changing any value changes billed CPU and forks a network that hasn't also
//! changed it. Treat it like the pinned wasm feature set: adjust only through a
//! coordinated upgrade. The point-to-time anchor is [`POINTS_PER_US`].
//!
//! Two tiers, by how the numbers were derived:
//!
//! - **MEASURED** — the cryptographic hashes, key recovery, bulk memory ops (from
//!   `estimate_intrinsic_costs`), and the database row operations (from
//!   `estimate_db_intrinsic_costs`). Native work benchmarked across input sizes / table population,
//!   fit as base + per-byte, times a 3x safety multiplier so a point is an upper bound on real
//!   time. See `docs/intrinsic-cost-model.md`. These were the worst under-charges — key recovery
//!   was ~800x too cheap, a row write ~160x.
//! - **PROVISIONAL** — the rest (getters, builtins, the auth scans, console, …). Still hand-scaled
//!   to the operator table, NOT benchmarked, but these are cheap fixed-cost paths (a host-boundary
//!   crossing, a small vector scan, a bounded print), not the row-I/O and hashing paths that were
//!   badly mispriced. Flagged here so the mixed scale is explicit, not hidden.
//!
//! [`WasmContext::charge`]: crate::chain::wasm_runtime::WasmContext::charge
//! [`POINTS_PER_US`]: crate::config::POINTS_PER_US

// ---------------------------------------------------------------------------
// MEASURED (estimate_intrinsic_costs, 3x safety, reference hardware)
// ---------------------------------------------------------------------------

// Cryptographic hashes: base + per-byte of input. sha256/sha512 use an asm
// backend and are fast per byte; sha1 and ripemd160 have none and are slower.
// sha224 shares sha256's compression function, so it is priced as sha256.

/// sha256 / sha224 (and their `assert_` forms) over `len` input bytes.
#[inline]
pub fn sha256(len: u64) -> u64 {
    2_000 + 35 * len
}

/// sha512 over `len` input bytes.
#[inline]
pub fn sha512(len: u64) -> u64 {
    5_800 + 64 * len
}

/// sha1 over `len` input bytes.
#[inline]
pub fn sha1(len: u64) -> u64 {
    5_500 + 82 * len
}

/// ripemd160 over `len` input bytes.
#[inline]
pub fn ripemd160(len: u64) -> u64 {
    16_600 + 276 * len
}

/// A bulk memory op (`memcpy`, `memmove`, `memset`, `memcmp`) over `len` bytes.
#[inline]
pub fn memory(len: u64) -> u64 {
    300 + 10 * len
}

/// Public-key recovery from a signature (`recover_key`, `assert_recover_key`).
/// A full secp256k1 recovery (~14.5 µs) -- by far the heaviest intrinsic.
pub const RECOVER_KEY: u64 = 1_650_000;

// ---------------------------------------------------------------------------
// PROVISIONAL (hand-scaled, pending measurement)
// ---------------------------------------------------------------------------

/// Crossing the host boundary plus the fixed bookkeeping every intrinsic does.
/// A trivial getter (`action_data_size`, `current_receiver`, `current_time`, …)
/// costs only this.
pub const BASE: u64 = 5;

/// A fixed-width soft-float / int128 compiler builtin (`__multf3`, `__ashlti3`,
/// …): a few native arithmetic ops.
pub const BUILTIN: u64 = 8;

/// The heavier soft-float / int128 builtins — division, modulo, square root.
pub const BUILTIN_DIV: u64 = 20;

/// A permission / authorization check on the action's own declared authorizations
/// (`require_auth`, `require_auth2`, `has_auth`, `require_recipient`). This is a
/// linear scan over that small vector — the recursive authority walk (keys,
/// sub-permissions, chained accounts) happens at transaction-authorization time,
/// before the contract runs, and is billed there, not here. So this stays a fixed
/// small cost. `is_account`, which does a real chainbase lookup, is priced as
/// [`DB_FIND`] instead.
pub const AUTH: u64 = 40;

// ---------------------------------------------------------------------------
// MEASURED — database (estimate_db_intrinsic_costs, 3x safety)
// ---------------------------------------------------------------------------
//
// Row I/O is native database work invisible to wasm metering, and it was the
// worst PROVISIONAL under-charge: a single flat `DB_OP = 100` billed a write, a
// keyed lookup, and an iterator step all the same, when measurement puts them
// 24-160x higher and 6x apart from each other. Split into the three tiers the
// benchmark actually separates. Secondary/wide-key indexes (idx128/idx256/
// idx_double/idx_long_double) reuse the primary-index prices plus the 3x safety;
// pricing their wider key comparisons exactly is a refinement follow-up.

/// A row write: `db_store_i64` / `db_update_i64` / `db_remove_i64` and the
/// secondary-index store/update/remove. Object alloc/free plus index maintenance;
/// value bytes add [`db_value_per_byte`].
pub const DB_STORE: u64 = 16_000;

/// A keyed lookup or bound: `db_find_i64`, `db_lowerbound_i64`,
/// `db_upperbound_i64`, `db_end_i64`, the secondary find/bound variants, and
/// `is_account`.
pub const DB_FIND: u64 = 6_500;

/// One iterator step: `db_next_i64` / `db_previous_i64` and the secondary-index
/// variants. Cheaper than a fresh lookup — it advances from a cached position.
pub const DB_ITERATE: u64 = 2_500;

/// Per-byte surcharge for reading or writing a row value (`db_store_i64`,
/// `db_update_i64`, `db_get_i64`): measured value-copy slope, 3x safety.
#[inline]
pub fn db_value_per_byte(len: u64) -> u64 {
    11 * len
}

/// A privileged intrinsic (`set_resource_limits`, `set_privileged`,
/// `set_proposed_producers`, …).
pub const PRIVILEGED: u64 = 40;

/// A producer / active-schedule intrinsic (`get_active_producers`).
pub const PRODUCER: u64 = 40;

/// A system intrinsic (`eosio_assert`, `pulse_exit`, …).
pub const SYSTEM: u64 = 10;

/// A transaction intrinsic (`send_inline`, `send_context_free_inline`,
/// `read_transaction`, …). The `send_*` and `read_*` variants also pay
/// [`per_byte`] over the serialized size.
pub const TRANSACTION: u64 = 40;

/// The fixed part of a console print (`prints`, `printi`, `printhex`, …); the
/// variable part is [`per_byte`] of the output.
pub const CONSOLE: u64 = 10;

/// Per-byte surcharge for a PROVISIONAL intrinsic whose work scales with a buffer
/// (console output, serialized transactions): one point per byte. The measured
/// families above (hashes, memory, database values) use their own per-byte slopes.
#[inline]
pub fn per_byte(len: u64) -> u64 {
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    // These amounts are consensus values: metered points become billed CPU that is
    // committed to the block, so an accidental edit forks a network that didn't
    // also change it. This test pins the numbers the estimators produced. If you
    // change a cost deliberately (a coordinated upgrade), update the expected value
    // here in the same commit; if it fails unexpectedly, a cost was edited by
    // accident. See docs/intrinsic-cost-model.md.
    #[test]
    fn costs_are_pinned() {
        // MEASURED crypto / memory: base at len 0, plus their own per-byte slope.
        assert_eq!((sha256(0), sha256(1)), (2_000, 2_035));
        assert_eq!(sha512(0), 5_800);
        assert_eq!(sha1(0), 5_500);
        assert_eq!((ripemd160(0), ripemd160(1)), (16_600, 16_876));
        assert_eq!((memory(0), memory(1)), (300, 310));
        assert_eq!(RECOVER_KEY, 1_650_000);

        // MEASURED database tiers + value byte.
        assert_eq!((DB_STORE, DB_FIND, DB_ITERATE), (16_000, 6_500, 2_500));
        assert_eq!(db_value_per_byte(256), 11 * 256);

        // PROVISIONAL fixed costs.
        assert_eq!((BASE, AUTH), (5, 40));
        assert_eq!(per_byte(100), 100);
    }
}
