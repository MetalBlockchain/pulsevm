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
//! - **MEASURED** — the cryptographic hashes, key recovery, and bulk memory ops. Derived from the
//!   `estimate_intrinsic_costs` tool (an ignored test in `wasm_runtime`): native work benchmarked
//!   across input sizes, fit as base + per-byte, times a 3x safety multiplier so a point is an
//!   upper bound on real time. See `docs/intrinsic-cost-model.md`. These were the worst
//!   under-charges (key recovery was ~800x too cheap).
//! - **PROVISIONAL** — everything else (getters, builtins, auth, database, console, …). Still
//!   hand-scaled to the operator table, NOT benchmarked. The database and authority intrinsics in
//!   particular do real work (row I/O, authority walks) and are almost certainly under-charged;
//!   measuring them needs a stateful harness and is the next estimator to build. Flagged here so
//!   the mixed scale is explicit, not hidden.
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

/// A permission / authorization check (`require_auth`, `has_auth`,
/// `require_recipient`, …). PROVISIONAL and likely low: it walks an account's
/// authority with database reads.
pub const AUTH: u64 = 40;

/// The fixed part of one row-level database operation (`db_find_i64`,
/// `db_get_i64`, `db_store_i64`, `db_next_i64`, the secondary-index variants,
/// …). Value-sized reads and writes add [`per_byte`]. PROVISIONAL and likely
/// low: row I/O and index lookups are real work not yet measured.
pub const DB_OP: u64 = 100;

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

/// Per-byte surcharge for a PROVISIONAL intrinsic whose work scales with a
/// buffer (console output, serialized transactions, database values): one point
/// per byte. The measured families above use their own per-byte slopes instead.
#[inline]
pub fn per_byte(len: u64) -> u64 {
    len
}
