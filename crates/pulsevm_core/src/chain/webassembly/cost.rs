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
//! coordinated upgrade.
//!
//! The values are scaled to the operator table (a wasm `Call` is 2, a multiply
//! 3), not to measured wall-clock. They are a coherent starting point, not a
//! benchmarked truth; the size-dependent ones charge one point per byte, on the
//! order of the single wasm op that would otherwise touch each byte.
//!
//! [`WasmContext::charge`]: crate::chain::wasm_runtime::WasmContext::charge

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
/// `require_recipient`, …): walks an account's authority, so heavier than a
/// plain getter.
pub const AUTH: u64 = 40;

/// The fixed part of one row-level database operation (`db_find_i64`,
/// `db_get_i64`, `db_store_i64`, `db_next_i64`, the secondary-index variants,
/// …). Value-sized reads and writes add [`per_byte`] on top.
pub const DB_OP: u64 = 100;

/// A privileged intrinsic (`set_resource_limits`, `set_privileged`,
/// `set_proposed_producers`, …).
pub const PRIVILEGED: u64 = 40;

/// A producer / active-schedule intrinsic (`get_active_producers`).
pub const PRODUCER: u64 = 40;

/// A system intrinsic (`eosio_assert`, `eosio_exit`, `check_transaction_authorization`, …).
pub const SYSTEM: u64 = 10;

/// A transaction intrinsic (`send_inline`, `send_context_free_inline`,
/// `send_deferred`, `read_transaction`, …). The `send_*` and `read_*` variants
/// also pay [`per_byte`] over the serialized size.
pub const TRANSACTION: u64 = 40;

/// The fixed part of a cryptographic hash (`sha256`, `sha512`, `sha1`,
/// `ripemd160`, and their `assert_` forms); the variable part is [`per_byte`] of
/// the input.
pub const HASH: u64 = 30;

/// Public-key recovery from a signature (`recover_key`, `assert_recover_key`).
/// secp256k1 recovery dwarfs every other intrinsic, so it is priced near a
/// thousand ordinary ops.
pub const RECOVER_KEY: u64 = 2000;

/// The fixed part of a bulk memory op (`memcpy`, `memmove`, `memset`, `memcmp`);
/// the variable part is [`per_byte`] of the length.
pub const MEMORY: u64 = 10;

/// The fixed part of a console print (`prints`, `printi`, `printhex`, …); the
/// variable part is [`per_byte`] of the output.
pub const CONSOLE: u64 = 10;

/// Per-byte surcharge for an intrinsic whose work scales with a buffer: one
/// point per byte, matching the roughly one wasm op it takes to touch each byte.
#[inline]
pub fn per_byte(len: u64) -> u64 {
    len
}
