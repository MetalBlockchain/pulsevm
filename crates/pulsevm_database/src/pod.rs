//! Pure-Rust plain-old-data types that used to be sourced from the cxx bridge.
//!
//! These carry values across the host/wasm boundary and into the arena; they are
//! byte-for-byte the same layout the bridge structs had, so the wasm database
//! host functions and the arena secondary-index writers keep working unchanged
//! while no longer depending on the C++ bridge.

/// A 256-bit secondary key, stored as its raw 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct U256 {
    pub value: [u8; 32],
}

/// A 128-bit float (`long double` secondary key) as its raw little-endian halves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Float128 {
    pub lo: u64,
    pub hi: u64,
}

/// The result of a per-account net-limit query: the effective limit and whether
/// the account is greylisted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NetLimitResult {
    pub limit: i64,
    pub greylisted: bool,
}

/// The result of a per-account cpu-limit query: the effective limit and whether
/// the account is greylisted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CpuLimitResult {
    pub limit: i64,
    pub greylisted: bool,
}
