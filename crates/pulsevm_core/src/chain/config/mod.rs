mod node_config;
pub use node_config::NodeConfig;

use crate::name::Name;
use pulsevm_constants::PERCENT_100;
use pulsevm_name_macro::name;

pub const PLUGIN_VERSION: u32 = 43;
pub const VERSION: &str = "v0.0.1";

/// Metering points per microsecond of reference CPU time. This is the physical
/// anchor for the whole CPU model: the operator table plus the host-intrinsic
/// table in `webassembly::cost` both bill in these points, and one point is
/// ~1/38000 µs on reference hardware (measured by the `estimate_intrinsic_costs`
/// tool; see `docs/intrinsic-cost-model.md`).
///
/// It's the bridge between a wall-clock intuition and a point budget: a CPU
/// limit meant to buy `n` microseconds of work is `n * POINTS_PER_US` points.
/// The genesis `max_block_cpu_usage` / `max_transaction_cpu_usage` are chosen
/// this way. Note `cpu_usage_us` in the receipt is `u32`, so per-transaction
/// billed points must stay below ~4.29e9 (~113 ms of reference compute).
///
/// Changing this rescales billed CPU, so it's a consensus value.
pub const POINTS_PER_US: u64 = 38_000;

// Names
pub const NEWACCOUNT_NAME: Name = Name::new(name!("newaccount"));
pub const SETCODE_NAME: Name = Name::new(name!("setcode"));
pub const SETABI_NAME: Name = Name::new(name!("setabi"));
pub const UPDATEAUTH_NAME: Name = Name::new(name!("updateauth"));
pub const DELETEAUTH_NAME: Name = Name::new(name!("deleteauth"));
pub const LINKAUTH_NAME: Name = Name::new(name!("linkauth"));
pub const UNLINKAUTH_NAME: Name = Name::new(name!("unlinkauth"));
pub const ONERROR_NAME: Name = Name::new(name!("onerror"));
pub const ONBLOCK_NAME: Name = Name::new(name!("onblock"));

pub const fn eos_percent(value: u64, percentage: u32) -> u64 {
    (value * percentage as u64) / PERCENT_100
}
