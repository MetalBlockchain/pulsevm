pub const PLUGIN_VERSION: u32 = 38;
pub const VERSION: &str = "v0.0.1";

pub const OVERHEAD_PER_ACCOUNT_RAM_BYTES: u32 = 2048;
pub const OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES: u32 = 32;
pub const BILLABLE_ALIGNMENT: u64 = 16;
pub const FIXED_OVERHEAD_SHARED_VECTOR_RAM_BYTES: u32 = 32;
pub const SETCODE_RAM_BYTES_MULTIPLIER: u32 = 10;

pub const FIXED_NET_OVERHEAD_OF_PACKED_TRX: u32 = 16;

pub const RATE_LIMITING_PRECISION: u64 = 1000 * 1000;

pub const BLOCK_INTERVAL_MS: u32 = 500;

pub const PERCENT_100: u64 = 10000; // Assuming EOS uses basis points (10000 = 100%)
pub const PERCENT_1: u64 = 100; // Assuming EOS uses basis points (100 = 1%)

pub const ACCOUNT_CPU_USAGE_AVERAGE_WINDOW_MS: u32 = 24 * 60 * 60 * 1000;
pub const ACCOUNT_NET_USAGE_AVERAGE_WINDOW_MS: u32 = 24 * 60 * 60 * 1000;
pub const BLOCK_CPU_USAGE_AVERAGE_WINDOW_MS: u32 = 60 * 1000;
pub const BLOCK_SIZE_AVERAGE_WINDOW_MS: u32 = 60 * 1000;
pub const MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER: u32 = 1000;

pub const DEFAULT_MAX_BLOCK_NET_USAGE: u32 = 1024 * 1024;
pub const DEFAULT_TARGET_BLOCK_NET_USAGE_PCT: u32 = 10 * PERCENT_1 as u32; // 10%
pub const DEFAULT_MAX_TRANSACTION_NET_USAGE: u32 = DEFAULT_MAX_BLOCK_NET_USAGE / 2;
pub const DEFAULT_BASE_PER_TRANSACTION_NET_USAGE: u32 = 12; // 12 bytes (11 bytes for worst case of transaction_receipt_header + 1 byte for static_variant tag)
pub const DEFAULT_NET_USAGE_LEEWAY: u32 = 500; // 500 bytes
pub const DEFAULT_CONTEXT_FREE_DISCOUNT_NET_USAGE_NUMERATOR: u32 = 20;
pub const DEFAULT_CONTEXT_FREE_DISCOUNT_NET_USAGE_DENOMINATOR: u32 = 100;
pub const TRANSACTION_ID_NET_USAGE: u32 = 32; // 32 bytes

pub const DEFAULT_MAX_BLOCK_CPU_USAGE: u32 = 200_000;
pub const DEFAULT_TARGET_BLOCK_CPU_USAGE_PCT: u32 = 10 * PERCENT_1 as u32; // 10%
pub const DEFAULT_MAX_TRANSACTION_CPU_USAGE: u32 = 3 * DEFAULT_MAX_BLOCK_CPU_USAGE / 4; // 75%
pub const DEFAULT_MIN_TRANSACTION_CPU_USAGE: u32 = 100;

// Names
pub const NEWACCOUNT_NAME: u64 = name!("newaccount");
pub const SETCODE_NAME: u64 = name!("setcode");
pub const SETABI_NAME: u64 = name!("setabi");
pub const UPDATEAUTH_NAME: u64 = name!("updateauth");
pub const DELETEAUTH_NAME: u64 = name!("deleteauth");
pub const LINKAUTH_NAME: u64 = name!("linkauth");
pub const UNLINKAUTH_NAME: u64 = name!("unlinkauth");
pub const ONERROR_NAME: u64 = name!("onerror");
pub const ONBLOCK_NAME: u64 = name!("onblock");

pub trait BillableSize {
    fn billable_size() -> u64;
}

pub fn billable_size_v<T: BillableSize>() -> u64 {
    return ((T::billable_size() + BILLABLE_ALIGNMENT - 1) / BILLABLE_ALIGNMENT) * BILLABLE_ALIGNMENT;
}

pub const fn eos_percent(value: u64, percentage: u32) -> u64 {
    (value * percentage as u64) / PERCENT_100
}

use pulsevm_ffi::{KeyValueObject, TableObject};
use pulsevm_proc_macros::name;

impl BillableSize for KeyValueObject {
    fn billable_size() -> u64 {
        16 + OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64 // TODO: Check this
    }
}

impl BillableSize for TableObject {
    fn billable_size() -> u64 {
        64 + OVERHEAD_PER_ACCOUNT_RAM_BYTES as u64 // TODO: Check this
    }
}
