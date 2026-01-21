use std::hash::{Hash, Hasher};

use cxx::{CxxString, SharedPtr, UniquePtr};
use pulsevm_error::ChainError;

use crate::{
    BlockTimestamp, PublicKey, TimePoint, bridge::ffi::GenesisState, types::ffi::{Digest, SharedBlob}
};

#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    unsafe extern "C++" {
        include!("types.hpp");

        #[cxx_name = "authority"]
        type Authority;

        #[cxx_name = "block_timestamp_type"]
        type BlockTimestamp;
        pub fn to_time_point(self: &BlockTimestamp) -> SharedPtr<TimePoint>;
        pub fn get_slot(self: &BlockTimestamp) -> u32;

        #[cxx_name = "chain_config"]
        type ChainConfig;
        pub fn get_max_block_net_usage(self: &ChainConfig) -> u64;
        pub fn get_target_block_net_usage_pct(self: &ChainConfig) -> u32;
        pub fn get_max_transaction_net_usage(self: &ChainConfig) -> u32;
        pub fn get_base_per_transaction_net_usage(self: &ChainConfig) -> u32;
        pub fn get_net_usage_leeway(self: &ChainConfig) -> u32;
        pub fn get_context_free_discount_net_usage_num(self: &ChainConfig) -> u32;
        pub fn get_context_free_discount_net_usage_den(self: &ChainConfig) -> u32;
        pub fn get_max_block_cpu_usage(self: &ChainConfig) -> u32;
        pub fn get_target_block_cpu_usage_pct(self: &ChainConfig) -> u32;
        pub fn get_max_transaction_cpu_usage(self: &ChainConfig) -> u32;
        pub fn get_min_transaction_cpu_usage(self: &ChainConfig) -> u32;
        pub fn get_max_transaction_lifetime(self: &ChainConfig) -> u32;
        pub fn get_deferred_trx_expiration_window(self: &ChainConfig) -> u32;
        pub fn get_max_transaction_delay(self: &ChainConfig) -> u32;
        pub fn get_max_inline_action_size(self: &ChainConfig) -> u32;
        pub fn get_max_inline_action_depth(self: &ChainConfig) -> u16;
        pub fn get_max_authority_depth(self: &ChainConfig) -> u16;
        pub fn get_max_action_return_value_size(self: &ChainConfig) -> u32;

        #[cxx_name = "digest_type"]
        type Digest;
        pub fn get_data(self: &Digest) -> &[u8];
        pub fn empty(self: &Digest) -> bool;

        #[cxx_name = "genesis_state"]
        type GenesisState;
        pub fn get_initial_timestamp(self: &GenesisState) -> &TimePoint;
        pub fn get_initial_key(self: &GenesisState) -> &PublicKey;
        pub fn get_initial_configuration(self: &GenesisState) -> &ChainConfig;

        #[cxx_name = "microseconds"]
        type Microseconds;
        pub fn count(self: &Microseconds) -> i64;

        #[cxx_name = "public_key_type"]
        type PublicKey;
        pub fn cmp(self: &PublicKey, other: &PublicKey) -> i32;
        pub fn pack(self: &PublicKey) -> Vec<u8>;

        #[cxx_name = "shared_blob"]
        type SharedBlob;
        pub fn get_data(self: &SharedBlob) -> &[u8];
        pub fn size(self: &SharedBlob) -> usize;

        #[cxx_name = "time_point"]
        type TimePoint;
        pub fn time_since_epoch(self: &TimePoint) -> &Microseconds;
        pub fn sec_since_epoch(self: &TimePoint) -> u32;

        #[cxx_name = "shared_authority"]
        type SharedAuthority;

        // Global functions
        pub fn make_empty_digest() -> UniquePtr<Digest>;
        pub fn make_digest_from_data(data: &[u8]) -> UniquePtr<Digest>;
        pub fn make_time_point_from_now() -> SharedPtr<TimePoint>;
        pub fn make_block_timestamp_from_now() -> SharedPtr<BlockTimestamp>;
        pub fn make_block_timestamp_from_slot(slot: u32) -> SharedPtr<BlockTimestamp>;
        pub fn make_time_point_from_i64(us: i64) -> SharedPtr<TimePoint>;
        pub fn make_time_point_from_microseconds(us: &Microseconds) -> SharedPtr<TimePoint>;
        pub fn parse_genesis_state(json: &str) -> Result<UniquePtr<GenesisState>>;
        pub fn parse_public_key(key_str: &str) -> SharedPtr<PublicKey>;
    }
}

impl Digest {
    pub fn new_empty() -> UniquePtr<Digest> {
        ffi::make_empty_digest()
    }

    pub fn hash(data: &[u8]) -> UniquePtr<Digest> {
        ffi::make_digest_from_data(data)
    }
}

impl PartialEq for &Digest {
    fn eq(&self, other: &Self) -> bool {
        self.get_data() == other.get_data()
    }
}

impl TimePoint {
    pub fn new(microseconds: i64) -> SharedPtr<TimePoint> {
        ffi::make_time_point_from_i64(microseconds)
    }

    pub fn now() -> SharedPtr<TimePoint> {
        ffi::make_time_point_from_now()
    }
}

impl BlockTimestamp {
    pub fn now() -> SharedPtr<BlockTimestamp> {
        ffi::make_block_timestamp_from_now()
    }

    pub fn from_slot(slot: u32) -> SharedPtr<BlockTimestamp> {
        ffi::make_block_timestamp_from_slot(slot)
    }
}

unsafe impl Send for ffi::BlockTimestamp {}
unsafe impl Sync for ffi::BlockTimestamp {}

impl GenesisState {
    pub fn new(json: &str) -> Result<UniquePtr<GenesisState>, ChainError> {
        ffi::parse_genesis_state(json)
            .map_err(|e| ChainError::ParseError(format!("failed to parse genesis state: {}", e)))
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == 0
    }
}

impl Eq for PublicKey {}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pack().hash(state);
    }
}