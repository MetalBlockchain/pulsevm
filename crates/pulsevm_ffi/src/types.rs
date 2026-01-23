use std::hash::{Hash, Hasher};

use cxx::{CxxString, SharedPtr, UniquePtr};
use pulsevm_error::ChainError;
use pulsevm_serialization::{NumBytes, Read};

use crate::{
    CxxSignature,
    types::ffi::{CxxBlockTimestamp, CxxDigest, CxxGenesisState, CxxPublicKey, CxxTimePoint},
};

#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    pub struct KeyWeight {
        key: SharedPtr<CxxPublicKey>,
        weight: u16,
    }

    pub struct PermissionLevel {
        actor: u64,
        permission: u64,
    }

    pub struct PermissionLevelWeight {
        permission: PermissionLevel,
        weight: u16,
    }

    pub struct WaitWeight {
        wait_sec: u32,
        weight: u16,
    }

    pub struct Authority {
        threshold: u32,
        keys: Vec<KeyWeight>,
        accounts: Vec<PermissionLevelWeight>,
        waits: Vec<WaitWeight>,
    }

    unsafe extern "C++" {
        include!("types.hpp");

        type CxxAuthority;

        type CxxBlockTimestamp;
        pub fn to_time_point(self: &CxxBlockTimestamp) -> SharedPtr<CxxTimePoint>;
        pub fn get_slot(self: &CxxBlockTimestamp) -> u32;

        type CxxChainConfig;
        pub fn get_max_block_net_usage(self: &CxxChainConfig) -> u64;
        pub fn get_target_block_net_usage_pct(self: &CxxChainConfig) -> u32;
        pub fn get_max_transaction_net_usage(self: &CxxChainConfig) -> u32;
        pub fn get_base_per_transaction_net_usage(self: &CxxChainConfig) -> u32;
        pub fn get_net_usage_leeway(self: &CxxChainConfig) -> u32;
        pub fn get_context_free_discount_net_usage_num(self: &CxxChainConfig) -> u32;
        pub fn get_context_free_discount_net_usage_den(self: &CxxChainConfig) -> u32;
        pub fn get_max_block_cpu_usage(self: &CxxChainConfig) -> u32;
        pub fn get_target_block_cpu_usage_pct(self: &CxxChainConfig) -> u32;
        pub fn get_max_transaction_cpu_usage(self: &CxxChainConfig) -> u32;
        pub fn get_min_transaction_cpu_usage(self: &CxxChainConfig) -> u32;
        pub fn get_max_transaction_lifetime(self: &CxxChainConfig) -> u32;
        pub fn get_deferred_trx_expiration_window(self: &CxxChainConfig) -> u32;
        pub fn get_max_transaction_delay(self: &CxxChainConfig) -> u32;
        pub fn get_max_inline_action_size(self: &CxxChainConfig) -> u32;
        pub fn get_max_inline_action_depth(self: &CxxChainConfig) -> u16;
        pub fn get_max_authority_depth(self: &CxxChainConfig) -> u16;
        pub fn get_max_action_return_value_size(self: &CxxChainConfig) -> u32;

        type CxxDigest;
        pub fn get_data(self: &CxxDigest) -> &[u8];
        pub fn empty(self: &CxxDigest) -> bool;

        type CxxGenesisState;
        pub fn get_initial_timestamp(self: &CxxGenesisState) -> &CxxTimePoint;
        pub fn get_initial_key(self: &CxxGenesisState) -> &CxxPublicKey;
        pub fn get_initial_configuration(self: &CxxGenesisState) -> &CxxChainConfig;

        type CxxMicroseconds;
        pub fn count(self: &CxxMicroseconds) -> i64;

        type CxxPublicKey;
        pub fn cmp(self: &CxxPublicKey, other: &CxxPublicKey) -> i32;
        pub fn pack(self: &CxxPublicKey) -> Vec<u8>;
        pub fn to_string_rust(self: &CxxPublicKey) -> &str;
        pub fn num_bytes(self: &CxxPublicKey) -> usize;

        type CxxSignature;
        pub fn cmp(self: &CxxSignature, other: &CxxSignature) -> i32;
        pub fn pack(self: &CxxSignature) -> Vec<u8>;
        pub fn to_string_rust(self: &CxxSignature) -> &str;
        pub fn num_bytes(self: &CxxSignature) -> usize;

        type CxxSharedBlob;
        pub fn get_data(self: &CxxSharedBlob) -> &[u8];
        pub fn size(self: &CxxSharedBlob) -> usize;

        type CxxTimePoint;
        pub fn time_since_epoch(self: &CxxTimePoint) -> &CxxMicroseconds;
        pub fn sec_since_epoch(self: &CxxTimePoint) -> u32;

        type CxxSharedAuthority;
        type CxxKeyWeight;
        type CxxPermissionLevelWeight;
        type CxxWaitWeight;
        type CxxPrivateKey;

        // Global functions
        pub fn make_empty_digest() -> UniquePtr<CxxDigest>;
        pub fn make_digest_from_data(data: &[u8]) -> UniquePtr<CxxDigest>;
        pub fn make_shared_digest_from_data(data: &[u8]) -> SharedPtr<CxxDigest>;
        pub fn make_time_point_from_now() -> SharedPtr<CxxTimePoint>;
        pub fn make_block_timestamp_from_now() -> SharedPtr<CxxBlockTimestamp>;
        pub fn make_block_timestamp_from_slot(slot: u32) -> SharedPtr<CxxBlockTimestamp>;
        pub fn make_time_point_from_i64(us: i64) -> SharedPtr<CxxTimePoint>;
        pub fn make_time_point_from_microseconds(us: &CxxMicroseconds) -> SharedPtr<CxxTimePoint>;
        pub fn parse_genesis_state(json: &str) -> Result<UniquePtr<CxxGenesisState>>;
        pub fn parse_public_key(key_str: &str) -> SharedPtr<CxxPublicKey>;
        pub fn parse_public_key_from_bytes(
            data: &[u8],
            pos: &mut usize,
        ) -> Result<SharedPtr<CxxPublicKey>>;
        pub fn parse_private_key(key_str: &str) -> SharedPtr<CxxPrivateKey>;
        pub fn sign_digest_with_private_key(
            digest: &CxxDigest,
            priv_key: &CxxPrivateKey,
        ) -> Result<SharedPtr<CxxSignature>>;
        pub fn parse_signature_from_bytes(
            data: &[u8],
            pos: &mut usize,
        ) -> Result<SharedPtr<CxxSignature>>;
        pub fn make_authority(
            threshold: u32,
            keys: &CxxVector<CxxKeyWeight>,
            accounts: &CxxVector<CxxPermissionLevelWeight>,
            waits: &CxxVector<CxxWaitWeight>,
        ) -> SharedPtr<CxxAuthority>;
        pub fn recover_public_key_from_signature(
            sig: &CxxSignature,
            digest: &CxxDigest,
        ) -> Result<SharedPtr<CxxPublicKey>>;
    }
}

impl CxxDigest {
    pub fn new_empty() -> UniquePtr<CxxDigest> {
        ffi::make_empty_digest()
    }

    pub fn hash(data: &[u8]) -> UniquePtr<CxxDigest> {
        ffi::make_digest_from_data(data)
    }
}

impl PartialEq for &CxxDigest {
    fn eq(&self, other: &Self) -> bool {
        self.get_data() == other.get_data()
    }
}

impl CxxTimePoint {
    pub fn new(microseconds: i64) -> SharedPtr<CxxTimePoint> {
        ffi::make_time_point_from_i64(microseconds)
    }

    pub fn now() -> SharedPtr<CxxTimePoint> {
        ffi::make_time_point_from_now()
    }
}

impl CxxBlockTimestamp {
    pub fn now() -> SharedPtr<CxxBlockTimestamp> {
        ffi::make_block_timestamp_from_now()
    }

    pub fn from_slot(slot: u32) -> SharedPtr<CxxBlockTimestamp> {
        ffi::make_block_timestamp_from_slot(slot)
    }
}

unsafe impl Send for ffi::CxxBlockTimestamp {}
unsafe impl Sync for ffi::CxxBlockTimestamp {}

impl CxxGenesisState {
    pub fn new(json: &str) -> Result<UniquePtr<CxxGenesisState>, ChainError> {
        ffi::parse_genesis_state(json)
            .map_err(|e| ChainError::ParseError(format!("failed to parse genesis state: {}", e)))
    }
}

impl PartialEq for CxxPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == 0
    }
}

impl Eq for CxxPublicKey {}

impl Hash for CxxPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pack().hash(state);
    }
}
