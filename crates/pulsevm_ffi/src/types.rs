use std::{
    fmt,
    hash::{Hash, Hasher},
};

use cxx::{CxxString, SharedPtr, UniquePtr};
use pulsevm_error::ChainError;
use pulsevm_serialization::{NumBytes, Read, Write, WriteError};
use serde::{Serialize, ser::SerializeStruct};

use crate::PermissionLevel;

#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    #[derive(Clone, PartialEq, Eq, Hash)]
    pub struct KeyWeight {
        key: SharedPtr<CxxPublicKey>,
        weight: u16,
    }

    #[derive(Clone, PartialEq, Eq, Hash)]
    pub struct PermissionLevel {
        actor: u64,
        permission: u64,
    }

    #[derive(Clone, PartialEq, Eq, Hash)]
    pub struct PermissionLevelWeight {
        permission: PermissionLevel,
        weight: u16,
    }

    #[derive(Clone, PartialEq, Eq, Hash)]
    pub struct WaitWeight {
        wait_sec: u32,
        weight: u16,
    }

    #[derive(Clone, PartialEq, Eq, Hash)]
    pub struct Authority {
        threshold: u32,
        keys: Vec<KeyWeight>,
        accounts: Vec<PermissionLevelWeight>,
        waits: Vec<WaitWeight>,
    }

    unsafe extern "C++" {
        include!("utils.hpp");

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
        pub fn get_max_inline_action_size(self: &CxxChainConfig) -> u32;
        pub fn get_max_inline_action_depth(self: &CxxChainConfig) -> u16;
        pub fn get_max_authority_depth(self: &CxxChainConfig) -> u16;
        pub fn get_max_action_return_value_size(self: &CxxChainConfig) -> u32;

        type CxxDigest;
        pub fn empty(self: &CxxDigest) -> bool;

        type CxxGenesisState;
        pub fn get_initial_timestamp(self: &CxxGenesisState) -> &CxxTimePoint;
        pub fn get_initial_key(self: &CxxGenesisState) -> &CxxPublicKey;
        pub fn get_initial_configuration(self: &CxxGenesisState) -> &CxxChainConfig;

        type CxxMicroseconds;
        pub fn count(self: &CxxMicroseconds) -> i64;

        type CxxPublicKey;
        pub fn cmp(self: &CxxPublicKey, other: &CxxPublicKey) -> i32;

        type CxxSignature;
        pub fn cmp(self: &CxxSignature, other: &CxxSignature) -> i32;

        type CxxSharedBlob;
        pub fn size(self: &CxxSharedBlob) -> usize;
        pub fn as_slice(self: &CxxSharedBlob) -> &[u8];

        type CxxTimePoint;
        pub fn time_since_epoch(self: &CxxTimePoint) -> &CxxMicroseconds;
        pub fn sec_since_epoch(self: &CxxTimePoint) -> u32;

        type CxxSharedAuthority;
        type CxxPrivateKey;

        // Global functions
        pub fn make_empty_digest() -> UniquePtr<CxxDigest>;
        pub fn make_digest_from_data(data: &[u8]) -> Result<UniquePtr<CxxDigest>>;
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
        pub fn parse_private_key(key_str: &str) -> Result<SharedPtr<CxxPrivateKey>>;
        pub fn sign_digest_with_private_key(
            digest: &CxxDigest,
            priv_key: &CxxPrivateKey,
        ) -> Result<SharedPtr<CxxSignature>>;
        pub fn parse_signature_from_bytes(
            data: &[u8],
            pos: &mut usize,
        ) -> Result<SharedPtr<CxxSignature>>;
        pub fn parse_signature(signature_str: &str) -> Result<SharedPtr<CxxSignature>>;
        pub fn recover_public_key_from_signature(
            sig: &CxxSignature,
            digest: &CxxDigest,
        ) -> Result<SharedPtr<CxxPublicKey>>;
        pub fn get_public_key_from_private_key(
            private_key: &CxxPrivateKey,
        ) -> SharedPtr<CxxPublicKey>;
        pub fn packed_public_key_bytes(
            public_key: &CxxPublicKey,
        ) -> Vec<u8>;
        pub fn public_key_to_string(
            public_key: &CxxPublicKey,
        ) -> &str;
        pub fn public_key_num_bytes(
            public_key: &CxxPublicKey,
        ) -> usize;
        pub fn packed_signature_bytes(
            signature: &CxxSignature,
        ) -> Vec<u8>;
        pub fn signature_to_string(
            signature: &CxxSignature,
        ) -> &str;
        pub fn signature_num_bytes(
            signature: &CxxSignature,
        ) -> usize;
        pub fn get_digest_data(
            digest: &CxxDigest,
        ) -> &[u8];
    }
}

impl ffi::CxxDigest {
    pub fn new_empty() -> UniquePtr<ffi::CxxDigest> {
        ffi::make_empty_digest()
    }

    pub fn hash(data: &[u8]) -> Result<UniquePtr<ffi::CxxDigest>, ChainError> {
        ffi::make_digest_from_data(data).map_err(|e| {
            ChainError::InternalError(format!("failed to create digest from data: {}", e))
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        ffi::get_digest_data(self)
    }
}

impl PartialEq for &ffi::CxxDigest {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl ffi::CxxTimePoint {
    pub fn new(microseconds: i64) -> SharedPtr<ffi::CxxTimePoint> {
        ffi::make_time_point_from_i64(microseconds)
    }

    pub fn now() -> SharedPtr<ffi::CxxTimePoint> {
        ffi::make_time_point_from_now()
    }
}

impl ffi::CxxBlockTimestamp {
    pub fn now() -> SharedPtr<ffi::CxxBlockTimestamp> {
        ffi::make_block_timestamp_from_now()
    }

    pub fn from_slot(slot: u32) -> SharedPtr<ffi::CxxBlockTimestamp> {
        ffi::make_block_timestamp_from_slot(slot)
    }
}

unsafe impl Send for ffi::CxxBlockTimestamp {}
unsafe impl Sync for ffi::CxxBlockTimestamp {}

impl ffi::CxxGenesisState {
    pub fn new(json: &str) -> Result<UniquePtr<ffi::CxxGenesisState>, ChainError> {
        ffi::parse_genesis_state(json)
            .map_err(|e| ChainError::ParseError(format!("failed to parse genesis state: {}", e)))
    }
}

impl PartialEq for ffi::CxxPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == 0
    }
}

impl Eq for ffi::CxxPublicKey {}

impl Hash for ffi::CxxPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.packed_bytes().hash(state);
    }
}

impl NumBytes for ffi::KeyWeight {
    fn num_bytes(&self) -> usize {
        self.key.num_bytes() + self.weight.num_bytes()
    }
}

impl NumBytes for ffi::PermissionLevel {
    fn num_bytes(&self) -> usize {
        self.actor.num_bytes() + self.permission.num_bytes()
    }
}

impl NumBytes for ffi::PermissionLevelWeight {
    fn num_bytes(&self) -> usize {
        self.permission.num_bytes() + self.weight.num_bytes()
    }
}

impl NumBytes for ffi::WaitWeight {
    fn num_bytes(&self) -> usize {
        self.wait_sec.num_bytes() + self.weight.num_bytes()
    }
}

impl NumBytes for ffi::Authority {
    fn num_bytes(&self) -> usize {
        self.threshold.num_bytes()
            + self.keys.num_bytes()
            + self.accounts.num_bytes()
            + self.waits.num_bytes()
    }
}

impl Read for ffi::KeyWeight {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let key = ffi::parse_public_key_from_bytes(bytes, pos).map_err(|e| {
            pulsevm_serialization::ReadError::CustomError(format!(
                "failed to parse public key in KeyWeight: {}",
                e
            ))
        })?;
        let weight = u16::read(bytes, pos)?;
        Ok(ffi::KeyWeight { key, weight })
    }
}

impl Read for ffi::PermissionLevel {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let actor = u64::read(bytes, pos)?;
        let permission = u64::read(bytes, pos)?;
        Ok(ffi::PermissionLevel { actor, permission })
    }
}

impl Read for ffi::PermissionLevelWeight {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let permission = ffi::PermissionLevel::read(bytes, pos)?;
        let weight = u16::read(bytes, pos)?;
        Ok(ffi::PermissionLevelWeight { permission, weight })
    }
}

impl Read for ffi::WaitWeight {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let wait_sec = u32::read(bytes, pos)?;
        let weight = u16::read(bytes, pos)?;
        Ok(ffi::WaitWeight { wait_sec, weight })
    }
}

impl Read for ffi::Authority {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let threshold = u32::read(bytes, pos)?;
        let keys = Vec::<ffi::KeyWeight>::read(bytes, pos)?;
        let accounts = Vec::<ffi::PermissionLevelWeight>::read(bytes, pos)?;
        let waits = Vec::<ffi::WaitWeight>::read(bytes, pos)?;
        Ok(ffi::Authority {
            threshold,
            keys,
            accounts,
            waits,
        })
    }
}

impl Serialize for ffi::Authority {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Authority", 4)?;
        state.serialize_field("threshold", &self.threshold)?;
        state.serialize_field("keys", &self.keys)?;
        state.serialize_field("accounts", &self.accounts)?;
        state.serialize_field("waits", &self.waits)?;
        state.end()
    }
}

impl Write for ffi::KeyWeight {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let packed_key = self.key.packed_bytes();
        packed_key.write(bytes, pos)?;
        self.weight.write(bytes, pos)?;
        Ok(())
    }
}

impl Serialize for ffi::KeyWeight {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("KeyWeight", 2)?;
        state.serialize_field("key", &self.key.to_string_rust())?;
        state.serialize_field("weight", &self.weight)?;
        state.end()
    }
}

impl Write for ffi::PermissionLevel {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.actor.write(bytes, pos)?;
        self.permission.write(bytes, pos)?;
        Ok(())
    }
}

impl Write for ffi::PermissionLevelWeight {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.permission.write(bytes, pos)?;
        self.weight.write(bytes, pos)?;
        Ok(())
    }
}

impl Serialize for ffi::PermissionLevelWeight {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PermissionLevelWeight", 2)?;
        state.serialize_field("permission", &self.permission)?;
        state.serialize_field("weight", &self.weight)?;
        state.end()
    }
}

impl Write for ffi::WaitWeight {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.wait_sec.write(bytes, pos)?;
        self.weight.write(bytes, pos)?;
        Ok(())
    }
}

impl Serialize for ffi::WaitWeight {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("WaitWeight", 2)?;
        state.serialize_field("wait_sec", &self.wait_sec)?;
        state.serialize_field("weight", &self.weight)?;
        state.end()
    }
}

impl Write for ffi::Authority {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.threshold.write(bytes, pos)?;
        self.keys.write(bytes, pos)?;
        self.accounts.write(bytes, pos)?;
        self.waits.write(bytes, pos)?;
        Ok(())
    }
}

impl fmt::Debug for ffi::KeyWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWeight")
            .field("key", &self.key.to_string_rust())
            .field("weight", &self.weight)
            .finish()
    }
}

impl fmt::Debug for ffi::PermissionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PermissionLevel")
            .field("actor", &self.actor)
            .field("permission", &self.permission)
            .finish()
    }
}

impl fmt::Display for ffi::PermissionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PermissionLevel(actor: {}, permission: {})",
            self.actor, self.permission
        )
    }
}

impl fmt::Debug for ffi::PermissionLevelWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PermissionLevelWeight")
            .field("permission", &self.permission)
            .field("weight", &self.weight)
            .finish()
    }
}

impl fmt::Debug for ffi::WaitWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WaitWeight")
            .field("wait_sec", &self.wait_sec)
            .field("weight", &self.weight)
            .finish()
    }
}

impl fmt::Debug for ffi::Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority")
            .field("threshold", &self.threshold)
            .field("keys", &self.keys)
            .field("accounts", &self.accounts)
            .field("waits", &self.waits)
            .finish()
    }
}

impl fmt::Display for ffi::Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Authority(threshold: {}, keys: {:?}, accounts: {:?}, waits: {:?})",
            self.threshold, self.keys, self.accounts, self.waits
        )
    }
}

impl ffi::Authority {
    pub fn new(
        threshold: u32,
        keys: Vec<ffi::KeyWeight>,
        accounts: Vec<ffi::PermissionLevelWeight>,
        waits: Vec<ffi::WaitWeight>,
    ) -> Self {
        ffi::Authority {
            threshold,
            keys,
            accounts,
            waits,
        }
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    pub fn keys(&self) -> &Vec<ffi::KeyWeight> {
        &self.keys
    }

    pub fn accounts(&self) -> &Vec<ffi::PermissionLevelWeight> {
        &self.accounts
    }

    pub fn waits(&self) -> &Vec<ffi::WaitWeight> {
        &self.waits
    }

    pub fn validate(&self) -> bool {
        return true;
    }
}

impl ffi::PermissionLevel {
    pub fn new(actor: u64, permission: u64) -> Self {
        ffi::PermissionLevel { actor, permission }
    }

    pub fn actor(&self) -> u64 {
        self.actor
    }

    pub fn permission(&self) -> u64 {
        self.permission
    }
}

impl Serialize for ffi::PermissionLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PermissionLevel", 2)?;
        state.serialize_field("actor", &self.actor)?;
        state.serialize_field("permission", &self.permission)?;
        state.end()
    }
}

impl ffi::KeyWeight {
    pub fn new(key: SharedPtr<ffi::CxxPublicKey>, weight: u16) -> Self {
        ffi::KeyWeight { key, weight }
    }
}

impl ffi::CxxPublicKey {
    pub fn packed_bytes(&self) -> Vec<u8> {
        ffi::packed_public_key_bytes(self)
    }

    pub fn to_string_rust(&self) -> &str {
        ffi::public_key_to_string(self)
    }

    pub fn num_bytes(&self) -> usize {
        ffi::public_key_num_bytes(self)
    }
}

impl ffi::CxxPrivateKey {
    pub fn get_public_key(&self) -> SharedPtr<ffi::CxxPublicKey> {
        ffi::get_public_key_from_private_key(self)
    }
}

impl ffi::CxxSignature {
    pub fn packed_bytes(&self) -> Vec<u8> {
        ffi::packed_signature_bytes(self)
    }

    pub fn to_string_rust(&self) -> &str {
        ffi::signature_to_string(self)
    }

    pub fn num_bytes(&self) -> usize {
        ffi::signature_num_bytes(self)
    }
}

unsafe impl Send for ffi::CxxSignature {}
unsafe impl Sync for ffi::CxxSignature {}
