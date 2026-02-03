mod bridge;
mod database;
mod iterator_cache;
mod objects;
mod types;

use pulsevm_error::ChainError;

pub use crate::bridge::ffi::DatabaseOpenFlags;
pub use crate::bridge::ffi::{
    AccountMetadataObject, AccountObject, Authority, CodeObject, GlobalPropertyObject,
    KeyValueObject, KeyWeight, PermissionLevel, PermissionLevelWeight, PermissionLinkObject,
    PermissionObject, PermissionUsageObject, TableId, TableObject, WaitWeight,
};
pub use crate::bridge::ffi::{
    CxxBlockTimestamp, CxxChainConfig, CxxDigest, CxxGenesisState, CxxMicroseconds, CxxPrivateKey,
    CxxPublicKey, CxxSignature, CxxTimePoint,
};
pub use crate::bridge::ffi::{CxxName, string_to_name, u64_to_name};
pub use crate::bridge::ffi::{
    make_k1_private_key, make_shared_digest_from_data, make_shared_digest_from_existing_hash,
    make_shared_digest_from_string, make_unknown_public_key, parse_private_key, parse_public_key,
    parse_public_key_from_bytes, parse_signature, parse_signature_from_bytes,
    recover_public_key_from_signature, sign_digest_with_private_key,
};
pub use crate::database::Database;
pub use crate::iterator_cache::KeyValueIteratorCache;
