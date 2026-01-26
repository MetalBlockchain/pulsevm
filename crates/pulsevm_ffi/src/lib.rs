mod bridge;
mod database;
mod iterator_cache;
mod name;
mod objects;
mod types;

use cxx::Exception;
use pulsevm_error::ChainError;

pub use crate::database::Database;
pub use crate::iterator_cache::CxxKeyValueIteratorCache;
pub use crate::name::ffi::{CxxName, string_to_name, u64_to_name};
pub use crate::objects::ffi::{
    AccountMetadataObject, AccountObject, CodeObject, GlobalPropertyObject, KeyValueObject,
    PermissionLinkObject, PermissionObject, PermissionUsageObject, TableId, TableObject,
};
pub use crate::types::ffi::{
    Authority, CxxBlockTimestamp, CxxChainConfig, CxxDigest, CxxGenesisState, CxxMicroseconds,
    CxxPrivateKey, CxxPublicKey, CxxSharedAuthority, CxxSharedBlob, CxxSignature, CxxTimePoint,
    KeyWeight, PermissionLevel, PermissionLevelWeight, WaitWeight, make_shared_digest_from_data,
    parse_private_key, parse_public_key_from_bytes, parse_signature_from_bytes,
    recover_public_key_from_signature, sign_digest_with_private_key, parse_signature,
};
