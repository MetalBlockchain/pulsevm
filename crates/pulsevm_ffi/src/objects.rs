use pulsevm_error::ChainError;

use crate::{Database, PermissionObject};

#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    unsafe extern "C++" {
        include!("name.hpp");
        include!("types.hpp");
        include!("objects.hpp");

        type AccountObject;
        type AccountMetadataObject;
        type PermissionObject;
        type PermissionUsageObject;
        type PermissionLinkObject;
        type CodeObject;
        type GlobalPropertyObject;
        type TableObject;
        type TableId;
        type KeyValueObject;

        type CxxDigest = crate::types::ffi::CxxDigest;
        type CxxName = crate::name::ffi::CxxName;
        type CxxSharedBlob = crate::types::ffi::CxxSharedBlob;
        type CxxChainConfig = crate::types::ffi::CxxChainConfig;

        // Account methods
        pub fn get_abi(self: &AccountObject) -> &CxxSharedBlob;

        // AccountMetadata methods
        pub fn get_code_hash(self: &AccountMetadataObject) -> &CxxDigest;
        pub fn get_recv_sequence(self: &AccountMetadataObject) -> u64;
        pub fn get_auth_sequence(self: &AccountMetadataObject) -> u64;
        pub fn get_code_sequence(self: &AccountMetadataObject) -> u64;
        pub fn get_abi_sequence(self: &AccountMetadataObject) -> u64;
        pub fn is_privileged(self: &AccountMetadataObject) -> bool;

        // CodeObject methods
        pub fn get_code_hash(self: &CodeObject) -> &CxxDigest;
        pub fn get_code(self: &CodeObject) -> &CxxSharedBlob;

        // PermissionObject methods
        pub fn get_id(self: &PermissionObject) -> i64;
        pub fn get_parent_id(self: &PermissionObject) -> i64;
        pub fn get_owner(self: &PermissionObject) -> &CxxName;
        pub fn get_name(self: &PermissionObject) -> &CxxName;

        // Methods on Table
        pub fn get_code(self: &TableObject) -> &CxxName;
        pub fn get_scope(self: &TableObject) -> &CxxName;
        pub fn get_table(self: &TableObject) -> &CxxName;
        pub fn get_payer(self: &TableObject) -> &CxxName;
        pub fn get_count(self: &TableObject) -> u32;

        // Methods on KeyValueObject
        pub fn get_table_id(self: &KeyValueObject) -> &TableId;
        pub fn get_primary_key(self: &KeyValueObject) -> u64;
        pub fn get_payer(self: &KeyValueObject) -> &CxxName;
        pub fn get_value(self: &KeyValueObject) -> &CxxSharedBlob;

        // Methods on GlobalPropertyObject
        pub fn get_chain_config(self: &GlobalPropertyObject) -> &CxxChainConfig;
    }
}

impl PermissionObject {
    pub fn satisfies(
        &self,
        other: &PermissionObject,
        db: &mut Database,
    ) -> Result<bool, ChainError> {
        Ok(true) // TODO: Fix this
    }
}
