#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    unsafe extern "C++" {
        include!("objects.hpp");

        #[cxx_name = "account_object"]
        type Account;
        #[cxx_name = "account_metadata_object"]
        type AccountMetadata;
        #[cxx_name = "permission_object"]
        pub type PermissionObject;
        #[cxx_name = "permission_usage_object"]
        pub type PermissionUsageObject;
        #[cxx_name = "permission_link_object"]
        pub type PermissionLinkObject;
        #[cxx_name = "code_object"]
        pub type CodeObject;
        #[cxx_name = "name"]
        pub type Name = crate::name::ffi::Name;
        #[cxx_name = "table_id_object"]
        pub type Table;
        #[cxx_name = "table_id"]
        pub type TableId;
        #[cxx_name = "key_value_object"]
        pub type KeyValue;
        #[cxx_name = "digest_type"]
        pub type Digest = crate::types::ffi::Digest;
        #[cxx_name = "shared_blob"]
        pub type SharedBlob = crate::types::ffi::SharedBlob;

        // Account methods
        pub fn get_abi(self: &Account) -> &SharedBlob;

        // AccountMetadata methods
        pub fn get_code_hash(self: &AccountMetadata) -> &Digest;
        pub fn get_recv_sequence(self: &AccountMetadata) -> u64;
        pub fn get_auth_sequence(self: &AccountMetadata) -> u64;
        pub fn get_code_sequence(self: &AccountMetadata) -> u64;
        pub fn get_abi_sequence(self: &AccountMetadata) -> u64;

        // CodeObject methods
        pub fn get_code_hash(self: &CodeObject) -> &Digest;
        pub fn get_code(self: &CodeObject) -> &SharedBlob;

        // PermissionObject methods
        pub fn get_id(self: &PermissionObject) -> i64;
        pub fn get_parent_id(self: &PermissionObject) -> i64;

        // Methods on Table
        pub fn get_code(self: &Table) -> &Name;
        pub fn get_scope(self: &Table) -> &Name;
        pub fn get_table(self: &Table) -> &Name;
        pub fn get_payer(self: &Table) -> &Name;
        pub fn get_count(self: &Table) -> u32;

        // Methods on KeyValue
        pub fn get_table_id(self: &KeyValue) -> &TableId;
        pub fn get_primary_key(self: &KeyValue) -> u64;
        pub fn get_payer(self: &KeyValue) -> &Name;
        pub fn get_value(self: &KeyValue) -> &SharedBlob;
    }
}
