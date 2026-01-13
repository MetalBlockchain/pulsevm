#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    unsafe extern "C++" {
        include!("contract_table_objects.hpp");

        #[cxx_name = "name"]
        pub type Name = crate::name::ffi::Name;
        #[cxx_name = "table_id_object"]
        pub type Table;
        #[cxx_name = "table_id"]
        pub type TableId;
        #[cxx_name = "key_value_object"]
        pub type KeyValue;
        #[cxx_name = "shared_blob"]
        pub type SharedBlob = crate::types::ffi::SharedBlob;

        // Methods on Table
        pub fn get_code(self: &Table) -> &Name;
        pub fn get_scope(self: &Table) -> &Name;
        pub fn get_table(self: &Table) -> &Name;
        pub fn get_payer(self: &Table) -> &Name;
        pub fn get_count(self: &Table) -> u32;

        // Methods on KeyValue
        pub fn get_table_id(self: &KeyValue) -> &TableId;
        pub fn get_primary(self: &KeyValue) -> u64;
        pub fn get_payer(self: &KeyValue) -> &Name;
        pub fn get_value(self: &KeyValue) -> &SharedBlob;
    }
}
