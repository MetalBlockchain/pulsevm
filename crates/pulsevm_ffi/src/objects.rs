#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    unsafe extern "C++" {
        include!("objects.hpp");

        #[cxx_name = "permission_object"]
        pub type PermissionObject;
        #[cxx_name = "permission_usage_object"]
        pub type PermissionUsageObject;
        #[cxx_name = "permission_link_object"]
        pub type PermissionLinkObject;
        #[cxx_name = "code_object"]
        pub type CodeObject;

        // PermissionObject methods
        pub fn get_id(self: &PermissionObject) -> i64;
        pub fn get_parent_id(self: &PermissionObject) -> i64;
    }
}
