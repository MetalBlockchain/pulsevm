#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    // Shared enums between Rust and C++
    #[repr(u32)]
    enum DatabaseOpenFlags {
        ReadOnly = 0,
        ReadWrite = 1,
    }

    #[cxx_name = "cpu_limit_result"]
    struct CpuLimitResult {
        limit: i64,
        greylisted: bool,
    }

    #[cxx_name = "net_limit_result"]
    struct NetLimitResult {
        limit: i64,
        greylisted: bool,
    }

    unsafe extern "C++" {
        include!("catcher.hpp");
        include!("utils.hpp");
        include!("database.hpp");

        #[cxx_name = "database_wrapper"]
        type Database;
        pub fn open_database(
            path: &str,
            flags: DatabaseOpenFlags,
            size: u64,
        ) -> UniquePtr<Database>;

        type UndoSession;

        type CxxDigest = crate::types::ffi::CxxDigest;
        type CxxName = crate::name::ffi::CxxName;
        type CxxGenesisState = crate::types::ffi::CxxGenesisState;
        type CxxTimePoint = crate::types::ffi::CxxTimePoint;
        type Authority = crate::types::ffi::Authority;
        type CxxSharedAuthority = crate::types::ffi::CxxSharedAuthority;
        type CxxKeyValueIteratorCache = crate::iterator_cache::ffi::CxxKeyValueIteratorCache;

        type AccountObject = crate::objects::ffi::AccountObject;
        type AccountMetadataObject = crate::objects::ffi::AccountMetadataObject;
        type CodeObject = crate::objects::ffi::CodeObject;
        type GlobalPropertyObject = crate::objects::ffi::GlobalPropertyObject;
        type TableObject = crate::objects::ffi::TableObject;
        type KeyValueObject = crate::objects::ffi::KeyValueObject;
        type PermissionObject = crate::objects::ffi::PermissionObject;
        type PermissionUsageObject = crate::objects::ffi::PermissionUsageObject;
        type PermissionLinkObject = crate::objects::ffi::PermissionLinkObject;

        // Methods on database
        pub fn flush(self: Pin<&mut Database>);
        pub fn undo(self: Pin<&mut Database>);
        pub fn commit(self: Pin<&mut Database>, revision: i64);
        pub fn revision(self: &Database) -> i64;
        pub fn add_indices(self: Pin<&mut Database>);
        pub fn create_undo_session(
            self: Pin<&mut Database>,
            enabled: bool,
        ) -> Result<UniquePtr<UndoSession>>;

        // Init methods
        pub fn initialize_database(
            self: Pin<&mut Database>,
            genesis_data: &CxxGenesisState,
        ) -> Result<()>;

        // Account methods
        pub fn create_account(
            self: Pin<&mut Database>,
            account_name: u64,
            creation_date: u32,
        ) -> Result<&AccountObject>;
        pub fn find_account(self: &Database, account_name: u64) -> Result<*const AccountObject>;
        pub fn create_account_metadata(
            self: Pin<&mut Database>,
            account_name: u64,
            is_privileged: bool,
        ) -> Result<&AccountMetadataObject>;
        pub fn find_account_metadata(
            self: &Database,
            account_name: u64,
        ) -> Result<*const AccountMetadataObject>;
        pub fn set_privileged(
            self: Pin<&mut Database>,
            account: u64,
            is_privileged: bool,
        ) -> Result<()>;
        pub fn unlink_account_code(
            self: Pin<&mut Database>,
            old_code_entry: &CodeObject,
        ) -> Result<()>;
        pub fn update_account_code(
            self: Pin<&mut Database>,
            account: &AccountMetadataObject,
            new_code: &[u8],
            head_block_num: u32,
            pending_block_time: &CxxTimePoint,
            code_hash: &CxxDigest,
            vm_type: u8,
            vm_version: u8,
        ) -> Result<()>;
        pub fn update_account_abi(
            self: Pin<&mut Database>,
            account: &AccountObject,
            account_metadata: &AccountMetadataObject,
            abi: &[u8],
        ) -> Result<()>;

        // Code object methods
        pub fn get_code_object_by_hash(
            self: &Database,
            code_hash: &CxxDigest,
            vm_type: u8,
            vm_version: u8,
        ) -> Result<&CodeObject>;

        // Resource methods
        pub fn initialize_resource_limits(self: Pin<&mut Database>) -> Result<()>;
        pub fn initialize_account_resource_limits(
            self: Pin<&mut Database>,
            account_name: u64,
        ) -> Result<()>;
        pub fn add_transaction_usage(
            self: Pin<&mut Database>,
            accounts: &Vec<u64>,
            cpu_usage: u64,
            net_usage: u64,
            time_slot: u32,
        ) -> Result<()>;
        pub fn add_pending_ram_usage(
            self: Pin<&mut Database>,
            account_name: u64,
            ram_bytes: i64,
        ) -> Result<()>;
        pub fn verify_account_ram_usage(self: Pin<&mut Database>, account_name: u64) -> Result<()>;
        pub fn get_account_ram_usage(self: &Database, account_name: u64) -> Result<i64>;
        pub fn set_account_limits(
            self: Pin<&mut Database>,
            account_name: u64,
            ram_bytes: i64,
            net_weight: i64,
            cpu_weight: i64,
        ) -> Result<bool>;
        pub fn get_account_limits(
            self: &Database,
            account_name: u64,
            ram_bytes: &mut i64,
            net_weight: &mut i64,
            cpu_weight: &mut i64,
        ) -> Result<()>;
        pub fn get_total_cpu_weight(self: &Database) -> Result<u64>;
        pub fn get_total_net_weight(self: &Database) -> Result<u64>;
        pub fn get_account_net_limit(
            self: &Database,
            name: u64,
            greylist_limit: u32,
        ) -> Result<NetLimitResult>;
        pub fn get_account_cpu_limit(
            self: &Database,
            name: u64,
            greylist_limit: u32,
        ) -> Result<CpuLimitResult>;
        pub fn process_account_limit_updates(self: Pin<&mut Database>) -> Result<()>;
        pub fn find_table(
            self: &Database,
            code: u64,
            scope: u64,
            table: u64,
        ) -> Result<*const TableObject>;
        pub fn get_table(
            self: Pin<&mut Database>,
            code: u64,
            scope: u64,
            table: u64,
        ) -> Result<&TableObject>;
        pub fn create_table(
            self: Pin<&mut Database>,
            code: u64,
            scope: u64,
            table: u64,
            payer: u64,
        ) -> Result<&TableObject>;
        pub fn db_find_i64(
            self: Pin<&mut Database>,
            code: u64,
            scope: u64,
            table: u64,
            id: u64,
            keyval_cache: Pin<&mut CxxKeyValueIteratorCache>,
        ) -> Result<i32>;
        pub fn create_key_value_object(
            self: Pin<&mut Database>,
            table: &TableObject,
            payer: u64,
            id: u64,
            buffer: &[u8],
        ) -> Result<&KeyValueObject>;
        pub fn update_key_value_object(
            self: Pin<&mut Database>,
            obj: &KeyValueObject,
            payer: u64,
            buffer: &[u8],
        ) -> Result<()>;
        pub fn remove_table(self: Pin<&mut Database>, table: &TableObject) -> Result<()>;
        // Account methods
        pub fn is_account(self: &Database, account: u64) -> Result<bool>;

        // Permission methods
        pub fn find_permission(self: &Database, id: i64) -> Result<*const PermissionObject>;
        pub fn find_permission_by_actor_and_permission(
            self: &Database,
            actor: u64,
            permission: u64,
        ) -> Result<*const PermissionObject>;
        pub fn delete_auth(
            self: Pin<&mut Database>,
            account: u64,
            permission_name: u64,
        ) -> Result<i64>;
        pub fn link_auth(
            self: Pin<&mut Database>,
            account_name: u64,
            code_name: u64,
            requirement_name: u64,
            requirement_type: u64,
        ) -> Result<i64>;
        pub fn unlink_auth(
            self: Pin<&mut Database>,
            account_name: u64,
            code_name: u64,
            requirement_type: u64,
        ) -> Result<i64>;

        pub fn next_recv_sequence(
            self: Pin<&mut Database>,
            receiver_account: &AccountMetadataObject,
        ) -> Result<u64>;
        pub fn next_auth_sequence(self: Pin<&mut Database>, actor: u64) -> Result<u64>;
        pub fn next_global_sequence(self: Pin<&mut Database>) -> Result<u64>;

        pub fn db_remove_i64(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxKeyValueIteratorCache>,
            iterator: i32,
            receiver: u64,
        ) -> Result<i64>;
        pub fn db_next_i64(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxKeyValueIteratorCache>,
            iterator: i32,
            primary: &mut u64,
        ) -> Result<i32>;
        pub fn db_previous_i64(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxKeyValueIteratorCache>,
            iterator: i32,
            primary: &mut u64,
        ) -> Result<i32>;
        pub fn db_end_i64(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxKeyValueIteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
        ) -> Result<i32>;
        pub fn db_lowerbound_i64(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxKeyValueIteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            id: u64,
        ) -> Result<i32>;
        pub fn db_upperbound_i64(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxKeyValueIteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            id: u64,
        ) -> Result<i32>;
        pub fn remove_permission(
            self: Pin<&mut Database>,
            permission: &PermissionObject,
        ) -> Result<()>;
        pub fn create_permission(
            self: Pin<&mut Database>,
            account: u64,
            name: u64,
            parent: u64,
            auth: &Authority,
            creation_time: &CxxTimePoint,
        ) -> Result<&PermissionObject>;
        pub fn modify_permission(
            self: Pin<&mut Database>,
            permission: &PermissionObject,
            authority: &Authority,
            pending_block_time: &CxxTimePoint,
        ) -> Result<()>;
        pub fn lookup_linked_permission(
            self: &Database,
            account: u64,
            code: u64,
            requirement_type: u64,
        ) -> Result<*const CxxName>;

        pub fn get_global_properties(self: &Database) -> Result<&GlobalPropertyObject>;

        // Methods on undo_session
        pub fn push(self: Pin<&mut UndoSession>) -> Result<()>;
        pub fn squash(self: Pin<&mut UndoSession>) -> Result<()>;
        pub fn undo(self: Pin<&mut UndoSession>) -> Result<()>;
    }
}

unsafe impl Send for ffi::Database {}
unsafe impl Sync for ffi::Database {}

unsafe impl Send for ffi::UndoSession {}
unsafe impl Sync for ffi::UndoSession {}