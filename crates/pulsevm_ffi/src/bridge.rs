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
        include!("database.hpp");
        include!("name.hpp");

        #[cxx_name = "name"]
        type Name = crate::name::ffi::Name;
        #[cxx_name = "database_wrapper"]
        type Database;
        pub fn open_database(
            path: &str,
            flags: DatabaseOpenFlags,
            size: u64,
        ) -> UniquePtr<Database>;

        #[cxx_name = "undo_session"]
        type UndoSession;
        #[cxx_name = "account_object"]
        type Account = crate::objects::ffi::Account;
        #[cxx_name = "account_metadata_object"]
        type AccountMetadata = crate::objects::ffi::AccountMetadata;
        #[cxx_name = "code_object"]
        type CodeObject = crate::objects::ffi::CodeObject;
        #[cxx_name = "genesis_state"]
        type GenesisState = crate::types::ffi::GenesisState;
        #[cxx_name = "global_property_object"]
        type GlobalPropertyObject = crate::objects::ffi::GlobalPropertyObject;
        #[cxx_name = "table_id_object"]
        type Table = crate::objects::ffi::Table;
        #[cxx_name = "key_value_object"]
        type KeyValue = crate::objects::ffi::KeyValue;
        #[cxx_name = "signed_block"]
        type SignedBlock;
        #[cxx_name = "key_value_iterator_cache"]
        type KeyValueIteratorCache = crate::iterator_cache::ffi::KeyValueIteratorCache;
        #[cxx_name = "permission_object"]
        pub type PermissionObject = crate::objects::ffi::PermissionObject;
        #[cxx_name = "permission_usage_object"]
        pub type PermissionUsageObject = crate::objects::ffi::PermissionUsageObject;
        #[cxx_name = "permission_link_object"]
        pub type PermissionLinkObject = crate::objects::ffi::PermissionLinkObject;
        #[cxx_name = "digest_type"]
        type Digest = crate::types::ffi::Digest;
        #[cxx_name = "time_point"]
        type TimePoint = crate::types::ffi::TimePoint;
        #[cxx_name = "authority"]
        type Authority = crate::types::ffi::Authority;
        #[cxx_name = "shared_authority"]
        type SharedAuthority = crate::types::ffi::SharedAuthority;

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
            genesis_data: &GenesisState,
        ) -> Result<()>;

        // Account methods
        pub fn create_account(
            self: Pin<&mut Database>,
            account_name: &Name,
            creation_date: u32,
        ) -> Result<&Account>;
        pub fn find_account(self: &Database, account_name: &Name) -> Result<*const Account>;
        pub fn create_account_metadata(
            self: Pin<&mut Database>,
            account_name: &Name,
            is_privileged: bool,
        ) -> Result<&AccountMetadata>;
        pub fn find_account_metadata(
            self: &Database,
            account_name: &Name,
        ) -> Result<*const AccountMetadata>;
        pub fn set_privileged(
            self: Pin<&mut Database>,
            account: &Name,
            is_privileged: bool,
        ) -> Result<()>;
        pub fn unlink_account_code(
            self: Pin<&mut Database>,
            old_code_entry: &CodeObject,
        ) -> Result<()>;
        pub fn update_account_code(
            self: Pin<&mut Database>,
            account: &AccountMetadata,
            new_code: &[u8],
            head_block_num: u32,
            pending_block_time: &TimePoint,
            code_hash: &Digest,
            vm_type: u8,
            vm_version: u8,
        ) -> Result<()>;
        pub fn update_account_abi(
            self: Pin<&mut Database>,
            account: &Account,
            account_metadata: &AccountMetadata,
            abi: &[u8],
        ) -> Result<()>;

        // Code object methods
        pub fn get_code_object_by_hash(
            self: &Database,
            code_hash: &Digest,
            vm_type: u8,
            vm_version: u8,
        ) -> Result<&CodeObject>;

        // Resource methods
        pub fn initialize_resource_limits(self: Pin<&mut Database>) -> Result<()>;
        pub fn initialize_account_resource_limits(
            self: Pin<&mut Database>,
            account_name: &Name,
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
            account_name: &Name,
            ram_bytes: i64,
        ) -> Result<()>;
        pub fn verify_account_ram_usage(
            self: Pin<&mut Database>,
            account_name: &Name,
        ) -> Result<()>;
        pub fn get_account_ram_usage(self: Pin<&mut Database>, account_name: &Name) -> Result<i64>;
        pub fn set_account_limits(
            self: Pin<&mut Database>,
            account_name: &Name,
            ram_bytes: i64,
            net_weight: i64,
            cpu_weight: i64,
        ) -> Result<bool>;
        pub fn get_account_limits(
            self: Pin<&mut Database>,
            account_name: &Name,
            ram_bytes: &mut i64,
            net_weight: &mut i64,
            cpu_weight: &mut i64,
        ) -> Result<()>;
        pub fn get_total_cpu_weight(self: Pin<&mut Database>) -> Result<u64>;
        pub fn get_total_net_weight(self: Pin<&mut Database>) -> Result<u64>;
        pub fn get_account_net_limit(
            self: Pin<&mut Database>,
            name: &Name,
            greylist_limit: u32,
        ) -> Result<NetLimitResult>;
        pub fn get_account_cpu_limit(
            self: Pin<&mut Database>,
            name: &Name,
            greylist_limit: u32,
        ) -> Result<CpuLimitResult>;
        pub fn process_account_limit_updates(self: Pin<&mut Database>) -> Result<()>;
        pub fn get_table(
            self: Pin<&mut Database>,
            code: &Name,
            scope: &Name,
            table: &Name,
        ) -> Result<&Table>;
        pub fn create_table(
            self: Pin<&mut Database>,
            code: &Name,
            scope: &Name,
            table: &Name,
            payer: &Name,
        ) -> Result<&Table>;
        pub fn db_find_i64(
            self: Pin<&mut Database>,
            code: &Name,
            scope: &Name,
            table: &Name,
            id: u64,
            keyval_cache: Pin<&mut KeyValueIteratorCache>,
        ) -> Result<i32>;
        pub fn create_key_value_object(
            self: Pin<&mut Database>,
            table: &Table,
            payer: &Name,
            id: u64,
            buffer: &[u8],
        ) -> Result<&KeyValue>;
        pub fn update_key_value_object(
            self: Pin<&mut Database>,
            obj: &KeyValue,
            payer: &Name,
            buffer: &[u8],
        ) -> Result<()>;
        pub fn remove_table(self: Pin<&mut Database>, table: &Table) -> Result<()>;

        // Account methods
        pub fn is_account(self: &Database, account: &Name) -> Result<bool>;

        // Permission methods
        pub fn find_permission(self: &Database, id: i64) -> Result<*const PermissionObject>;
        pub fn find_permission_by_actor_and_permission(
            self: &Database,
            actor: &Name,
            permission: &Name,
        ) -> Result<*const PermissionObject>;
        pub fn delete_auth(
            self: Pin<&mut Database>,
            account: &Name,
            permission_name: &Name,
        ) -> Result<i64>;
        pub fn link_auth(
            self: Pin<&mut Database>,
            account_name: &Name,
            code_name: &Name,
            requirement_name: &Name,
            requirement_type: &Name,
        ) -> Result<i64>;
        pub fn unlink_auth(
            self: Pin<&mut Database>,
            account_name: &Name,
            code_name: &Name,
            requirement_type: &Name,
        ) -> Result<i64>;

        pub fn next_recv_sequence(
            self: Pin<&mut Database>,
            receiver_account: &AccountMetadata,
        ) -> Result<u64>;
        pub fn next_auth_sequence(self: Pin<&mut Database>, actor: &Name) -> Result<u64>;
        pub fn next_global_sequence(self: Pin<&mut Database>) -> Result<u64>;

        pub fn db_remove_i64(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut KeyValueIteratorCache>,
            iterator: i32,
            receiver: &Name,
        ) -> Result<i64>;
        pub fn db_next_i64(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut KeyValueIteratorCache>,
            iterator: i32,
            primary: &mut u64,
        ) -> Result<i32>;
        pub fn db_previous_i64(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut KeyValueIteratorCache>,
            iterator: i32,
            primary: &mut u64,
        ) -> Result<i32>;
        pub fn db_end_i64(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut KeyValueIteratorCache>,
            code: &Name,
            scope: &Name,
            table: &Name,
        ) -> Result<i32>;
        pub fn db_lowerbound_i64(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut KeyValueIteratorCache>,
            code: &Name,
            scope: &Name,
            table: &Name,
            id: u64,
        ) -> Result<i32>;
        pub fn db_upperbound_i64(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut KeyValueIteratorCache>,
            code: &Name,
            scope: &Name,
            table: &Name,
            id: u64,
        ) -> Result<i32>;
        pub fn remove_permission(
            self: Pin<&mut Database>,
            permission: &PermissionObject,
        ) -> Result<()>;
        pub fn create_permission(
            self: Pin<&mut Database>,
            account: &Name,
            name: &Name,
            parent: u64,
            auth: &Authority,
            creation_time: &TimePoint,
        ) -> Result<&PermissionObject>;
        pub fn modify_permission(
            self: Pin<&mut Database>,
            permission: &PermissionObject,
            authority: &Authority,
            pending_block_time: &TimePoint,
        ) -> Result<()>;
        pub fn lookup_linked_permission(
            self: &Database,
            account: &Name,
            code: &Name,
            requirement_type: &Name,
        ) -> Result<*const Name>;

        pub fn get_global_properties(self: &Database) -> Result<&GlobalPropertyObject>;

        // Methods on undo_session
        pub fn push(self: Pin<&mut UndoSession>) -> Result<()>;
        pub fn squash(self: Pin<&mut UndoSession>) -> Result<()>;
        pub fn undo(self: Pin<&mut UndoSession>) -> Result<()>;
    }
}

unsafe impl Send for ffi::Database {}
unsafe impl Sync for ffi::Database {}
