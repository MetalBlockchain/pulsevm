#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    // Shared enums between Rust and C++
    #[repr(u32)]
    enum DatabaseOpenFlags {
        ReadOnly = 0,
        ReadWrite = 1,
    }

    struct CpuLimitResult {
        limit: i64,
        greylisted: bool,
    }

    struct NetLimitResult {
        limit: i64,
        greylisted: bool,
    }

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

    #[derive(Clone, PartialEq, Eq, Hash)]
    pub struct Genesis {
        test: u64,
        test2: u32,
    }

    unsafe extern "C++" {
        include!("catcher.hpp");
        include!("utils.hpp");
        include!("name.hpp");
        include!("database.hpp");
        include!("iterator_cache.hpp");
        include!("api.hpp");

        pub fn open_database(
            path: &str,
            flags: DatabaseOpenFlags,
            size: u64,
        ) -> UniquePtr<Database>;

        #[cxx_name = "database_wrapper"]
        type Database;

        #[cxx_name = "session"]
        type UndoSession;

        // Database objects
        #[cxx_name = "account_object"]
        type AccountObject;
        pub fn get_creation_date(self: &AccountObject) -> &CxxBlockTimestamp;
        pub fn get_abi(self: &AccountObject) -> &CxxSharedBlob;

        #[cxx_name = "account_metadata_object"]
        type AccountMetadataObject;
        pub fn get_code_hash(self: &AccountMetadataObject) -> &CxxDigest;
        pub fn get_recv_sequence(self: &AccountMetadataObject) -> u64;
        pub fn get_auth_sequence(self: &AccountMetadataObject) -> u64;
        pub fn get_code_sequence(self: &AccountMetadataObject) -> u64;
        pub fn get_abi_sequence(self: &AccountMetadataObject) -> u64;
        pub fn get_last_code_update(self: &AccountMetadataObject) -> &CxxTimePoint;
        pub fn is_privileged(self: &AccountMetadataObject) -> bool;

        #[cxx_name = "permission_object"]
        type PermissionObject;
        pub fn get_id(self: &PermissionObject) -> i64;
        pub fn get_parent_id(self: &PermissionObject) -> i64;
        pub fn get_owner(self: &PermissionObject) -> &CxxName;
        pub fn get_name(self: &PermissionObject) -> &CxxName;
        pub fn get_authority(self: &PermissionObject) -> &CxxSharedAuthority;

        #[cxx_name = "permission_usage_object"]
        type PermissionUsageObject;

        #[cxx_name = "permission_link_object"]
        type PermissionLinkObject;

        #[cxx_name = "code_object"]
        type CodeObject;
        pub fn get_code_hash(self: &CodeObject) -> &CxxDigest;
        pub fn get_code(self: &CodeObject) -> &CxxSharedBlob;

        #[cxx_name = "global_property_object"]
        type GlobalPropertyObject;
        pub fn get_chain_config(self: &GlobalPropertyObject) -> &CxxChainConfig;

        #[cxx_name = "table_id_object"]
        type TableObject;
        pub fn get_code(self: &TableObject) -> &CxxName;
        pub fn get_scope(self: &TableObject) -> &CxxName;
        pub fn get_table(self: &TableObject) -> &CxxName;
        pub fn get_payer(self: &TableObject) -> &CxxName;
        pub fn get_count(self: &TableObject) -> u32;

        #[cxx_name = "table_id"]
        type TableId;

        #[cxx_name = "key_value_object"]
        type KeyValueObject;
        pub fn get_table_id(self: &KeyValueObject) -> &TableId;
        pub fn get_primary_key(self: &KeyValueObject) -> u64;
        pub fn get_payer(self: &KeyValueObject) -> &CxxName;
        pub fn get_value(self: &KeyValueObject) -> &CxxSharedBlob;

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
        pub fn initialize_database(
            self: Pin<&mut Database>,
            genesis_data: &CxxGenesisState,
        ) -> Result<()>;
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
        pub fn get_code_object_by_hash(
            self: &Database,
            code_hash: &CxxDigest,
            vm_type: u8,
            vm_version: u8,
        ) -> Result<&CodeObject>;
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
        pub fn is_account(self: &Database, account: u64) -> Result<bool>;
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
        pub fn permission_satisfies_other_permission(
            self: &Database,
            permission: &PermissionObject,
            required_permission: &PermissionObject,
        ) -> Result<bool>;
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
        pub fn get_virtual_block_cpu_limit(self: &Database) -> Result<u64>;
        pub fn get_virtual_block_net_limit(self: &Database) -> Result<u64>;
        pub fn get_block_cpu_limit(self: &Database) -> Result<u64>;
        pub fn get_block_net_limit(self: &Database) -> Result<u64>;

        // Methods on undo_session
        pub fn push(self: Pin<&mut UndoSession>) -> Result<()>;
        pub fn squash(self: Pin<&mut UndoSession>) -> Result<()>;
        pub fn undo(self: Pin<&mut UndoSession>) -> Result<()>;

        pub type CxxKeyValueIteratorCache;
        pub fn new_key_value_iterator_cache() -> UniquePtr<CxxKeyValueIteratorCache>;
        pub fn cache_table(
            self: Pin<&mut CxxKeyValueIteratorCache>,
            table: &TableObject,
        ) -> Result<i32>;
        pub fn get_table(
            self: &CxxKeyValueIteratorCache,
            table_id: &TableId,
        ) -> Result<&TableObject>;
        pub fn get_end_iterator_by_table_id(
            self: &CxxKeyValueIteratorCache,
            table_id: &TableId,
        ) -> Result<i32>;
        pub fn find_table_by_end_iterator(
            self: &CxxKeyValueIteratorCache,
            ei: i32,
        ) -> Result<*const TableObject>;
        pub fn get(self: &CxxKeyValueIteratorCache, iterator: i32) -> Result<&KeyValueObject>;
        pub fn remove(self: Pin<&mut CxxKeyValueIteratorCache>, iterator: i32) -> Result<()>;
        pub fn add(self: Pin<&mut CxxKeyValueIteratorCache>, obj: &KeyValueObject) -> Result<i32>;

        pub type CxxBlockTimestamp;
        pub fn to_time_point(self: &CxxBlockTimestamp) -> SharedPtr<CxxTimePoint>;
        pub fn get_slot(self: &CxxBlockTimestamp) -> u32;

        pub type CxxChainConfig;
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

        #[cxx_name = "public_key_type"]
        pub type CxxPublicKey;
        pub fn cmp(self: &CxxPublicKey, other: &CxxPublicKey) -> i32;

        type CxxDigest;
        pub fn empty(self: &CxxDigest) -> bool;

        type CxxGenesisState;
        pub fn get_initial_timestamp(self: &CxxGenesisState) -> &CxxTimePoint;
        pub fn get_initial_key(self: &CxxGenesisState) -> &CxxPublicKey;
        pub fn get_initial_configuration(self: &CxxGenesisState) -> &CxxChainConfig;

        type CxxMicroseconds;
        pub fn count(self: &CxxMicroseconds) -> i64;

        type CxxSignature;
        pub fn cmp(self: &CxxSignature, other: &CxxSignature) -> i32;

        type CxxSharedBlob;
        pub fn size(self: &CxxSharedBlob) -> usize;

        type CxxTimePoint;
        pub fn time_since_epoch(self: &CxxTimePoint) -> &CxxMicroseconds;
        pub fn sec_since_epoch(self: &CxxTimePoint) -> u32;

        type CxxSharedAuthority;
        pub fn get_billable_size(self: &CxxSharedAuthority) -> usize;

        type CxxSharedKeyWeight;

        type CxxPrivateKey;

        // Global functions
        pub fn make_empty_digest() -> UniquePtr<CxxDigest>;
        pub fn make_digest_from_data(data: &[u8]) -> Result<UniquePtr<CxxDigest>>;
        pub fn make_shared_digest_from_data(data: &[u8]) -> SharedPtr<CxxDigest>;
        pub fn make_shared_digest_from_existing_hash(data: &[u8]) -> SharedPtr<CxxDigest>;
        pub fn make_shared_digest_from_string(key_str: &str) -> SharedPtr<CxxDigest>;
        pub fn make_time_point_from_now() -> SharedPtr<CxxTimePoint>;
        pub fn make_block_timestamp_from_now() -> SharedPtr<CxxBlockTimestamp>;
        pub fn make_block_timestamp_from_slot(slot: u32) -> SharedPtr<CxxBlockTimestamp>;
        pub fn make_time_point_from_i64(us: i64) -> SharedPtr<CxxTimePoint>;
        pub fn make_time_point_from_microseconds(us: &CxxMicroseconds) -> SharedPtr<CxxTimePoint>;
        pub fn parse_genesis_state(json: &str) -> Result<UniquePtr<CxxGenesisState>>;
        pub fn parse_public_key(key_str: &str) -> Result<SharedPtr<CxxPublicKey>>;
        pub fn parse_public_key_from_bytes(data: &[u8]) -> Result<SharedPtr<CxxPublicKey>>;
        pub fn parse_private_key(key_str: &str) -> Result<SharedPtr<CxxPrivateKey>>;
        pub fn private_key_to_string(private_key: &CxxPrivateKey) -> String;
        pub fn sign_digest_with_private_key(
            digest: &CxxDigest,
            priv_key: &CxxPrivateKey,
        ) -> Result<SharedPtr<CxxSignature>>;
        pub fn parse_signature_from_bytes(data: &[u8]) -> Result<SharedPtr<CxxSignature>>;
        pub fn parse_signature(signature_str: &str) -> Result<SharedPtr<CxxSignature>>;
        pub fn recover_public_key_from_signature(
            sig: &CxxSignature,
            digest: &CxxDigest,
        ) -> Result<SharedPtr<CxxPublicKey>>;
        pub fn get_public_key_from_private_key(
            private_key: &CxxPrivateKey,
        ) -> SharedPtr<CxxPublicKey>;
        pub fn packed_public_key_bytes(public_key: &CxxPublicKey) -> Vec<u8>;
        pub fn public_key_to_string(public_key: &CxxPublicKey) -> String;
        pub fn public_key_num_bytes(public_key: &CxxPublicKey) -> usize;
        pub fn packed_signature_bytes(signature: &CxxSignature) -> Vec<u8>;
        pub fn signature_to_string(signature: &CxxSignature) -> String;
        pub fn signature_num_bytes(signature: &CxxSignature) -> usize;
        pub fn get_digest_data(digest: &CxxDigest) -> &[u8];
        pub fn get_shared_blob_data(blob: &CxxSharedBlob) -> &[u8];
        pub fn get_authority_from_shared_authority(shared_auth: &CxxSharedAuthority) -> Authority;
        pub fn make_unknown_public_key() -> SharedPtr<CxxPublicKey>;
        pub fn make_k1_private_key(secret: &CxxDigest) -> SharedPtr<CxxPrivateKey>;
        pub fn extract_chain_id_from_genesis_state(genesis: &CxxGenesisState) -> Vec<u8>;

        pub type CxxName;

        // Name methods
        pub fn u64_to_name(val: u64) -> UniquePtr<CxxName>;
        pub fn string_to_name(str: &str) -> Result<UniquePtr<CxxName>>;
        pub fn name_to_uint64(name: &CxxName) -> u64;
        pub fn to_uint64_t(self: &CxxName) -> u64;
        pub fn empty(self: &CxxName) -> bool;

        // API methods
        pub fn get_account_info_without_core_symbol(
            db: &Database,
            account: u64,
            head_block_num: u32,
            head_block_time: &CxxTimePoint,
        ) -> Result<String>;
        pub fn get_account_info_with_core_symbol(
            db: &Database,
            account: u64,
            expected_core_symbol: &str,
            head_block_num: u32,
            head_block_time: &CxxTimePoint,
        ) -> Result<String>;
        pub fn get_currency_balance_with_symbol(
            db: &Database,
            code: u64,
            account: u64,
            symbol: &str,
        ) -> Result<String>;
        pub fn get_currency_balance_without_symbol(
            db: &Database,
            code: u64,
            account: u64,
        ) -> Result<String>;
        pub fn get_currency_stats(db: &Database, code: u64, symbol: &str) -> Result<String>;
        pub fn get_table_rows(
            db: &Database,
            json: bool,
            code: u64,
            scope: &str,
            table: u64,
            table_key: &str,
            lower_bound: &str,
            upper_bound: &str,
            limit: u32,
            key_type: &str,
            index_position: &str,
            encode_type: &str,
            reverse: bool,
            show_payer: bool,
        ) -> Result<String>;
    }
}

unsafe impl Send for ffi::Database {}
unsafe impl Sync for ffi::Database {}

unsafe impl Send for ffi::UndoSession {}
unsafe impl Sync for ffi::UndoSession {}
