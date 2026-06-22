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

    struct Ratio {
        numerator: u64,
        denominator: u64,
    }

    struct ElasticLimitParameters {
        target: u64,
        max: u64,
        periods: u32,
        max_multiplier: u32,
        contract_rate: Ratio,
        expand_rate: Ratio,
    }

    struct U128 {
        lo: u64,
        hi: u64,
    }

    struct I128 {
        lo: u64,
        hi: u64,
    }

    struct U256 {
        value: [u8; 32],
    }

    struct Float128 {
        lo: u64,
        hi: u64,
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

    #[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug, PartialOrd, Ord)]
    pub struct Microseconds {
        count: i64,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
    pub struct TimePoint {
        elapsed: Microseconds,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
    pub struct TimePointSec {
        utc_seconds: u32,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
    pub struct BlockTimestamp {
        slot: u32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ChainConfigV0 {
        /// Maximum net usage (in instructions) for a block.
        pub max_block_net_usage: u64,
        /// Target percent (1% == 100, 100% == 10,000) of max net usage; exceeding triggers congestion handling.
        pub target_block_net_usage_pct: u32,
        /// Maximum objectively measured net usage the chain allows regardless of account limits.
        pub max_transaction_net_usage: u32,
        /// Base net usage billed per transaction to cover incidentals.
        pub base_per_transaction_net_usage: u32,
        pub net_usage_leeway: u32,
        /// Numerator of the discount on net usage of context-free data.
        pub context_free_discount_net_usage_num: u32,
        /// Denominator of the discount on net usage of context-free data.
        pub context_free_discount_net_usage_den: u32,

        /// Maximum billable cpu usage (microseconds) for a block.
        pub max_block_cpu_usage: u32,
        /// Target percent (1% == 100, 100% == 10,000) of max cpu usage; exceeding triggers congestion handling.
        pub target_block_cpu_usage_pct: u32,
        /// Maximum billable cpu usage (microseconds) the chain allows regardless of account limits.
        pub max_transaction_cpu_usage: u32,
        /// Minimum billable cpu usage (microseconds) the chain requires.
        pub min_transaction_cpu_usage: u32,

        /// Max seconds an input transaction's expiration can be ahead of its first-including block.
        pub max_transaction_lifetime: u32,
        /// Seconds after first-executable time until a deferred transaction expires.
        pub deferred_trx_expiration_window: u32,
        /// Max seconds that can be imposed as a delay requirement by authorization checks.
        pub max_transaction_delay: u32,
        /// Maximum allowed size (bytes) of an inline action.
        pub max_inline_action_size: u32,
        /// Recursion depth limit on sending inline actions.
        pub max_inline_action_depth: u16,
        /// Recursion depth limit for checking if an authority is satisfied.
        pub max_authority_depth: u16,
    }

    unsafe extern "C++" {
        include!("catcher.hpp");
        include!("utils.hpp");
        include!("name.hpp");
        include!("database.hpp");
        include!("iterator_cache.hpp");
        include!("api.hpp");
        include!("builtins.hpp");

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
        pub fn get_vm_type(self: &AccountMetadataObject) -> u8;
        pub fn get_vm_version(self: &AccountMetadataObject) -> u8;

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

        #[cxx_name = "index64_object"]
        type Index64Object;
        pub fn get_table_id(self: &Index64Object) -> &TableId;
        pub fn get_primary_key(self: &Index64Object) -> u64;
        pub fn get_secondary_key(self: &Index64Object) -> u64;
        pub fn get_payer(self: &Index64Object) -> &CxxName;

        #[cxx_name = "index128_object"]
        type Index128Object;
        pub fn get_table_id(self: &Index128Object) -> &TableId;
        pub fn get_primary_key(self: &Index128Object) -> u64;
        pub fn get_payer(self: &Index128Object) -> &CxxName;

        #[cxx_name = "index256_object"]
        type Index256Object;
        pub fn get_table_id(self: &Index256Object) -> &TableId;
        pub fn get_primary_key(self: &Index256Object) -> u64;
        pub fn get_payer(self: &Index256Object) -> &CxxName;

        #[cxx_name = "index_double_object"]
        type IndexDoubleObject;
        pub fn get_table_id(self: &IndexDoubleObject) -> &TableId;
        pub fn get_primary_key(self: &IndexDoubleObject) -> u64;
        pub fn get_payer(self: &IndexDoubleObject) -> &CxxName;

        #[cxx_name = "index_long_double_object"]
        type IndexLongDoubleObject;
        pub fn get_table_id(self: &IndexLongDoubleObject) -> &TableId;
        pub fn get_primary_key(self: &IndexLongDoubleObject) -> u64;
        pub fn get_payer(self: &IndexLongDoubleObject) -> &CxxName;

        // Methods on database
        pub fn flush(self: Pin<&mut Database>) -> Result<()>;
        pub fn undo(self: Pin<&mut Database>) -> Result<()>;
        pub fn commit(self: Pin<&mut Database>, revision: i64) -> Result<()>;
        pub fn revision(self: &Database) -> i64;
        pub fn set_revision(self: Pin<&mut Database>, revision: i64) -> Result<()>;
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
            pending_block_time: &TimePoint,
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
        pub fn update_account_usage(
            self: Pin<&mut Database>,
            account: u64,
            time_slot: u32,
        ) -> Result<()>;
        pub fn add_transaction_usage(
            self: Pin<&mut Database>,
            account: u64,
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
        pub fn set_block_parameters(
            self: Pin<&mut Database>,
            cpu_limit_parameters: &ElasticLimitParameters,
            net_limit_parameters: &ElasticLimitParameters,
        ) -> Result<()>;
        pub fn process_block_usage(self: Pin<&mut Database>, block_num: u32) -> Result<()>;
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
        pub fn create_index64_object(
            self: Pin<&mut Database>,
            table: &TableObject,
            payer: u64,
            id: u64,
            secondary_key: u64,
        ) -> Result<&Index64Object>;
        pub fn create_index128_object(
            self: Pin<&mut Database>,
            table: &TableObject,
            payer: u64,
            id: u64,
            secondary_key: U128,
        ) -> Result<&Index128Object>;
        pub fn create_index256_object(
            self: Pin<&mut Database>,
            table: &TableObject,
            payer: u64,
            id: u64,
            secondary_key: U256,
        ) -> Result<&Index256Object>;
        pub fn update_key_value_object(
            self: Pin<&mut Database>,
            obj: &KeyValueObject,
            payer: u64,
            buffer: &[u8],
        ) -> Result<()>;
        pub fn update_index64_object(
            self: Pin<&mut Database>,
            obj: &Index64Object,
            payer: u64,
            secondary_key: u64,
        ) -> Result<()>;
        pub fn update_index128_object(
            self: Pin<&mut Database>,
            obj: &Index128Object,
            payer: u64,
            secondary_key: U128,
        ) -> Result<()>;
        pub fn update_index256_object(
            self: Pin<&mut Database>,
            obj: &Index256Object,
            payer: u64,
            secondary_key: U256,
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

        // Index 64 methods
        pub fn db_idx64_remove(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex64IteratorCache>,
            iterator: i32,
            receiver: u64,
        ) -> Result<()>;
        pub fn db_idx64_find_secondary(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex64IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: u64,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx64_find_primary(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex64IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut u64,
            primary_key: u64,
        ) -> Result<i32>;
        pub fn db_idx64_lowerbound(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex64IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut u64,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx64_upperbound(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex64IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut u64,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx64_end(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex64IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
        ) -> Result<i32>;
        pub fn db_idx64_next(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex64IteratorCache>,
            iterator: i32,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx64_previous(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex64IteratorCache>,
            iterator: i32,
            primary_key: &mut u64,
        ) -> Result<i32>;

        // Index 128 methods
        pub fn db_idx128_remove(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex128IteratorCache>,
            iterator: i32,
            receiver: u64,
        ) -> Result<()>;
        pub fn db_idx128_find_secondary(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex128IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: U128,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx128_find_primary(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex128IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut U128,
            primary_key: u64,
        ) -> Result<i32>;
        pub fn db_idx128_lowerbound(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex128IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut U128,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx128_upperbound(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex128IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut U128,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx128_end(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex128IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
        ) -> Result<i32>;
        pub fn db_idx128_next(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex128IteratorCache>,
            iterator: i32,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx128_previous(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex128IteratorCache>,
            iterator: i32,
            primary_key: &mut u64,
        ) -> Result<i32>;

        // Index 256 methods
        pub fn db_idx256_remove(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex256IteratorCache>,
            iterator: i32,
            receiver: u64,
        ) -> Result<()>;
        pub fn db_idx256_find_secondary(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex256IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: U256,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx256_find_primary(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex256IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut U256,
            primary_key: u64,
        ) -> Result<i32>;
        pub fn db_idx256_lowerbound(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex256IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut U256,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx256_upperbound(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex256IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut U256,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx256_end(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex256IteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
        ) -> Result<i32>;
        pub fn db_idx256_next(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex256IteratorCache>,
            iterator: i32,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx256_previous(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndex256IteratorCache>,
            iterator: i32,
            primary_key: &mut u64,
        ) -> Result<i32>;

        // Index double methods
        pub fn create_idx_double_object(
            self: Pin<&mut Database>,
            table: &TableObject,
            payer: u64,
            id: u64,
            secondary_key: u64,
        ) -> Result<&IndexDoubleObject>;
        pub fn update_idx_double_object(
            self: Pin<&mut Database>,
            obj: &IndexDoubleObject,
            payer: u64,
            secondary_key: u64,
        ) -> Result<()>;
        pub fn db_idx_double_remove(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexDoubleIteratorCache>,
            iterator: i32,
            receiver: u64,
        ) -> Result<()>;
        pub fn db_idx_double_find_secondary(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexDoubleIteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: u64,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx_double_find_primary(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexDoubleIteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut u64,
            primary_key: u64,
        ) -> Result<i32>;
        pub fn db_idx_double_lowerbound(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexDoubleIteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut u64,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx_double_upperbound(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexDoubleIteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut u64,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx_double_end(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexDoubleIteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
        ) -> Result<i32>;
        pub fn db_idx_double_next(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexDoubleIteratorCache>,
            iterator: i32,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx_double_previous(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexDoubleIteratorCache>,
            iterator: i32,
            primary_key: &mut u64,
        ) -> Result<i32>;

        // Index long double methods
        pub fn create_idx_long_double_object(
            self: Pin<&mut Database>,
            table: &TableObject,
            payer: u64,
            id: u64,
            secondary_key: Float128,
        ) -> Result<&IndexLongDoubleObject>;
        pub fn update_idx_long_double_object(
            self: Pin<&mut Database>,
            obj: &IndexLongDoubleObject,
            payer: u64,
            secondary_key: Float128,
        ) -> Result<()>;
        pub fn db_idx_long_double_remove(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexLongDoubleIteratorCache>,
            iterator: i32,
            receiver: u64,
        ) -> Result<()>;
        pub fn db_idx_long_double_find_secondary(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexLongDoubleIteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: Float128,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx_long_double_find_primary(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexLongDoubleIteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut Float128,
            primary_key: u64,
        ) -> Result<i32>;
        pub fn db_idx_long_double_lowerbound(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexLongDoubleIteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut Float128,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx_long_double_upperbound(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexLongDoubleIteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
            secondary_key: &mut Float128,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx_long_double_end(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexLongDoubleIteratorCache>,
            code: u64,
            scope: u64,
            table: u64,
        ) -> Result<i32>;
        pub fn db_idx_long_double_next(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexLongDoubleIteratorCache>,
            iterator: i32,
            primary_key: &mut u64,
        ) -> Result<i32>;
        pub fn db_idx_long_double_previous(
            self: Pin<&mut Database>,
            keyval_cache: Pin<&mut CxxIndexLongDoubleIteratorCache>,
            iterator: i32,
            primary_key: &mut u64,
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
            creation_time: &TimePoint,
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
            pending_block_time: &TimePoint,
        ) -> Result<()>;
        pub fn update_permission_usage(
            self: Pin<&mut Database>,
            permission: &PermissionObject,
            pending_block_time: &TimePoint,
        ) -> Result<()>;
        pub fn get_permission_last_used(
            self: &Database,
            permission: &PermissionObject,
        ) -> Result<TimePoint>;
        pub fn lookup_linked_permission(
            self: &Database,
            account: u64,
            code: u64,
            requirement_type: u64,
        ) -> Result<*const CxxName>;
        pub fn get_global_properties(self: &Database) -> Result<&GlobalPropertyObject>;
        pub fn set_global_properties(self: Pin<&mut Database>, cfg: &ChainConfigV0) -> Result<()>;
        pub fn get_virtual_block_cpu_limit(self: &Database) -> Result<u64>;
        pub fn get_virtual_block_net_limit(self: &Database) -> Result<u64>;
        pub fn get_block_cpu_limit(self: &Database) -> Result<u64>;
        pub fn get_block_net_limit(self: &Database) -> Result<u64>;
        pub fn is_known_unexpired_transaction(self: &Database, trx_id: &CxxDigest) -> Result<bool>;
        pub fn record_transaction(
            self: Pin<&mut Database>,
            trx_id: &CxxDigest,
            expiration: u32,
        ) -> Result<()>;
        pub fn clear_expired_input_transactions(
            self: Pin<&mut Database>,
            cutoff: &TimePoint,
        ) -> Result<()>;

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

        pub type CxxIndex64IteratorCache;
        pub fn new_index64_iterator_cache() -> UniquePtr<CxxIndex64IteratorCache>;
        pub fn cache_table(
            self: Pin<&mut CxxIndex64IteratorCache>,
            table: &TableObject,
        ) -> Result<i32>;
        pub fn get_table(
            self: &CxxIndex64IteratorCache,
            table_id: &TableId,
        ) -> Result<&TableObject>;
        pub fn get_end_iterator_by_table_id(
            self: &CxxIndex64IteratorCache,
            table_id: &TableId,
        ) -> Result<i32>;
        pub fn find_table_by_end_iterator(
            self: &CxxIndex64IteratorCache,
            ei: i32,
        ) -> Result<*const TableObject>;
        pub fn get(self: &CxxIndex64IteratorCache, iterator: i32) -> Result<&Index64Object>;
        pub fn remove(self: Pin<&mut CxxIndex64IteratorCache>, iterator: i32) -> Result<()>;
        pub fn add(self: Pin<&mut CxxIndex64IteratorCache>, obj: &Index64Object) -> Result<i32>;

        pub type CxxIndex128IteratorCache;
        pub fn new_index128_iterator_cache() -> UniquePtr<CxxIndex128IteratorCache>;
        pub fn cache_table(
            self: Pin<&mut CxxIndex128IteratorCache>,
            table: &TableObject,
        ) -> Result<i32>;
        pub fn get_table(
            self: &CxxIndex128IteratorCache,
            table_id: &TableId,
        ) -> Result<&TableObject>;
        pub fn get_end_iterator_by_table_id(
            self: &CxxIndex128IteratorCache,
            table_id: &TableId,
        ) -> Result<i32>;
        pub fn find_table_by_end_iterator(
            self: &CxxIndex128IteratorCache,
            ei: i32,
        ) -> Result<*const TableObject>;
        pub fn get(self: &CxxIndex128IteratorCache, iterator: i32) -> Result<&Index128Object>;
        pub fn remove(self: Pin<&mut CxxIndex128IteratorCache>, iterator: i32) -> Result<()>;
        pub fn add(self: Pin<&mut CxxIndex128IteratorCache>, obj: &Index128Object) -> Result<i32>;

        pub type CxxIndex256IteratorCache;
        pub fn new_index256_iterator_cache() -> UniquePtr<CxxIndex256IteratorCache>;
        pub fn cache_table(
            self: Pin<&mut CxxIndex256IteratorCache>,
            table: &TableObject,
        ) -> Result<i32>;
        pub fn get_table(
            self: &CxxIndex256IteratorCache,
            table_id: &TableId,
        ) -> Result<&TableObject>;
        pub fn get_end_iterator_by_table_id(
            self: &CxxIndex256IteratorCache,
            table_id: &TableId,
        ) -> Result<i32>;
        pub fn find_table_by_end_iterator(
            self: &CxxIndex256IteratorCache,
            ei: i32,
        ) -> Result<*const TableObject>;
        pub fn get(self: &CxxIndex256IteratorCache, iterator: i32) -> Result<&Index256Object>;
        pub fn remove(self: Pin<&mut CxxIndex256IteratorCache>, iterator: i32) -> Result<()>;
        pub fn add(self: Pin<&mut CxxIndex256IteratorCache>, obj: &Index256Object) -> Result<i32>;

        pub type CxxIndexDoubleIteratorCache;
        pub fn new_index_double_iterator_cache() -> UniquePtr<CxxIndexDoubleIteratorCache>;
        pub fn cache_table(
            self: Pin<&mut CxxIndexDoubleIteratorCache>,
            table: &TableObject,
        ) -> Result<i32>;
        pub fn get_table(
            self: &CxxIndexDoubleIteratorCache,
            table_id: &TableId,
        ) -> Result<&TableObject>;
        pub fn get_end_iterator_by_table_id(
            self: &CxxIndexDoubleIteratorCache,
            table_id: &TableId,
        ) -> Result<i32>;
        pub fn find_table_by_end_iterator(
            self: &CxxIndexDoubleIteratorCache,
            ei: i32,
        ) -> Result<*const TableObject>;
        pub fn get(self: &CxxIndexDoubleIteratorCache, iterator: i32)
        -> Result<&IndexDoubleObject>;
        pub fn remove(self: Pin<&mut CxxIndexDoubleIteratorCache>, iterator: i32) -> Result<()>;
        pub fn add(
            self: Pin<&mut CxxIndexDoubleIteratorCache>,
            obj: &IndexDoubleObject,
        ) -> Result<i32>;

        pub type CxxIndexLongDoubleIteratorCache;
        pub fn new_index_long_double_iterator_cache() -> UniquePtr<CxxIndexLongDoubleIteratorCache>;
        pub fn cache_table(
            self: Pin<&mut CxxIndexLongDoubleIteratorCache>,
            table: &TableObject,
        ) -> Result<i32>;
        pub fn get_table(
            self: &CxxIndexLongDoubleIteratorCache,
            table_id: &TableId,
        ) -> Result<&TableObject>;
        pub fn get_end_iterator_by_table_id(
            self: &CxxIndexLongDoubleIteratorCache,
            table_id: &TableId,
        ) -> Result<i32>;
        pub fn find_table_by_end_iterator(
            self: &CxxIndexLongDoubleIteratorCache,
            ei: i32,
        ) -> Result<*const TableObject>;
        pub fn get(
            self: &CxxIndexLongDoubleIteratorCache,
            iterator: i32,
        ) -> Result<&IndexLongDoubleObject>;
        pub fn remove(self: Pin<&mut CxxIndexLongDoubleIteratorCache>, iterator: i32)
        -> Result<()>;
        pub fn add(
            self: Pin<&mut CxxIndexLongDoubleIteratorCache>,
            obj: &IndexLongDoubleObject,
        ) -> Result<i32>;

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
        pub fn get_max_transaction_delay(self: &CxxChainConfig) -> u32;
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
        pub fn make_digest_from_existing_hash(data: &[u8]) -> Result<UniquePtr<CxxDigest>>;
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
        pub fn random_private_key() -> SharedPtr<CxxPrivateKey>;
        pub fn random_private_key_r1() -> SharedPtr<CxxPrivateKey>;
        pub fn extract_chain_id_from_genesis_state(genesis: &CxxGenesisState) -> Vec<u8>;
        pub fn index128_object_secondary_key_as_u128(obj: &Index128Object) -> U128;

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
            head_block_time: &TimePoint,
        ) -> Result<String>;
        pub fn get_account_info_with_core_symbol(
            db: &Database,
            account: u64,
            expected_core_symbol: &str,
            head_block_num: u32,
            head_block_time: &TimePoint,
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
        pub fn get_table_by_scope(
            db: &Database,
            code: u64,
            table: u64,
            lower_bound: &str,
            upper_bound: &str,
            limit: u32,
            reverse: bool,
        ) -> Result<String>;
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

        // State history
        pub fn pack_deltas(self: &Database, full_snapshot: bool) -> Result<Vec<u8>>;

        // Arithmetic operations
        pub fn addtf3(la: u64, ha: u64, lb: u64, hb: u64) -> Float128;
        pub fn subtf3(la: u64, ha: u64, lb: u64, hb: u64) -> Float128;
        pub fn multf3(la: u64, ha: u64, lb: u64, hb: u64) -> Float128;
        pub fn divtf3(la: u64, ha: u64, lb: u64, hb: u64) -> Float128;
        pub fn negtf2(la: u64, ha: u64) -> Float128;

        // ---- widening: float -> f128 ----
        pub fn extendsftf2(f: f32) -> Float128;
        pub fn extenddftf2(d: f64) -> Float128;

        // ---- narrowing: f128 -> float ----
        pub fn trunctfdf2(l: u64, h: u64) -> f64;
        pub fn trunctfsf2(l: u64, h: u64) -> f32;

        // ---- f128 -> signed/unsigned int ----
        pub fn fixtfsi(l: u64, h: u64) -> i32;
        pub fn fixtfdi(l: u64, h: u64) -> i64;
        pub fn fixtfti(l: u64, h: u64) -> I128;
        pub fn fixunstfsi(l: u64, h: u64) -> u32;
        pub fn fixunstfdi(l: u64, h: u64) -> u64;
        pub fn fixunstfti(l: u64, h: u64) -> U128;

        // ---- float -> i128/u128 ----
        pub fn fixsfti(a: f32) -> I128;
        pub fn fixdfti(a: f64) -> I128;
        pub fn fixunssfti(a: f32) -> U128;
        pub fn fixunsdfti(a: f64) -> U128;

        // ---- int -> float/f128 ----
        pub fn floatsidf(i: i32) -> f64;
        pub fn floatsitf(i: i32) -> Float128;
        pub fn floatditf(a: u64) -> Float128;
        pub fn floatunsitf(i: u32) -> Float128;
        pub fn floatunditf(a: u64) -> Float128;

        // ---- 128-bit int -> double ----
        pub fn floattidf(l: u64, h: u64) -> f64;
        pub fn floatuntidf(l: u64, h: u64) -> f64;

        // ---- comparisons ----
        pub fn unordtf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32;
        pub fn eqtf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32;
        pub fn netf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32;
        pub fn getf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32;
        pub fn gttf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32;
        pub fn letf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32;
        pub fn lttf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32;
        pub fn cmptf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32;
    }
}

unsafe impl Send for ffi::Database {}
unsafe impl Sync for ffi::Database {}

unsafe impl Send for ffi::UndoSession {}
unsafe impl Sync for ffi::UndoSession {}
