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
        include!("block_log.hpp");
        include!("database.hpp");
        include!("name.hpp");

        #[cxx_name = "name"]
        type Name;

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
        type Account;

        #[cxx_name = "key_value_object"]
        type KeyValue;

        #[cxx_name = "signed_block"]
        type SignedBlock;

        // Block log
        #[cxx_name = "block_log"]
        pub type BlockLog;
        pub fn open_block_log(path: &str) -> UniquePtr<BlockLog>;
        pub fn read_block_by_num(self: &BlockLog, block_num: u32) -> SharedPtr<SignedBlock>;

        // Name methods
        pub fn string_to_name(str: &str) -> &Name;
        pub fn name_to_uint64(name: &Name) -> u64;

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
        pub fn add_account(self: Pin<&mut Database>, account_name: &Name);
        pub fn get_account(self: Pin<&mut Database>) -> Result<UniquePtr<Account>>;
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

        // Methods on undo_session
        pub fn push(self: Pin<&mut UndoSession>) -> Result<()>;
        pub fn squash(self: Pin<&mut UndoSession>) -> Result<()>;
        pub fn undo(self: Pin<&mut UndoSession>) -> Result<()>;
    }
}
