#[cxx::bridge]
pub mod ffi {
    // Shared enums between Rust and C++
    #[repr(u32)]
    enum DatabaseOpenFlags {
        ReadOnly = 0,
        ReadWrite = 1,
    }

    struct Account {
        id: i64,
        name: u64,
    }

    unsafe extern "C++" {
        include!("database.hpp");

        type database_wrapper;
        #[cxx_name = "account_object"]
        type Account;
        
        // Constructor wrapper
        pub fn open_database(
            path: &str,
            flags: DatabaseOpenFlags,
            size: u64
        ) -> UniquePtr<database_wrapper>;
        
        // Methods on database
        fn flush(self: Pin<&mut database_wrapper>);
        fn undo(self: Pin<&mut database_wrapper>);
        fn commit(self: Pin<&mut database_wrapper>, revision: i64);
        fn revision(self: &database_wrapper) -> i64;
        fn add_indices(self: Pin<&mut database_wrapper>);
        fn add_account(self: Pin<&mut database_wrapper>);
        fn get_account(self: Pin<&mut database_wrapper>) -> Account;
    }
}