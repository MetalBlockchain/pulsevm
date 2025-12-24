mod bridge;
use std::sync::{Arc, RwLock};

use bridge::ffi as ffi;

pub struct Database {
    inner: cxx::UniquePtr<ffi::database_wrapper>,
    lock: Arc<RwLock<()>>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self, String> {
        let db = ffi::open_database(path, ffi::DatabaseOpenFlags::ReadWrite, 20*1024*1024*1024);

        if db.is_null() {
            Err("Failed to open database".to_string())
        } else {
            Ok(Database { inner: db, lock: Arc::new(RwLock::new(()))  })
        }
    }

    pub fn add_indices(&mut self) {
        self.inner.pin_mut().add_indices();
    }

    pub fn add_account(&mut self) {
        let _lock = self.lock.write().unwrap();
        self.inner.pin_mut().add_account();
    }

    pub fn get_account(&mut self) -> ffi::Account {
        let _lock = self.lock.read().unwrap();
        self.inner.pin_mut().get_account()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_creation() {
        let mut db = Database::new("/tmp/testdb").unwrap();
        db.add_indices();
        db.add_account();
    }
}