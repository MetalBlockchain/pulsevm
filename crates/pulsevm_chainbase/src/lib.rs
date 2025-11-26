mod error;
pub use error::ChainbaseError;

mod index;
mod ro_index;

mod session;
use heed::{Env, EnvOpenOptions, types::Bytes};
pub use session::ReadOnlySession;

mod undo_session;
pub use undo_session::UndoSession;

use pulsevm_serialization::{Read, Write};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{Arc, RwLock},
};

pub trait Session {
    fn exists<T: ChainbaseObject>(&mut self, key: T::PrimaryKey) -> Result<bool, ChainbaseError>;
    fn find<T: ChainbaseObject>(&self, key: T::PrimaryKey) -> Result<Option<T>, ChainbaseError>;
    fn find_by_secondary<T: ChainbaseObject, S: SecondaryIndex<T>>(
        &self,
        key: S::Key,
    ) -> Result<Option<T>, ChainbaseError>;
    fn get<T: ChainbaseObject>(&self, key: T::PrimaryKey) -> Result<T, ChainbaseError>;
    fn get_by_secondary<T: ChainbaseObject, S: SecondaryIndex<T>>(
        &self,
        key: S::Key,
    ) -> Result<T, ChainbaseError>;
}

pub trait ChainbaseObject: Default + Read + Write {
    type PrimaryKey: Read;

    fn primary_key(&self) -> Vec<u8>;
    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8>;
    fn primary_key_from_bytes(key: &[u8]) -> Result<Self::PrimaryKey, ChainbaseError> {
        let mut pos = 0;
        Ok(Self::PrimaryKey::read(key, &mut pos).map_err(|_| ChainbaseError::ReadError)?)
    }
    fn secondary_indexes(&self) -> Vec<SecondaryKey>;
    fn table_name() -> &'static str;
}

pub struct SecondaryKey {
    pub key: Vec<u8>,
    pub index_name: &'static str,
}

pub trait SecondaryIndex<C>
where
    C: ChainbaseObject,
{
    type Object: ChainbaseObject;
    type Key: Clone;

    fn secondary_key(object: &Self::Object) -> Vec<u8>;
    fn secondary_key_as_bytes(key: Self::Key) -> Vec<u8>;
    fn index_name() -> &'static str;
}

pub struct Database {
    environment: Arc<Env>,
    databases: Arc<RwLock<HashMap<&'static str, heed::Database<Bytes, Bytes>>>>,
}

impl Database {
    #[must_use]
    #[inline]
    pub fn new(path: &Path) -> Result<Self, ChainbaseError> {
        fs::create_dir_all(path).map_err(|e| {
            ChainbaseError::InternalError(format!("failed to create database directory: {}", e))
        })?;
        let environment = unsafe {
            EnvOpenOptions::new()
                .max_dbs(40)
                .map_size(1024 * 1024 * 100) // TODO: validate this value
                .open(path)
                .map_err(|e| {
                    ChainbaseError::InternalError(format!("failed to open LMDB environment: {}", e))
                })?
        };

        Ok(Self {
            environment: Arc::new(environment),
            databases: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn open_database(
        &self,
        name: &'static str,
    ) -> Result<heed::Database<Bytes, Bytes>, ChainbaseError> {
        let mut dbs = self
            .databases
            .write()
            .map_err(|_| ChainbaseError::InternalError("failed to read databases map".into()))?;
        match self.environment.write_txn() {
            Ok(mut tx) => {
                let db = self
                    .environment
                    .create_database::<Bytes, Bytes>(&mut tx, Some(name))
                    .map_err(|e| {
                        ChainbaseError::InternalError(format!(
                            "failed to open database '{}': {}",
                            name, e
                        ))
                    })?;
                tx.commit().map_err(|e| {
                    ChainbaseError::InternalError(format!(
                        "failed to commit database open transaction: {}",
                        e
                    ))
                })?;
                dbs.insert(name, db.clone());
                Ok(db)
            }
            Err(_) => Err(ChainbaseError::InternalError(
                "failed to open undo session".into(),
            )),
        }
    }

    #[inline]
    pub fn session(&self) -> Result<ReadOnlySession, ChainbaseError> {
        match self.environment.read_txn() {
            Ok(tx) => ReadOnlySession::new(tx, self.databases.clone()),
            Err(_) => Err(ChainbaseError::InternalError(
                "failed to open undo session".into(),
            )),
        }
    }

    #[inline]
    pub fn undo_session(&self) -> Result<UndoSession, ChainbaseError> {
        match self.environment.write_txn() {
            Ok(tx) => UndoSession::new(self.databases.clone(), tx),
            Err(_) => Err(ChainbaseError::InternalError(
                "failed to open undo session".into(),
            )),
        }
    }
}

mod tests {
    use super::*;
    use pulsevm_proc_macros::{NumBytes, Read, Write};

    #[derive(Debug, Default, Clone, Read, Write, NumBytes)]
    struct TestObject {
        id: u64,
        name: String,
    }

    impl ChainbaseObject for TestObject {
        type PrimaryKey = u64;

        fn primary_key(&self) -> Vec<u8> {
            TestObject::primary_key_to_bytes(self.id)
        }
        fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
            key.to_le_bytes().to_vec()
        }
        fn secondary_indexes(&self) -> Vec<SecondaryKey> {
            vec![SecondaryKey {
                key: TestObjectByNameIndex::secondary_key_as_bytes(self.name.clone()),
                index_name: TestObjectByNameIndex::index_name(),
            }]
        }
        fn table_name() -> &'static str {
            "test_object"
        }
    }

    #[derive(Debug, Default)]
    pub struct TestObjectByNameIndex;

    impl SecondaryIndex<TestObject> for TestObjectByNameIndex {
        type Object = TestObject;
        type Key = String;

        fn secondary_key(object: &TestObject) -> Vec<u8> {
            TestObjectByNameIndex::secondary_key_as_bytes(object.name.clone())
        }

        fn secondary_key_as_bytes(key: Self::Key) -> Vec<u8> {
            key.as_bytes().to_vec()
        }

        fn index_name() -> &'static str {
            "test_object_by_name"
        }
    }

    #[test]
    fn test_database() {
        let path = Path::new("test_db");
        let db = Database::new(&path).expect("failed to create database");
        let mut session = db.undo_session().expect("failed to create session");

        let obj = TestObject {
            id: 1,
            name: "Test".to_string(),
        };

        session.insert(&obj).expect("failed to insert object");
        let found = session
            .find::<TestObject>(1)
            .expect("failed to find object");
        assert_eq!(found.unwrap().name, "Test");
        let found = session
            .find_by_secondary::<TestObject, TestObjectByNameIndex>("Test".to_string())
            .expect("failed to find object by secondary index");
        assert_eq!(found.unwrap().id, 1);
    }
}
