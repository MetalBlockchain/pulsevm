mod index;
mod ro_index;

mod session;
use jsonrpsee::types::ErrorObjectOwned;
pub use session::Session;

mod undo_session;
pub use undo_session::UndoSession;

use fjall::{Config, PartitionCreateOptions, TransactionalKeyspace, TransactionalPartitionHandle};
use pulsevm_serialization::{Read, Write};
use std::{error::Error, fmt, path::Path};

#[derive(Debug, Clone)]
pub enum ChainbaseError {
    NotFound,
    AlreadyExists,
    InvalidData,
    ReadError,
    InternalError(String),
}

impl fmt::Display for ChainbaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainbaseError::NotFound => write!(f, "item not found"),
            ChainbaseError::AlreadyExists => write!(f, "item already exists"),
            ChainbaseError::InvalidData => write!(f, "invalid data provided"),
            ChainbaseError::ReadError => write!(f, "error reading data"),
            ChainbaseError::InternalError(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl Error for ChainbaseError {}

impl From<ChainbaseError> for ErrorObjectOwned {
    fn from(e: ChainbaseError) -> Self {
        match e {
            ChainbaseError::NotFound => ErrorObjectOwned::owned::<&str>(404, "not_found", None),
            ChainbaseError::AlreadyExists => {
                ErrorObjectOwned::owned::<&str>(409, "already_exists", None)
            }
            ChainbaseError::InvalidData => {
                ErrorObjectOwned::owned::<&str>(400, "invalid_data", None)
            }
            ChainbaseError::ReadError => ErrorObjectOwned::owned::<&str>(500, "read_error", None),
            ChainbaseError::InternalError(msg) => {
                ErrorObjectOwned::owned::<&str>(500, "internal_error", Some(&msg))
            }
        }
    }
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

#[derive(Clone)]
pub struct Database {
    keyspace: TransactionalKeyspace,
    partition_create_options: PartitionCreateOptions,
}

impl Database {
    #[must_use]
    #[inline]
    pub fn new(path: &Path) -> Result<Self, fjall::Error> {
        Ok(Self {
            keyspace: Config::new(path).open_transactional()?,
            partition_create_options: PartitionCreateOptions::default(),
        })
    }

    #[inline]
    pub fn temporary(path: &Path) -> Result<Self, fjall::Error> {
        let config = Config::new(path).temporary(true);
        let keyspace = config.open_transactional()?;
        Ok(Self { keyspace, partition_create_options: PartitionCreateOptions::default() })
    }

    #[inline]
    pub fn session(&self) -> Result<Session, ChainbaseError> {
        Session::new(&self.keyspace)
    }

    #[inline]
    pub fn undo_session(&self) -> Result<UndoSession, ChainbaseError> {
        UndoSession::new(&self.keyspace, self.partition_create_options.clone())
    }

    #[inline]
    pub fn open_partition_handle(
        &self,
        table_name: &str,
    ) -> Result<TransactionalPartitionHandle, ChainbaseError> {
        open_partition(&self.keyspace, table_name, self.partition_create_options.clone())
    }
}

#[inline]
fn open_partition(
    keyspace: &TransactionalKeyspace,
    table_name: &str,
    partition_create_options: PartitionCreateOptions,
) -> Result<TransactionalPartitionHandle, ChainbaseError> {
    keyspace
        .open_partition(table_name, partition_create_options)
        .map_err(|_| {
            ChainbaseError::InternalError(format!(
                "failed to open partition for table: {}",
                table_name
            ))
        })
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
        let db = Database::temporary(&path).expect("failed to create database");
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
