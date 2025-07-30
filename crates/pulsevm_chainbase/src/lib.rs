mod index;

mod undo_session;
pub use undo_session::UndoSession;

use fjall::{Config, TransactionalKeyspace};
use pulsevm_serialization::{Read, Write};
use std::{error::Error, path::Path};

pub trait ChainbaseObject: Default + Read + Write {
    type PrimaryKey: Read;

    fn primary_key(&self) -> Vec<u8>;
    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8>;
    fn primary_key_from_bytes(key: &[u8]) -> Result<Self::PrimaryKey, Box<dyn Error>> {
        let mut pos = 0;
        Ok(Self::PrimaryKey::read(key, &mut pos)
            .map_err(|_| format!("failed to read primary key from bytes"))?)
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
}

impl<'a> Database {
    #[must_use]
    pub fn new(path: &Path) -> Result<Self, fjall::Error> {
        Ok(Self {
            keyspace: Config::new(path).open_transactional()?,
        })
    }

    pub fn temporary(path: &Path) -> Result<Self, fjall::Error> {
        let config = Config::new(path).temporary(true);
        let keyspace = config.open_transactional()?;
        Ok(Self { keyspace })
    }

    pub fn exists<T: ChainbaseObject>(&self, key: T::PrimaryKey) -> Result<bool, Box<dyn Error>> {
        let partition = self
            .keyspace
            .open_partition(T::table_name(), Default::default())?;
        let res = partition.contains_key(T::primary_key_to_bytes(key))?;
        Ok(res)
    }

    #[must_use]
    pub fn find<T: ChainbaseObject>(
        &self,
        key: T::PrimaryKey,
    ) -> Result<Option<T>, Box<dyn Error>> {
        let partition = self
            .keyspace
            .open_partition(T::table_name(), Default::default())?;
        let serialized = partition.get(T::primary_key_to_bytes(key))?;
        if serialized.is_none() {
            return Ok(None);
        }
        let mut pos = 0 as usize;
        let object: T = T::read(&serialized.unwrap(), &mut pos).expect("failed to read object");
        Ok(Some(object))
    }

    #[must_use]
    pub fn get<T: ChainbaseObject>(&mut self, key: T::PrimaryKey) -> Result<T, Box<dyn Error>> {
        let found = self.find::<T>(key)?;
        if found.is_none() {
            return Err("Object not found".into());
        }
        let object = found.unwrap();
        Ok(object)
    }

    #[must_use]
    pub fn find_by_secondary<T: ChainbaseObject, S: SecondaryIndex<T>>(
        &self,
        key: S::Key,
    ) -> Result<Option<T>, Box<dyn Error>> {
        let partition = self
            .keyspace
            .open_partition(S::index_name(), Default::default())?;
        let secondary_key = partition.get(S::secondary_key_as_bytes(key))?;
        if secondary_key.is_none() {
            return Ok(None);
        }
        let partition = self
            .keyspace
            .open_partition(T::table_name(), Default::default())?;
        let serialized = partition.get(secondary_key.unwrap())?;
        if serialized.is_none() {
            return Ok(None);
        }
        let mut pos = 0 as usize;
        let object: T = T::read(&serialized.unwrap(), &mut pos).expect("failed to read object");
        Ok(Some(object))
    }

    pub fn undo_session(&self) -> Result<UndoSession, Box<dyn Error>> {
        UndoSession::new(&self.keyspace)
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
            key.to_be_bytes().to_vec()
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

        session.commit();
    }
}
