mod index;

use fjall::{Config, Slice, TransactionalKeyspace, WriteTransaction};
use pulsevm_serialization::{Read, Write};
use std::{
    cell::RefCell, char, collections::VecDeque, error::Error, path::Path, rc::Rc, sync::Arc,
};

use crate::index::Index;

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

enum ObjectChange {
    New(Vec<u8>),                        // key
    Modified(Vec<u8>, Vec<u8>, Vec<u8>), // (key, old, new)
    Deleted(Vec<u8>, Vec<u8>),           // key, previous value
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

#[derive(Clone)]
pub struct UndoSession {
    changes: Rc<RefCell<VecDeque<ObjectChange>>>,
    tx: Rc<RefCell<WriteTransaction>>,
    keyspace: TransactionalKeyspace,
}

impl UndoSession {
    pub fn new(keyspace: &TransactionalKeyspace) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            changes: Rc::new(RefCell::new(VecDeque::new())),
            tx: Rc::new(RefCell::new(keyspace.write_tx()?)),
            keyspace: keyspace.clone(),
        })
    }

    pub fn tx(&self) -> Rc<RefCell<WriteTransaction>> {
        self.tx.clone()
    }

    pub fn keyspace(&self) -> TransactionalKeyspace {
        self.keyspace.clone()
    }

    #[must_use]
    pub fn exists<T: ChainbaseObject>(
        &mut self,
        key: T::PrimaryKey,
    ) -> Result<bool, Box<dyn Error>> {
        let partition = self
            .keyspace
            .open_partition(T::table_name(), Default::default())?;
        let mut tx = self.tx.borrow_mut();
        let res = tx.contains_key(&partition, T::primary_key_to_bytes(key))?;
        Ok(res)
    }

    #[must_use]
    pub fn find<T: ChainbaseObject>(
        &mut self,
        key: T::PrimaryKey,
    ) -> Result<Option<T>, Box<dyn Error>> {
        let partition = self
            .keyspace
            .open_partition(T::table_name(), Default::default())?;
        let mut tx = self.tx.borrow_mut();
        let serialized = tx.get(&partition, T::primary_key_to_bytes(key))?;
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
        &mut self,
        key: S::Key,
    ) -> Result<Option<T>, Box<dyn Error>> {
        let partition = self
            .keyspace
            .open_partition(S::index_name(), Default::default())?;
        let mut tx = self.tx.borrow_mut();
        let secondary_key = tx.get(&partition, S::secondary_key_as_bytes(key))?;
        if secondary_key.is_none() {
            return Ok(None);
        }
        let partition = self
            .keyspace
            .open_partition(T::table_name(), Default::default())?;
        let serialized = tx.get(&partition, secondary_key.unwrap())?;
        if serialized.is_none() {
            return Ok(None);
        }
        let mut pos = 0 as usize;
        let object: T = T::read(&serialized.unwrap(), &mut pos).expect("failed to read object");
        Ok(Some(object))
    }

    pub fn generate_id<T: ChainbaseObject>(&mut self) -> Result<u64, Box<dyn Error>> {
        let partition = self
            .keyspace
            .open_partition(T::table_name(), Default::default())?;
        let mut new_id = 0u64;
        let mut tx = self.tx.borrow_mut();
        // Do we have a sequence for this table?
        tx.fetch_update(&partition, "id", |v| {
            if v.is_none() {
                return Some(Slice::new(&0u64.to_be_bytes()));
            }
            let id = v.unwrap();
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&id);
            let mut id = u64::from_be_bytes(arr);
            id += 1;
            new_id = id;
            Some(Slice::new(&id.to_be_bytes()))
        })?;
        Ok(new_id)
    }

    pub fn insert<T: ChainbaseObject>(&mut self, object: &T) -> Result<(), Box<dyn Error>> {
        let key = object.primary_key();
        let serialized = object.pack()?;
        let partition = self
            .keyspace
            .open_partition(T::table_name(), Default::default())?;
        let mut tx = self.tx.borrow_mut();
        let exists = tx.contains_key(&partition, &key)?;
        if exists {
            return Err("Object already exists".into());
        }
        let mut changes = self.changes.borrow_mut();
        changes.push_back(ObjectChange::New(key.to_owned()));
        tx.insert(&partition, &key, serialized);
        for index in object.secondary_indexes() {
            let partition = self
                .keyspace
                .open_partition(index.index_name, Default::default())?;
            tx.insert(&partition, &index.key, &key);
        }
        Ok(())
    }

    pub fn modify<T, F>(&mut self, old: &mut T, f: F) -> Result<(), Box<dyn Error>>
    where
        T: ChainbaseObject,
        F: FnOnce(&mut T),
    {
        let key = old.primary_key();
        let partition = self
            .keyspace
            .open_partition(T::table_name(), Default::default())?;
        let mut tx = self.tx.borrow_mut();
        let existing = tx.get(&partition, &key)?;
        if existing.is_none() {
            return Err("Object does not exist".into());
        }
        f(old);
        let serialized_old = existing.unwrap().to_vec();
        let serialized_new = old.pack()?;
        let mut changes = self.changes.borrow_mut();
        changes.push_back(ObjectChange::Modified(
            key.to_owned(),
            serialized_old,
            serialized_new.to_owned(),
        ));
        tx.insert(&partition, &key, serialized_new);
        Ok(())
    }

    pub fn remove<T: ChainbaseObject>(&mut self, object: T) -> Result<(), Box<dyn Error>> {
        let key = object.primary_key();
        let partition = self
            .keyspace
            .open_partition(T::table_name(), Default::default())?;
        let mut tx = self.tx.borrow_mut();
        let old_value = tx.get(&partition, &key)?;
        if old_value.is_none() {
            return Err("Object does not exist".into());
        }
        let mut changes = self.changes.borrow_mut();
        changes.push_back(ObjectChange::Deleted(
            key.to_owned(),
            old_value.unwrap().to_vec(),
        ));
        tx.remove(&partition, &key);
        for index in object.secondary_indexes() {
            let partition = self
                .keyspace
                .open_partition(index.index_name, Default::default())?;
            tx.remove(&partition, &index.key);
        }
        Ok(())
    }

    pub fn commit(self) -> Result<(), Box<dyn Error>> {
        let tx = Rc::try_unwrap(self.tx)
            .map_err(|_| "failed to unwrap Rc: multiple owners".to_string())?
            .into_inner();
        let result = tx.commit();
        if result.is_err() {
            return Err("failed to commit transaction".into());
        }
        Ok(())
    }

    pub fn rollback(self) -> Result<(), Box<dyn Error>> {
        let tx = Rc::try_unwrap(self.tx)
            .map_err(|_| "failed to unwrap Rc: multiple owners".to_string())?
            .into_inner();
        tx.rollback();
        Ok(())
    }

    pub fn get_index<C, S>(&self) -> Index<C, S>
    where
        C: ChainbaseObject,
        S: SecondaryIndex<C>,
    {
        Index::<C, S>::new(self.clone(), self.keyspace.clone())
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
