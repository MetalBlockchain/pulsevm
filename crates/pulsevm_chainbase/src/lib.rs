use std::{collections::VecDeque, error::Error, path::Path};
use fjall::{Config, TransactionalKeyspace, WriteTransaction};
use pulsevm_serialization::{serialize, Deserialize, Serialize};

pub trait ChainbaseObject<'a>: Default + Serialize + Deserialize {
    type PrimaryKey;

    fn primary_key(&self) -> Vec<u8>;
    fn primary_key_as_bytes(key: Self::PrimaryKey) -> Vec<u8>;
    fn secondary_indexes(&self) -> Vec<SecondaryKey>;
    fn table_name() -> &'static str;
}

pub struct SecondaryKey {
    pub key: Vec<u8>,
    pub index_name: &'static str,
}

pub trait SecondaryIndex<'a, C>
where
    C: ChainbaseObject<'a>,
{
    type Key;

    fn secondary_key(&self, object: &C) -> Vec<u8>;
    fn secondary_key_as_bytes(key: Self::Key) -> Vec<u8>;
    fn index_name() -> &'static str;
}

enum ObjectChange
{
    New(Vec<u8>), // key
    Modified(Vec<u8>, Vec<u8>, Vec<u8>), // (key, old, new)
    Deleted(Vec<u8>, Vec<u8>), // key, previous value
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

    pub fn exists<T: ChainbaseObject<'a> + 'static>(&self, key: T::PrimaryKey) -> Result<bool, Box<dyn Error>> {
        let partition = self.keyspace.open_partition(T::table_name(),  Default::default())?;
        let res = partition.contains_key(T::primary_key_as_bytes(key))?;
        Ok(res)
    }

    #[must_use]
    pub fn find_by_primary<T: ChainbaseObject<'a>>(&self, key: T::PrimaryKey) -> Result<Option<T>, Box<dyn Error>> {
        let partition = self.keyspace.open_partition(T::table_name(),  Default::default())?;
        let serialized = partition.get(T::primary_key_as_bytes(key))?;
        if serialized.is_none() {
            return Ok(None);
        }
        let mut pos = 0 as usize;
        let object: T = T::deserialize(&serialized.unwrap(), &mut pos).expect("failed to deserialize object");
        Ok(Some(object))
    }

    #[must_use]
    pub fn find_by_secondary<T: ChainbaseObject<'a>, S: SecondaryIndex<'a, T>>(&self, key: S::Key) -> Result<Option<T>, Box<dyn Error>> {
        let partition = self.keyspace.open_partition(S::index_name(),  Default::default())?;
        let secondary_key = partition.get(S::secondary_key_as_bytes(key))?;
        if secondary_key.is_none() {
            return Ok(None);
        }
        let partition = self.keyspace.open_partition(T::table_name(),  Default::default())?;
        let serialized = partition.get(secondary_key.unwrap())?;
        if serialized.is_none() {
            return Ok(None);
        }
        let mut pos = 0 as usize;
        let object: T = T::deserialize(&serialized.unwrap(), &mut pos).expect("failed to deserialize object");
        Ok(Some(object))
    }

    pub fn undo_session(&self) -> Result<UndoSession, Box<dyn Error>> {
        UndoSession::new(&self.keyspace)
    }
}

pub struct UndoSession<'a> {
    changes: VecDeque<ObjectChange>,
    tx: WriteTransaction<'a>,
    keyspace: &'a TransactionalKeyspace,
}

impl<'a> UndoSession<'a> {
    pub fn new(keyspace: &'a TransactionalKeyspace) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            changes: VecDeque::new(),
            tx: keyspace.write_tx(),
            keyspace: keyspace,
        })
    }

    #[must_use]
    pub fn exists<T: ChainbaseObject<'a> + 'static>(&self, key: T::PrimaryKey) -> Result<bool, Box<dyn Error>> {
        let partition = self.keyspace.open_partition(T::table_name(),  Default::default())?;
        let res = self.tx.contains_key(&partition, T::primary_key_as_bytes(key))?;
        Ok(res)
    }

    #[must_use]
    pub fn find_by_primary<T: ChainbaseObject<'a> + 'static>(&self, key: T::PrimaryKey) -> Result<Option<T>, Box<dyn Error>> {
        let partition = self.keyspace.open_partition(T::table_name(),  Default::default())?;
        let serialized = self.tx.get(&partition, T::primary_key_as_bytes(key))?;
        if serialized.is_none() {
            return Ok(None);
        }
        let mut pos = 0 as usize;
        let object: T = T::deserialize(&serialized.unwrap(), &mut pos).expect("failed to deserialize object");
        Ok(Some(object))
    }

    pub fn insert<T: ChainbaseObject<'a>>(&mut self, object: &T) -> Result<(), Box<dyn Error>> {
        let key = object.primary_key();
        let serialized = serialize(object);
        let partition = self.keyspace.open_partition(T::table_name(),  Default::default())?;
        let exists = self.tx.contains_key(&partition, &key)?;
        if exists {
            return Err("Object already exists".into());
        }
        self.changes.push_back(ObjectChange::New(key.to_owned()));
        self.tx.insert(&partition, &key, serialized);
        for index in object.secondary_indexes() {
            let partition = self.keyspace.open_partition(index.index_name,  Default::default())?;
            self.tx.insert(&partition, &index.key, &key);
        }
        Ok(())
    }

    pub fn modify<T, F>(&mut self, old: &T, f: F) -> Result<(), Box<dyn Error>>
    where 
        T: ChainbaseObject<'a> + 'static,
        F: FnOnce(&T) -> T,
    {
        let key = old.primary_key();
        let partition = self.keyspace.open_partition(T::table_name(),  Default::default())?;
        let existing = self.tx.get(&partition, &key)?;
        if existing.is_none() {
            return Err("Object does not exist".into());
        }
        let new = f(&old);
        let serialized_old = existing.unwrap().to_vec();
        let serialized_new = serialize(&new);
        self.changes.push_back(ObjectChange::Modified(
            key.to_owned(),
            serialized_old,
            serialized_new.to_owned(),
        ));
        self.tx.insert(&partition, &key, serialized_new);
        Ok(())
    }

    pub fn remove<T: ChainbaseObject<'a> + 'static>(&mut self, object: T) -> Result<(), Box<dyn Error>> {
        let key = object.primary_key();
        let partition = self.keyspace.open_partition(T::table_name(),  Default::default())?;
        let old_value = self.tx.get(&partition, &key)?;
        if old_value.is_none() {
            return Err("Object does not exist".into());
        }
        self.changes.push_back(ObjectChange::Deleted(key.to_owned(), old_value.unwrap().to_vec()));
        self.tx.remove(&partition, &key);
        for index in object.secondary_indexes() {
            let partition = self.keyspace.open_partition(index.index_name,  Default::default())?;
            self.tx.remove(&partition, &index.key);
        }
        Ok(())
    }

    pub fn commit(self) {
        self.tx.commit().expect("failed to commit transaction");
    }

    pub fn rollback(self) {
        self.tx.rollback();
    }
}