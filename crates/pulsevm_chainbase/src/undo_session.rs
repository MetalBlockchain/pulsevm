use std::{cell::RefCell, collections::VecDeque, error::Error, rc::Rc};

use fjall::{Slice, TransactionalKeyspace, WriteTransaction};

use crate::{ChainbaseError, ChainbaseObject, SecondaryIndex, index::Index, open_partition};

enum ObjectChange {
    New(Vec<u8>),                        // key
    Modified(Vec<u8>, Vec<u8>, Vec<u8>), // (key, old, new)
    Deleted(Vec<u8>, Vec<u8>),           // key, previous value
}

#[derive(Clone)]
pub struct UndoSession {
    changes: Rc<RefCell<VecDeque<ObjectChange>>>,
    tx: Rc<RefCell<WriteTransaction>>,
    keyspace: TransactionalKeyspace,
}

impl UndoSession {
    pub fn new(keyspace: &TransactionalKeyspace) -> Result<Self, ChainbaseError> {
        Ok(Self {
            changes: Rc::new(RefCell::new(VecDeque::new())),
            tx: Rc::new(RefCell::new(keyspace.write_tx().map_err(|_| {
                ChainbaseError::InternalError("failed to create write transaction".to_string())
            })?)),
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
    ) -> Result<bool, ChainbaseError> {
        let partition = open_partition(&self.keyspace, T::table_name())?;
        let mut tx = self.tx.borrow_mut();
        let res = tx
            .contains_key(&partition, T::primary_key_to_bytes(key))
            .map_err(|_| {
                ChainbaseError::InternalError(format!("failed to check existence for key"))
            })?;
        Ok(res)
    }

    #[must_use]
    pub fn find<T: ChainbaseObject>(
        &mut self,
        key: T::PrimaryKey,
    ) -> Result<Option<T>, ChainbaseError> {
        let partition = open_partition(&self.keyspace, T::table_name())?;
        let mut tx = self.tx.borrow_mut();
        let serialized = tx
            .get(&partition, T::primary_key_to_bytes(key))
            .map_err(|_| ChainbaseError::InternalError(format!("failed to get object for key")))?;
        if serialized.is_none() {
            return Ok(None);
        }
        let mut pos = 0 as usize;
        let object: T = T::read(&serialized.unwrap(), &mut pos).expect("failed to read object");
        Ok(Some(object))
    }

    #[must_use]
    pub fn get<T: ChainbaseObject>(&mut self, key: T::PrimaryKey) -> Result<T, ChainbaseError> {
        let found = self.find::<T>(key)?;
        if found.is_none() {
            return Err(ChainbaseError::NotFound);
        }
        let object = found.unwrap();
        Ok(object)
    }

    #[must_use]
    pub fn find_by_secondary<T: ChainbaseObject, S: SecondaryIndex<T>>(
        &mut self,
        key: S::Key,
    ) -> Result<Option<T>, ChainbaseError> {
        let partition = open_partition(&self.keyspace, S::index_name())?;
        let mut tx = self.tx.borrow_mut();
        let secondary_key = tx
            .get(&partition, S::secondary_key_as_bytes(key))
            .map_err(|_| ChainbaseError::InternalError(format!("failed to get secondary key")))?;
        if secondary_key.is_none() {
            return Ok(None);
        }
        let partition = open_partition(&self.keyspace, T::table_name())?;
        let serialized = tx.get(&partition, secondary_key.unwrap()).map_err(|_| {
            ChainbaseError::InternalError(format!("failed to get object for secondary key"))
        })?;
        if serialized.is_none() {
            return Ok(None);
        }
        let mut pos = 0 as usize;
        let object: T = T::read(&serialized.unwrap(), &mut pos).expect("failed to read object");
        Ok(Some(object))
    }

    pub fn generate_id<T: ChainbaseObject>(&mut self) -> Result<u64, ChainbaseError> {
        let partition = open_partition(&self.keyspace, T::table_name())?;
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
        })
        .map_err(|_| {
            ChainbaseError::InternalError(format!(
                "failed to generate new ID for table: {}",
                T::table_name()
            ))
        })?;
        Ok(new_id)
    }

    pub fn insert<T: ChainbaseObject>(&mut self, object: &T) -> Result<(), ChainbaseError> {
        let key = object.primary_key();
        let serialized = object.pack().map_err(|_| {
            ChainbaseError::InternalError(format!("failed to serialize object for key: {:?}", key))
        })?;
        let partition = open_partition(&self.keyspace, T::table_name())?;
        let mut tx = self.tx.borrow_mut();
        let exists = tx.contains_key(&partition, &key).map_err(|_| {
            ChainbaseError::InternalError(format!("failed to check existence for key: {:?}", key))
        })?;
        if exists {
            return Err(ChainbaseError::AlreadyExists);
        }
        let mut changes = self.changes.borrow_mut();
        changes.push_back(ObjectChange::New(key.to_owned()));
        tx.insert(&partition, &key, serialized);
        for index in object.secondary_indexes() {
            let partition = open_partition(&self.keyspace, index.index_name)?;
            tx.insert(&partition, &index.key, &key);
        }
        Ok(())
    }

    pub fn modify<T, F>(&mut self, old: &mut T, f: F) -> Result<(), ChainbaseError>
    where
        T: ChainbaseObject,
        F: FnOnce(&mut T),
    {
        let key = old.primary_key();
        let partition = open_partition(&self.keyspace, T::table_name())?;
        let mut tx = self.tx.borrow_mut();
        let existing = tx.get(&partition, &key).map_err(|_| {
            ChainbaseError::InternalError(format!(
                "failed to get existing object for key: {:?}",
                key
            ))
        })?;
        if existing.is_none() {
            return Err(ChainbaseError::NotFound);
        }
        f(old);
        let serialized_old = existing.unwrap().to_vec();
        let serialized_new = old.pack().map_err(|_| {
            ChainbaseError::InternalError(format!(
                "failed to serialize modified object for key: {:?}",
                key
            ))
        })?;
        let mut changes = self.changes.borrow_mut();
        changes.push_back(ObjectChange::Modified(
            key.to_owned(),
            serialized_old,
            serialized_new.to_owned(),
        ));
        tx.insert(&partition, &key, serialized_new);
        Ok(())
    }

    pub fn remove<T: ChainbaseObject>(&mut self, object: T) -> Result<(), ChainbaseError> {
        let key = object.primary_key();
        let partition = open_partition(&self.keyspace, T::table_name())?;
        let mut tx = self.tx.borrow_mut();
        let old_value = tx.get(&partition, &key).map_err(|_| {
            ChainbaseError::InternalError(format!("failed to get object for key: {:?}", key))
        })?;
        if old_value.is_none() {
            return Err(ChainbaseError::NotFound);
        }
        let mut changes = self.changes.borrow_mut();
        changes.push_back(ObjectChange::Deleted(
            key.to_owned(),
            old_value.unwrap().to_vec(),
        ));
        tx.remove(&partition, &key);
        for index in object.secondary_indexes() {
            let partition = open_partition(&self.keyspace, index.index_name)?;
            tx.remove(&partition, &index.key);
        }
        Ok(())
    }

    pub fn commit(self) -> Result<(), ChainbaseError> {
        let tx = Rc::try_unwrap(self.tx)
            .map_err(|_| "failed to unwrap Rc: multiple owners".to_string())
            .map_err(|_| ChainbaseError::InternalError("failed to unwrap transaction".to_string()))?
            .into_inner();
        let result = tx.commit();
        if result.is_err() {
            return Err(ChainbaseError::InternalError(
                "failed to commit transaction".to_string(),
            ));
        }
        Ok(())
    }

    pub fn rollback(self) -> Result<(), ChainbaseError> {
        let tx = Rc::try_unwrap(self.tx)
            .map_err(|_| "failed to unwrap Rc: multiple owners".to_string())
            .map_err(|_| ChainbaseError::InternalError("failed to unwrap transaction".to_string()))?
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
