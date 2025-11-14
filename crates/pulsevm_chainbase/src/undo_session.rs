use std::{
    collections::VecDeque,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use fjall::{PartitionCreateOptions, Slice, TransactionalKeyspace, WriteTransaction};

use crate::{ChainbaseError, ChainbaseObject, SecondaryIndex, index::Index, open_partition};

enum ObjectChange {
    New(Vec<u8>),                      // key
    Modified(Vec<u8>, Slice, Vec<u8>), // (key, old, new)
    Deleted(Vec<u8>, Vec<u8>),         // key, previous value
}

#[derive(Clone)]
pub struct UndoSession {
    changes: Arc<RwLock<VecDeque<ObjectChange>>>,
    tx: Arc<RwLock<WriteTransaction>>,
    keyspace: TransactionalKeyspace,
    partition_create_options: PartitionCreateOptions,
}

impl UndoSession {
    #[inline]
    pub fn new(keyspace: &TransactionalKeyspace, partition_create_options: PartitionCreateOptions) -> Result<Self, ChainbaseError> {
        Ok(Self {
            changes: Arc::new(RwLock::new(VecDeque::new())),
            tx: Arc::new(RwLock::new(keyspace.write_tx().map_err(|_| {
                ChainbaseError::InternalError("failed to create write transaction".to_string())
            })?)),
            keyspace: keyspace.clone(),
            partition_create_options,
        })
    }

    #[inline]
    pub fn tx(&self) -> Arc<RwLock<WriteTransaction>> {
        self.tx.clone()
    }

    #[inline]
    pub fn keyspace(&self) -> TransactionalKeyspace {
        self.keyspace.clone()
    }

    #[must_use]
    #[inline]
    pub fn exists<T: ChainbaseObject>(
        &mut self,
        key: T::PrimaryKey,
    ) -> Result<bool, ChainbaseError> {
        let partition = open_partition(&self.keyspace, T::table_name(), self.partition_create_options.clone())?;
        let mut tx = self
            .tx
            .write()
            .map_err(|_| ChainbaseError::InternalError(format!("failed to write transaction")))?;
        let res = tx
            .contains_key(&partition, T::primary_key_to_bytes(key))
            .map_err(|_| {
                ChainbaseError::InternalError(format!("failed to check existence for key"))
            })?;
        Ok(res)
    }

    #[must_use]
    #[inline]
    pub fn find<T: ChainbaseObject>(
        &mut self,
        key: T::PrimaryKey,
    ) -> Result<Option<T>, ChainbaseError> {
        let partition = open_partition(&self.keyspace, T::table_name(), self.partition_create_options.clone())?;
        let mut tx = self
            .tx
            .write()
            .map_err(|_| ChainbaseError::InternalError(format!("failed to write transaction")))?;
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
    #[inline]
    pub fn get<T: ChainbaseObject>(&mut self, key: T::PrimaryKey) -> Result<T, ChainbaseError> {
        let found = self.find::<T>(key)?;
        if found.is_none() {
            return Err(ChainbaseError::NotFound);
        }
        let object = found.unwrap();
        Ok(object)
    }

    #[must_use]
    #[inline]
    pub fn get_by_secondary<T: ChainbaseObject, S: SecondaryIndex<T>>(
        &mut self,
        key: S::Key,
    ) -> Result<T, ChainbaseError> {
        let partition = open_partition(&self.keyspace, S::index_name(), self.partition_create_options.clone())?;
        let mut tx = self
            .tx
            .write()
            .map_err(|_| ChainbaseError::InternalError(format!("failed to write transaction")))?;
        let secondary_key = tx
            .get(&partition, S::secondary_key_as_bytes(key))
            .map_err(|_| ChainbaseError::InternalError(format!("failed to get secondary key")))?;
        if secondary_key.is_none() {
            return Err(ChainbaseError::NotFound);
        }
        let partition = open_partition(&self.keyspace, T::table_name(), self.partition_create_options.clone())?;
        let serialized = tx.get(&partition, secondary_key.unwrap()).map_err(|_| {
            ChainbaseError::InternalError(format!("failed to get object for secondary key"))
        })?;
        if serialized.is_none() {
            return Err(ChainbaseError::NotFound);
        }
        let mut pos = 0 as usize;
        let object: T = T::read(&serialized.unwrap(), &mut pos)
            .map_err(|_| ChainbaseError::InternalError(format!("failed to read object")))?;
        Ok(object)
    }

    #[must_use]
    #[inline]
    pub fn find_by_secondary<T: ChainbaseObject, S: SecondaryIndex<T>>(
        &mut self,
        key: S::Key,
    ) -> Result<Option<T>, ChainbaseError> {
        let mut tx = self
            .tx
            .write()
            .map_err(|_| ChainbaseError::InternalError(format!("failed to write transaction")))?;
        let sec_part = open_partition(&self.keyspace, S::index_name(), self.partition_create_options.clone())?;
        if let Some(primary_key) = tx
            .get(&sec_part, S::secondary_key_as_bytes(key))
            .map_err(|_| ChainbaseError::InternalError("failed to get secondary key".into()))?
        {
            let prim_part = open_partition(&self.keyspace, T::table_name(), self.partition_create_options.clone())?;
            if let Some(bytes) = tx.get(&prim_part, primary_key).map_err(|_| {
                ChainbaseError::InternalError("failed to get object for secondary key".into())
            })? {
                let mut pos = 0usize;
                let obj = T::read(&bytes, &mut pos)
                    .map_err(|_| ChainbaseError::InternalError("failed to read object".into()))?;
                return Ok(Some(obj));
            }
        }
        Ok(None)
    }

    #[inline]
    pub fn generate_id<T: ChainbaseObject>(&mut self) -> Result<u64, ChainbaseError> {
        let partition = open_partition(&self.keyspace, T::table_name(), self.partition_create_options.clone())?;
        let mut new_id = 1u64;
        let mut tx = self
            .tx
            .write()
            .map_err(|_| ChainbaseError::InternalError(format!("failed to write transaction")))?;
        // Do we have a sequence for this table?
        tx.fetch_update(&partition, "id", |v| {
            if v.is_none() {
                return Some(Slice::new(&1u64.to_le_bytes()));
            }
            let id = v.unwrap();
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&id);
            let mut id = u64::from_le_bytes(arr);
            id += 1;
            new_id = id;
            Some(Slice::new(&id.to_le_bytes()))
        })
        .map_err(|_| {
            ChainbaseError::InternalError(format!(
                "failed to generate new ID for table: {}",
                T::table_name()
            ))
        })?;
        Ok(new_id)
    }

    #[inline]
    pub fn insert<T: ChainbaseObject>(&mut self, object: &T) -> Result<(), ChainbaseError> {
        let mut tx = self
            .tx
            .write()
            .map_err(|_| ChainbaseError::InternalError(format!("failed to write transaction")))?;
        let key = object.primary_key();
        let partition = open_partition(&self.keyspace, T::table_name(), self.partition_create_options.clone())?;
        let exists = tx.contains_key(&partition, &key).map_err(|_| {
            ChainbaseError::InternalError(format!("failed to check existence for key: {:?}", key))
        })?;
        if exists {
            return Err(ChainbaseError::AlreadyExists);
        }

        let serialized = object.pack().map_err(|_| {
            ChainbaseError::InternalError(format!("failed to serialize object for key: {:?}", key))
        })?;

        let mut changes = self
            .changes
            .write()
            .map_err(|_| ChainbaseError::InternalError(format!("failed to write changes")))?;
        changes.push_back(ObjectChange::New(key.to_owned()));

        tx.insert(&partition, &key, serialized);

        for index in object.secondary_indexes() {
            let part = open_partition(&self.keyspace, index.index_name, self.partition_create_options.clone())?;
            tx.insert(&part, &index.key, &key);
        }
        Ok(())
    }

    #[inline]
    pub fn modify<T, F>(&mut self, old: &mut T, f: F) -> Result<(), ChainbaseError>
    where
        T: ChainbaseObject,
        F: FnOnce(&mut T) -> Result<()>,
    {
        let mut tx = self
            .tx
            .write()
            .map_err(|_| ChainbaseError::InternalError(format!("failed to write transaction")))?;
        let partition = open_partition(&self.keyspace, T::table_name(), self.partition_create_options.clone())?;
        let key = old.primary_key();
        let key_bytes = old.primary_key();

        let existing = tx.get(&partition, &key_bytes).map_err(|_| {
            ChainbaseError::InternalError(format!(
                "failed to get existing object for key: {:?}",
                key
            ))
        })?;
        let Some(old_bytes) = existing else {
            return Err(ChainbaseError::NotFound);
        };

        f(old).map_err(|e| {
            ChainbaseError::InternalError(format!("failed to modify object for key {:?}: {e}", key))
        })?;

        let new_bytes = old.pack().map_err(|_| {
            ChainbaseError::InternalError(format!(
                "failed to serialize modified object for key: {:?}",
                key
            ))
        })?;

        let mut changes = self
            .changes
            .write()
            .map_err(|_| ChainbaseError::InternalError(format!("failed to write changes")))?;
        changes.push_back(ObjectChange::Modified(
            key.to_owned(),
            old_bytes,         // moved
            new_bytes.clone(), // keep a copy for insertion below
        ));

        tx.insert(&partition, &key, new_bytes);
        Ok(())
    }

    #[inline]
    pub fn remove<T: ChainbaseObject>(&mut self, object: T) -> Result<(), ChainbaseError> {
        let key = object.primary_key();
        let partition = open_partition(&self.keyspace, T::table_name(), self.partition_create_options.clone())?;
        let mut tx = self
            .tx
            .write()
            .map_err(|_| ChainbaseError::InternalError(format!("failed to write transaction")))?;
        let old_value = tx.get(&partition, &key).map_err(|_| {
            ChainbaseError::InternalError(format!("failed to get object for key: {:?}", key))
        })?;
        if old_value.is_none() {
            return Err(ChainbaseError::NotFound);
        }
        let mut changes = self
            .changes
            .write()
            .map_err(|_| ChainbaseError::InternalError(format!("failed to write changes")))?;
        changes.push_back(ObjectChange::Deleted(
            key.to_owned(),
            old_value.unwrap().to_vec(),
        ));
        tx.remove(&partition, &key);
        for index in object.secondary_indexes() {
            let partition = open_partition(&self.keyspace, index.index_name, self.partition_create_options.clone())?;
            tx.remove(&partition, &index.key);
        }
        Ok(())
    }

    #[inline]
    pub fn commit(self) -> Result<(), ChainbaseError> {
        let tx = Arc::try_unwrap(self.tx)
            .map_err(|_| "failed to unwrap Rc: multiple owners".to_string())
            .map_err(|_| ChainbaseError::InternalError("failed to unwrap transaction".to_string()))?
            .into_inner()
            .map_err(|_| {
                ChainbaseError::InternalError("failed to get inner transaction".to_string())
            })?;
        let result = tx.commit();
        if result.is_err() {
            return Err(ChainbaseError::InternalError(
                "failed to commit transaction".to_string(),
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn rollback(self) -> Result<(), ChainbaseError> {
        let tx = Arc::try_unwrap(self.tx)
            .map_err(|_| "failed to unwrap Rc: multiple owners".to_string())
            .map_err(|_| ChainbaseError::InternalError("failed to unwrap transaction".to_string()))?
            .into_inner()
            .map_err(|_| {
                ChainbaseError::InternalError("failed to get inner transaction".to_string())
            })?;
        tx.rollback();
        Ok(())
    }

    #[inline]
    pub fn get_index<C, S>(&self) -> Index<C, S>
    where
        C: ChainbaseObject,
        S: SecondaryIndex<C>,
    {
        Index::<C, S>::new(self.clone(), self.keyspace.clone())
    }
}
