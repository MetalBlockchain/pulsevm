use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use heed::{Database, Env, PutFlags, RwTxn, types::Bytes};

use crate::{ChainbaseError, ChainbaseObject, SecondaryIndex, Session, index::Index};

#[derive(Clone)]
pub struct UndoSession {
    tx: Arc<RwLock<WriteTransaction>>,
    keyspace: TransactionalKeyspace,
    partition_create_options: PartitionCreateOptions,
}

impl<'a> UndoSession<'a> {
    #[inline]
    pub fn new(
        databases: Arc<RwLock<HashMap<&'static str, Database<Bytes, Bytes>>>>,
        tx: RwTxn<'a>,
    ) -> Result<Self, ChainbaseError> {
        Ok(Self {
            tx: Arc::new(RwLock::new(keyspace.write_tx().map_err(|_| {
                ChainbaseError::InternalError("failed to create write transaction".to_string())
            })?)),
            keyspace: keyspace.clone(),
            partition_create_options,
        })
    }

    #[inline]
    pub fn get_database(
        &self,
        name: &'static str,
    ) -> Result<Database<Bytes, Bytes>, ChainbaseError> {
        let databases = self
            .databases
            .read()
            .map_err(|_| ChainbaseError::InternalError("failed to get db".into()))?;

        if let Some(db) = databases.get(name) {
            Ok(db.clone())
        } else {
            Err(ChainbaseError::NotFound)
        }
    }

    #[inline]
    pub fn generate_id<T: ChainbaseObject>(&mut self) -> Result<u64, ChainbaseError> {
        let db = self.get_database(T::table_name())?;
        let mut tx = self
            .tx
            .write()
            .map_err(|e| ChainbaseError::InternalError(format!("failed to lock tx: {}", e)))?;
        let current_id = match db.get(&tx, &KEY) {
            Ok(Some(bytes)) => u64::from_le_bytes(bytes.try_into().map_err(|e| {
                ChainbaseError::InternalError(format!("failed to convert bytes to id: {}", e))
            })?),
            Ok(None) => 0,
            Err(e) => {
                return Err(ChainbaseError::InternalError(format!(
                    "failed to get current id: {}",
                    e
                )));
            }
        };

        // Compute new ID
        let new_id = current_id + 1;

        // Store new ID
        db.put(&mut tx, &KEY, &new_id.to_le_bytes())
            .map_err(|e| ChainbaseError::InternalError(format!("failed to store new id: {}", e)))?;

        Ok(new_id)
    }

    #[inline]
    pub fn insert<T: ChainbaseObject>(&mut self, object: &T) -> Result<(), ChainbaseError> {
        let key = object.primary_key();
        let db = self.get_database(T::table_name())?;
        let mut tx = self
            .tx
            .write()
            .map_err(|_| ChainbaseError::InternalError(format!("failed to write transaction")))?;
        let key = object.primary_key();
        let partition = open_partition(
            &self.keyspace,
            T::table_name(),
            self.partition_create_options.clone(),
        )?;
        let serialized = object.pack().map_err(|_| {
            ChainbaseError::InternalError(format!("failed to serialize object for key: {:?}", key))
        })?;
        tx.insert(&partition, &key, serialized);

        for index in object.secondary_indexes() {
            let part = open_partition(
                &self.keyspace,
                index.index_name,
                self.partition_create_options.clone(),
            )?;
            tx.insert(&part, &index.key, &key);
        }
        Ok(())
    }

    #[inline]
    pub fn modify<T, F>(&mut self, obj: &mut T, f: F) -> Result<(), ChainbaseError>
    where
        T: ChainbaseObject,
        F: FnOnce(&mut T) -> Result<()>,
    {
        let mut tx = self
            .tx
            .write()
            .map_err(|_| ChainbaseError::InternalError(format!("failed to write transaction")))?;
        let partition = open_partition(
            &self.keyspace,
            T::table_name(),
            self.partition_create_options.clone(),
        )?;
        let key = old.primary_key();
        f(old).map_err(|e| {
            ChainbaseError::InternalError(format!("failed to modify object for key {:?}: {e}", key))
        })?;
        let new_bytes = old.pack().map_err(|_| {
            ChainbaseError::InternalError(format!(
                "failed to serialize modified object for key: {:?}",
                key
            ))
        })?;
        tx.insert(&partition, &key, new_bytes);
        Ok(())
    }

    #[inline]
    pub fn remove<T: ChainbaseObject>(&mut self, object: T) -> Result<(), ChainbaseError> {
        let key = object.primary_key();
        let db = self.get_database(T::table_name())?;
        let mut tx = self
            .tx
            .write()
            .map_err(|e| ChainbaseError::InternalError(format!("failed to lock tx: {}", e)))?;
        db.delete(&mut tx, &key).map_err(|e| {
            ChainbaseError::InternalError(format!(
                "failed to delete object for key {:?}: {}",
                key, e
            ))
        })?;
        if old_value.is_none() {
            return Err(ChainbaseError::NotFound);
        }
        tx.remove(&partition, &key);
        for index in object.secondary_indexes() {
            let partition = open_partition(
                &self.keyspace,
                index.index_name,
                self.partition_create_options.clone(),
            )?;
            tx.remove(&partition, &index.key);
        }
        Ok(())
    }

        for index in object.secondary_indexes().iter() {
            let db = self.get_database(index.index_name)?;
            db.delete(&mut tx, &index.key).map_err(|e| {
                ChainbaseError::InternalError(format!(
                    "failed to delete secondary index for key {:?}: {}",
                    key, e
                ))
            })?;
        }

        Ok(())
    }

    #[inline]
    pub fn commit(self) -> Result<(), ChainbaseError> {
        Arc::try_unwrap(self.tx)
            .map_err(|_| ChainbaseError::InternalError("failed to unwrap tx".into()))?
            .into_inner()
            .map_err(|_| ChainbaseError::InternalError("failed to lock tx for commit".into()))?
            .commit()
            .map_err(|e| ChainbaseError::InternalError(format!("failed to commit tx: {}", e)))?;
        Ok(())
    }

    #[inline]
    pub fn get_index<C, S>(&self) -> Index<'a, C, S>
    where
        C: ChainbaseObject,
        S: SecondaryIndex<C>,
    {
        Index::new(self.clone())
    }
}

impl Session for UndoSession<'_> {
    fn exists<T: ChainbaseObject>(&mut self, key: T::PrimaryKey) -> Result<bool, ChainbaseError> {
        let db = self.get_database(T::table_name())?;
        let tx = self
            .tx
            .read()
            .map_err(|e| ChainbaseError::InternalError(format!("{}", e)))?;
        let res = db.get(&tx, &T::primary_key_to_bytes(key));

        match res {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(ChainbaseError::InternalError(format!(
                "failed to check existence: {}",
                e
            ))),
        }
    }

    fn find<T: ChainbaseObject>(&self, key: T::PrimaryKey) -> Result<Option<T>, ChainbaseError> {
        let db = self.get_database(T::table_name())?;
        let tx = self
            .tx
            .read()
            .map_err(|e| ChainbaseError::InternalError(format!("{}", e)))?;
        let res = db.get(&tx, &T::primary_key_to_bytes(key));

        match res {
            Ok(Some(data)) => {
                let mut pos = 0;
                let object: T = T::read(&data, &mut pos).map_err(|_| ChainbaseError::ReadError)?;
                return Ok(Some(object));
            }
            Ok(None) => {
                return Ok(None);
            }
            Err(e) => {
                return Err(ChainbaseError::InternalError(format!(
                    "failed to get object: {}",
                    e
                )));
            }
        };
    }

    fn find_by_secondary<T: ChainbaseObject, S: SecondaryIndex<T>>(
        &self,
        key: S::Key,
    ) -> Result<Option<T>, ChainbaseError> {
        let res = self.get_by_secondary::<T, S>(key);

        match res {
            Ok(obj) => Ok(Some(obj)),
            Err(ChainbaseError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get<T: ChainbaseObject>(&self, key: T::PrimaryKey) -> Result<T, ChainbaseError> {
        let found = self.find::<T>(key)?;

        match found {
            Some(obj) => Ok(obj),
            None => Err(ChainbaseError::NotFound),
        }
    }

    fn get_by_secondary<T: ChainbaseObject, S: SecondaryIndex<T>>(
        &self,
        key: S::Key,
    ) -> Result<T, ChainbaseError> {
        let db = self.get_database(S::index_name())?;
        let tx = self
            .tx
            .read()
            .map_err(|e| ChainbaseError::InternalError(format!("{}", e)))?;
        let secondary_key = db.get(&tx, &S::secondary_key_as_bytes(key));
        let secondary_key = match secondary_key {
            Err(e) => {
                return Err(ChainbaseError::InternalError(format!(
                    "failed to get secondary key: {}",
                    e
                )));
            }
            Ok(Some(v)) => v,
            Ok(None) => return Err(ChainbaseError::NotFound),
        };

        let db = self.get_database(T::table_name())?;
        let res = db.get(&tx, &secondary_key);

        match res {
            Ok(Some(data)) => {
                let mut pos = 0;
                let object: T = T::read(&data, &mut pos).map_err(|_| ChainbaseError::ReadError)?;
                return Ok(object);
            }
            Ok(None) => {
                return Err(ChainbaseError::NotFound);
            }
            Err(e) => {
                return Err(ChainbaseError::InternalError(format!(
                    "failed to get object: {}",
                    e
                )));
            }
        };
    }
}
