use std::{
    collections::{HashMap, VecDeque},
    env,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use heed::{Database, PutFlags, RoTxn, RwTxn, WithTls, types::Bytes};

use crate::{
    ChainbaseError, ChainbaseObject, SecondaryIndex, Session, index::Index, ro_index::ReadOnlyIndex,
};

const KEY: &[u8] = b"id";

pub struct ReadOnlySession<'a> {
    pub databases: Arc<RwLock<HashMap<&'static str, Database<Bytes, Bytes>>>>,
    pub tx: RoTxn<'a, WithTls>,
}

impl<'a> ReadOnlySession<'a> {
    #[inline]
    pub fn new(
        tx: RoTxn<'a, WithTls>,
        databases: Arc<RwLock<HashMap<&'static str, Database<Bytes, Bytes>>>>,
    ) -> Result<Self, ChainbaseError> {
        Ok(Self { databases, tx })
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
    pub fn get_index<C, S>(&self) -> ReadOnlyIndex<C, S>
    where
        C: ChainbaseObject,
        S: SecondaryIndex<C>,
    {
        ReadOnlyIndex::<C, S>::new(self)
    }
}

impl Session for ReadOnlySession<'_> {
    fn exists<T: ChainbaseObject>(&mut self, key: T::PrimaryKey) -> Result<bool, ChainbaseError> {
        let db = self.get_database(T::table_name())?;
        let res = db.get(&self.tx, &T::primary_key_to_bytes(key));

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
        let res = db.get(&self.tx, &T::primary_key_to_bytes(key));

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
        let secondary_key = db.get(&self.tx, &S::secondary_key_as_bytes(key));
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
        let res = db.get(&self.tx, &secondary_key);

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
