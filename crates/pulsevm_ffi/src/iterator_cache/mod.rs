use std::{ops::Deref, pin::Pin};

use pulsevm_error::ChainError;

use crate::{
    KeyValueObject, TableId, TableObject,
    bridge::ffi::{CxxKeyValueIteratorCache, new_key_value_iterator_cache},
};

pub struct KeyValueIteratorCache {
    inner: cxx::UniquePtr<CxxKeyValueIteratorCache>,
}

impl KeyValueIteratorCache {
    pub fn new() -> Self {
        let inner = new_key_value_iterator_cache();
        KeyValueIteratorCache { inner }
    }

    pub fn pin_mut(&mut self) -> Pin<&mut CxxKeyValueIteratorCache> {
        self.inner.pin_mut()
    }

    pub fn cache_table(&mut self, table: &TableObject) -> Result<i32, ChainError> {
        self.inner
            .pin_mut()
            .cache_table(table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_table(&self, table_id: &TableId) -> Result<&TableObject, ChainError> {
        self.inner
            .get_table(table_id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_end_iterator_by_table_id(&self, table_id: &TableId) -> Result<i32, ChainError> {
        self.inner
            .get_end_iterator_by_table_id(table_id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn find_table_by_end_iterator(&self, ei: i32) -> Result<Option<&TableObject>, ChainError> {
        let res = self
            .inner
            .find_table_by_end_iterator(ei)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        match res.is_null() {
            true => Ok(None),
            false => unsafe { Ok(Some(&*res)) },
        }
    }

    pub fn get(&self, id: i32) -> Result<&KeyValueObject, ChainError> {
        self.inner
            .get(id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn remove(&mut self, iterator: i32) -> Result<(), ChainError> {
        self.inner
            .pin_mut()
            .remove(iterator)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn add(&mut self, obj: &KeyValueObject) -> Result<i32, ChainError> {
        self.inner
            .pin_mut()
            .add(obj)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }
}

impl Deref for KeyValueIteratorCache {
    type Target = cxx::UniquePtr<CxxKeyValueIteratorCache>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

unsafe impl Send for KeyValueIteratorCache {}
unsafe impl Sync for KeyValueIteratorCache {}
