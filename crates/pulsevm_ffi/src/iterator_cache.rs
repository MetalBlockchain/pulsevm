use std::{ops::Deref, pin::Pin};

use pulsevm_error::ChainError;

use crate::{KeyValue, Table, TableId};

#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    unsafe extern "C++" {
        include!("iterator_cache.hpp");

        #[cxx_name = "table_id_object"]
        type Table = crate::contract_table_objects::ffi::Table;
        #[cxx_name = "table_id"]
        type TableId = crate::contract_table_objects::ffi::TableId;
        #[cxx_name = "key_value_object"]
        type KeyValue = crate::contract_table_objects::ffi::KeyValue;

        #[cxx_name = "key_value_iterator_cache"]
        pub type KeyValueIteratorCache;
        pub fn new_key_value_iterator_cache() -> UniquePtr<KeyValueIteratorCache>;
        pub fn cache_table(self: Pin<&mut KeyValueIteratorCache>, table: &Table) -> Result<i32>;
        pub fn get_table(self: &KeyValueIteratorCache, table_id: &TableId) -> Result<&Table>;
        pub fn get_end_iterator_by_table_id(
            self: &KeyValueIteratorCache,
            table_id: &TableId,
        ) -> Result<i32>;
        pub fn find_table_by_end_iterator(
            self: &KeyValueIteratorCache,
            ei: i32,
        ) -> Result<*const Table>;
        pub fn get(self: Pin<&mut KeyValueIteratorCache>, iterator: i32) -> Result<&KeyValue>;
        pub fn remove(self: Pin<&mut KeyValueIteratorCache>, iterator: i32) -> Result<()>;
        pub fn add(self: Pin<&mut KeyValueIteratorCache>, obj: &KeyValue) -> Result<i32>;
    }
}

pub struct KeyValueIteratorCache {
    inner: cxx::UniquePtr<ffi::KeyValueIteratorCache>,
}

impl KeyValueIteratorCache {
    pub fn new() -> Self {
        let inner = ffi::new_key_value_iterator_cache();
        KeyValueIteratorCache { inner }
    }

    pub fn pin_mut(&mut self) -> Pin<&mut ffi::KeyValueIteratorCache> {
        self.inner.pin_mut()
    }

    pub fn cache_table(&mut self, table: &Table) -> Result<i32, ChainError> {
        self.inner
            .pin_mut()
            .cache_table(table)
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn get_table(&self, table_id: &TableId) -> Result<&Table, ChainError> {
        self.inner
            .get_table(table_id)
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn get_end_iterator_by_table_id(&self, table_id: &TableId) -> Result<i32, ChainError> {
        self.inner
            .get_end_iterator_by_table_id(table_id)
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn find_table_by_end_iterator(&self, ei: i32) -> Result<Option<&Table>, ChainError> {
        let res = self
            .inner
            .find_table_by_end_iterator(ei)
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))?;

        match res.is_null() {
            true => Ok(None),
            false => unsafe { Ok(Some(&*res)) },
        }
    }

    pub fn get(&mut self, id: i32) -> Result<&KeyValue, ChainError> {
        self.inner
            .pin_mut()
            .get(id)
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn remove(&mut self, iterator: i32) -> Result<(), ChainError> {
        self.inner
            .pin_mut()
            .remove(iterator)
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }

    pub fn add(&mut self, obj: &KeyValue) -> Result<i32, ChainError> {
        self.inner
            .pin_mut()
            .add(obj)
            .map_err(|e| ChainError::InternalError(Some(format!("{}", e))))
    }
}

impl Deref for KeyValueIteratorCache {
    type Target = cxx::UniquePtr<ffi::KeyValueIteratorCache>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
