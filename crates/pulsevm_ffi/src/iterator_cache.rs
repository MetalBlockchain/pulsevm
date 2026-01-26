use std::{ops::Deref, pin::Pin};

use pulsevm_error::ChainError;

use crate::objects::ffi::{KeyValueObject, TableId, TableObject};

#[cxx::bridge(namespace = "pulsevm::chain")]
pub mod ffi {
    unsafe extern "C++" {
        include!("iterator_cache.hpp");

        type TableObject = crate::objects::ffi::TableObject;
        type TableId = crate::objects::ffi::TableId;
        type KeyValueObject = crate::objects::ffi::KeyValueObject;

        pub type CxxKeyValueIteratorCache;
        pub fn new_key_value_iterator_cache() -> UniquePtr<CxxKeyValueIteratorCache>;
        pub fn cache_table(
            self: Pin<&mut CxxKeyValueIteratorCache>,
            table: &TableObject,
        ) -> Result<i32>;
        pub fn get_table(
            self: &CxxKeyValueIteratorCache,
            table_id: &TableId,
        ) -> Result<&TableObject>;
        pub fn get_end_iterator_by_table_id(
            self: &CxxKeyValueIteratorCache,
            table_id: &TableId,
        ) -> Result<i32>;
        pub fn find_table_by_end_iterator(
            self: &CxxKeyValueIteratorCache,
            ei: i32,
        ) -> Result<*const TableObject>;
        pub fn get(self: &CxxKeyValueIteratorCache, iterator: i32) -> Result<&KeyValueObject>;
        pub fn remove(self: Pin<&mut CxxKeyValueIteratorCache>, iterator: i32) -> Result<()>;
        pub fn add(self: Pin<&mut CxxKeyValueIteratorCache>, obj: &KeyValueObject) -> Result<i32>;
    }
}

pub struct CxxKeyValueIteratorCache {
    inner: cxx::UniquePtr<ffi::CxxKeyValueIteratorCache>,
}

impl CxxKeyValueIteratorCache {
    pub fn new() -> Self {
        let inner = ffi::new_key_value_iterator_cache();
        CxxKeyValueIteratorCache { inner }
    }

    pub fn pin_mut(&mut self) -> Pin<&mut ffi::CxxKeyValueIteratorCache> {
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

impl Deref for CxxKeyValueIteratorCache {
    type Target = cxx::UniquePtr<ffi::CxxKeyValueIteratorCache>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

unsafe impl Send for ffi::CxxKeyValueIteratorCache {}
unsafe impl Sync for ffi::CxxKeyValueIteratorCache {}
