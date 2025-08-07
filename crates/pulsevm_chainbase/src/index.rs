use std::{io::Chain, ops::Bound};

use fjall::{TransactionalKeyspace, TransactionalPartitionHandle};
use pulsevm_serialization::Write;

use crate::{ChainbaseError, ChainbaseObject, SecondaryIndex, UndoSession};

#[derive(Clone)]
pub struct Index<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    undo_session: UndoSession,
    keyspace: TransactionalKeyspace,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<C, S> Index<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    pub fn new(undo_session: UndoSession, keyspace: TransactionalKeyspace) -> Self {
        Index::<C, S> {
            undo_session,
            keyspace,
            __phantom: std::marker::PhantomData,
        }
    }

    pub fn iterator_to(
        &mut self,
        object: &S::Object,
    ) -> Result<IndexIterator<C, S>, ChainbaseError> {
        Ok(IndexIterator::<C, S> {
            undo_session: self.undo_session.clone(),
            partition: self
                .keyspace
                .clone()
                .open_partition(S::index_name(), Default::default())
                .map_err(|_| ChainbaseError::InternalError(format!("failed to open partition")))?,
            current_key: S::secondary_key(object),
            current_value: object.primary_key(),
            __phantom: std::marker::PhantomData,
        })
    }

    pub fn lower_bound(&mut self, key: impl Write) -> Result<RangeIterator<C, S>, ChainbaseError> {
        let key_bytes = key.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;

        Ok(RangeIterator::<C, S> {
            undo_session: self.undo_session.clone(),
            partition: self
                .keyspace
                .clone()
                .open_partition(S::index_name(), Default::default())
                .map_err(|_| ChainbaseError::InternalError(format!("failed to open partition")))?,
            range: (Bound::Included(key_bytes.clone()), Bound::Unbounded),
            current_key: key_bytes,
            current_value: Vec::new(),
            __phantom: std::marker::PhantomData,
        })
    }

    pub fn upper_bound(&mut self, key: impl Write) -> Result<RangeIterator<C, S>, ChainbaseError> {
        let key_bytes = key.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;

        Ok(RangeIterator::<C, S> {
            undo_session: self.undo_session.clone(),
            partition: self
                .keyspace
                .clone()
                .open_partition(S::index_name(), Default::default())
                .map_err(|_| ChainbaseError::InternalError(format!("failed to open partition")))?,
            range: (Bound::Excluded(key_bytes.clone()), Bound::Unbounded),
            current_key: key_bytes,
            current_value: Vec::new(),
            __phantom: std::marker::PhantomData,
        })
    }
}

pub struct RangeIterator<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    undo_session: UndoSession,
    partition: TransactionalPartitionHandle,
    range: (Bound<Vec<u8>>, Bound<Vec<u8>>),
    current_key: Vec<u8>,
    current_value: Vec<u8>,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<C, S> RangeIterator<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    pub fn new(
        undo_session: UndoSession,
        partition: TransactionalPartitionHandle,
        range: (Bound<Vec<u8>>, Bound<Vec<u8>>),
    ) -> Self {
        RangeIterator::<C, S> {
            undo_session,
            partition,
            range,
            current_key: Vec::new(),
            current_value: Vec::new(),
            __phantom: std::marker::PhantomData,
        }
    }

    pub fn previous(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let prev = {
            let tx = self.undo_session.tx();
            let mut tx = tx.write().map_err(|_| {
                ChainbaseError::InternalError(format!("failed to write transaction"))
            })?;
            let mut range = tx.range(&self.partition, self.range.clone()).rev();
            let prev = range.next();
            prev
        };

        if prev.is_some() {
            let (key, value) = prev
                .unwrap()
                .map_err(|e| {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed to get previous element: {}", e),
                    ))
                })
                .map_err(|e| ChainbaseError::InternalError(e.to_string()))?;
            self.current_key = key.to_vec();
            self.current_value = value.to_vec();
            self.range = (Bound::Excluded(self.current_key.clone()), Bound::Unbounded);
            if let Ok(object) = self.get_object() {
                return Ok(Some(object));
            } else {
                return Err(ChainbaseError::InternalError(format!(
                    "failed to get object from previous element"
                )));
            }
        }

        Ok(None)
    }

    pub fn next(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let next = {
            let tx = self.undo_session.tx();
            let mut tx = tx.write().map_err(|_| {
                ChainbaseError::InternalError(format!("failed to write transaction"))
            })?;
            let mut range = tx.range(&self.partition, self.range.clone());
            let next = range.next();
            next
        };

        if next.is_some() {
            let (key, value) = next
                .unwrap()
                .map_err(|e| {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed to get next element: {}", e),
                    ))
                })
                .map_err(|e| ChainbaseError::InternalError(e.to_string()))?;
            self.current_key = key.to_vec();
            self.current_value = value.to_vec();
            self.range = (Bound::Excluded(self.current_key.clone()), Bound::Unbounded);
            if let Ok(object) = self.get_object() {
                return Ok(Some(object));
            } else {
                return Err(ChainbaseError::InternalError(format!(
                    "failed to get object from next element"
                )));
            }
        }

        Ok(None)
    }

    pub fn get_object(&mut self) -> Result<S::Object, ChainbaseError> {
        return self
            .undo_session
            .get::<S::Object>(S::Object::primary_key_from_bytes(
                self.current_value.as_slice(),
            )?);
    }
}

pub struct IndexIterator<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    undo_session: UndoSession,
    partition: TransactionalPartitionHandle,
    current_key: Vec<u8>,
    current_value: Vec<u8>,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<C, S> IndexIterator<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    pub fn next(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let next = {
            let tx = self.undo_session.tx();
            let mut tx = tx.write().map_err(|_| {
                ChainbaseError::InternalError(format!("failed to write transaction"))
            })?;
            let range = (
                std::ops::Bound::Excluded(self.current_key.clone()),
                std::ops::Bound::Unbounded,
            );
            let mut range = tx.range(&self.partition, range);
            let next = range.next();
            next
        };

        if next.is_some() {
            let (key, value) = next
                .unwrap()
                .map_err(|e| {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed to get next element: {}", e),
                    ))
                })
                .map_err(|e| ChainbaseError::InternalError(e.to_string()))?;
            self.current_key = key.to_vec();
            self.current_value = value.to_vec();
            if let Ok(object) = self.get_object() {
                return Ok(Some(object));
            } else {
                return Err(ChainbaseError::InternalError(format!(
                    "failed to get object from next element"
                )));
            }
        }

        Ok(None)
    }

    pub fn previous(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let prev = {
            let tx = self.undo_session.tx();
            let mut tx = tx.write().map_err(|_| {
                ChainbaseError::InternalError(format!("failed to write transaction"))
            })?;
            let mut range = tx.range(&self.partition, ..self.current_key.clone()).rev();
            let prev = range.next();
            prev
        };

        if prev.is_some() {
            let (key, value) = prev
                .unwrap()
                .map_err(|e| {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed to get previous element: {}", e),
                    ))
                })
                .map_err(|e| ChainbaseError::InternalError(e.to_string()))?;
            self.current_key = key.to_vec();
            self.current_value = value.to_vec();
            if let Ok(object) = self.get_object() {
                return Ok(Some(object));
            } else {
                return Err(ChainbaseError::InternalError(format!(
                    "failed to get object from previous element"
                )));
            }
        }

        Ok(None)
    }

    pub fn get_object(&mut self) -> Result<S::Object, ChainbaseError> {
        return self
            .undo_session
            .get::<S::Object>(S::Object::primary_key_from_bytes(
                self.current_value.as_slice(),
            )?);
    }
}

impl<C, S> PartialEq for IndexIterator<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    fn eq(&self, other: &Self) -> bool {
        self.current_key == other.current_key
    }
}
