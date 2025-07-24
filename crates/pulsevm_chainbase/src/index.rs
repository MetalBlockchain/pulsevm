use std::ops::{Add, AddAssign, Deref};

use fjall::{PartitionHandle, Slice, TransactionalKeyspace, TransactionalPartitionHandle};

use crate::{ChainbaseObject, SecondaryIndex, UndoSession};

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
    ) -> Result<IndexIterator<C, S>, Box<dyn std::error::Error>> {
        Ok(IndexIterator::<C, S> {
            undo_session: self.undo_session.clone(),
            partition: self
                .keyspace
                .open_partition(S::index_name(), Default::default())?,
            current_key: S::secondary_key(object),
            current_value: object.primary_key(),
            __phantom: std::marker::PhantomData,
        })
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
    pub fn next(&mut self) -> Result<Option<S::Object>, Box<dyn std::error::Error>> {
        let next = {
            let tx = self.undo_session.tx();
            let mut tx = tx.borrow_mut();
            let mut range = tx.range(&self.partition, self.current_key.clone()..);
            let next = range.next();
            next
        };

        if next.is_some() {
            let (key, value) = next.unwrap().map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to get next element: {}", e),
                ))
            })?;
            self.current_key = key.to_vec();
            self.current_value = value.to_vec();
            if let Ok(object) = self.get_object() {
                return Ok(Some(object));
            } else {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "failed to get object from next element",
                )));
            }
        }

        Ok(None)
    }

    pub fn previous(&mut self) -> Result<Option<S::Object>, Box<dyn std::error::Error>> {
        let prev = {
            let tx = self.undo_session.tx();
            let mut tx = tx.borrow_mut();
            let mut range = tx.range(&self.partition, ..self.current_key.clone()).rev();
            let prev = range.next();
            prev
        };

        if prev.is_some() {
            let (key, value) = prev.unwrap().map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to get previous element: {}", e),
                ))
            })?;
            self.current_key = key.to_vec();
            self.current_value = value.to_vec();
            if let Ok(object) = self.get_object() {
                return Ok(Some(object));
            } else {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "failed to get object from previous element",
                )));
            }
        }

        Ok(None)
    }

    pub fn get_object(&mut self) -> Result<S::Object, Box<dyn std::error::Error>> {
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
