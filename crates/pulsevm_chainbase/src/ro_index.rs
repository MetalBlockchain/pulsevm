use std::ops::Bound;

use fjall::{Slice, TransactionalKeyspace, TransactionalPartitionHandle};
use pulsevm_serialization::Write;

use crate::{ChainbaseError, ChainbaseObject, SecondaryIndex, Session};

#[derive(Clone)]
pub struct ReadOnlyIndex<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    session: Session,
    keyspace: TransactionalKeyspace,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<C, S> ReadOnlyIndex<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    #[inline]
    pub fn new(session: Session, keyspace: TransactionalKeyspace) -> Self {
        ReadOnlyIndex::<C, S> {
            session,
            keyspace,
            __phantom: std::marker::PhantomData,
        }
    }

    #[inline]
    pub fn iterator_to(
        &mut self,
        object: &S::Object,
    ) -> Result<ReadOnlyIndexIterator<C, S>, ChainbaseError> {
        Ok(ReadOnlyIndexIterator::<C, S> {
            session: self.session.clone(),
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

    #[inline]
    pub fn range(
        &mut self,
        lower_bound: impl Write,
        upper_bound: impl Write,
    ) -> Result<ReadOnlyRangeIterator<C, S>, ChainbaseError> {
        let lower_bound_bytes = lower_bound.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;
        let upper_bound_bytes = upper_bound.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;

        Ok(ReadOnlyRangeIterator::<C, S> {
            session: self.session.clone(),
            partition: self
                .keyspace
                .clone()
                .open_partition(S::index_name(), Default::default())
                .map_err(|_| ChainbaseError::InternalError(format!("failed to open partition")))?,
            range: (
                Bound::Included(lower_bound_bytes.clone().into()),
                Bound::Excluded(upper_bound_bytes.into()),
            ),
            current_key: lower_bound_bytes.into(),
            current_value: Slice::new(&[]),
            __phantom: std::marker::PhantomData,
        })
    }

    #[inline]
    pub fn lower_bound(
        &mut self,
        key: impl Write,
    ) -> Result<ReadOnlyRangeIterator<C, S>, ChainbaseError> {
        let key_bytes = key.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;

        Ok(ReadOnlyRangeIterator::<C, S> {
            session: self.session.clone(),
            partition: self
                .keyspace
                .clone()
                .open_partition(S::index_name(), Default::default())
                .map_err(|_| ChainbaseError::InternalError(format!("failed to open partition")))?,
            range: (Bound::Included(key_bytes.clone().into()), Bound::Unbounded),
            current_key: key_bytes.into(),
            current_value: Slice::new(&[]),
            __phantom: std::marker::PhantomData,
        })
    }

    #[inline]
    pub fn upper_bound(
        &mut self,
        key: impl Write,
    ) -> Result<ReadOnlyRangeIterator<C, S>, ChainbaseError> {
        let key_bytes = key.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;

        Ok(ReadOnlyRangeIterator::<C, S> {
            session: self.session.clone(),
            partition: self
                .keyspace
                .clone()
                .open_partition(S::index_name(), Default::default())
                .map_err(|_| ChainbaseError::InternalError(format!("failed to open partition")))?,
            range: (Bound::Excluded(key_bytes.clone().into()), Bound::Unbounded),
            current_key: key_bytes.into(),
            current_value: Slice::new(&[]),
            __phantom: std::marker::PhantomData,
        })
    }
}

pub struct ReadOnlyRangeIterator<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    session: Session,
    partition: TransactionalPartitionHandle,
    range: (Bound<Slice>, Bound<Slice>),
    current_key: Slice,
    current_value: Slice,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<C, S> ReadOnlyRangeIterator<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    #[inline]
    pub fn new(
        session: Session,
        partition: TransactionalPartitionHandle,
        range: (Bound<Slice>, Bound<Slice>),
    ) -> Self {
        ReadOnlyRangeIterator::<C, S> {
            session,
            partition,
            range,
            current_key: Slice::new(&[]),
            current_value: Slice::new(&[]),
            __phantom: std::marker::PhantomData,
        }
    }

    #[inline]
    pub fn previous(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let prev = {
            let tx = self.session.tx();
            let tx = tx.read().map_err(|_| {
                ChainbaseError::InternalError(format!("failed to read transaction"))
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
            self.current_key = key;
            self.current_value = value;
            self.range = (
                Bound::Excluded(self.current_key.clone()),
                self.range.1.clone(),
            );
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

    #[inline]
    pub fn next(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let next = {
            let tx = self.session.tx();
            let tx = tx.read().map_err(|_| {
                ChainbaseError::InternalError(format!("failed to read transaction"))
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
            self.current_key = key;
            self.current_value = value;
            self.range = (
                Bound::Excluded(self.current_key.clone()),
                self.range.1.clone(),
            );
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

    #[inline]
    pub fn get_object(&mut self) -> Result<S::Object, ChainbaseError> {
        return self
            .session
            .get::<S::Object>(S::Object::primary_key_from_bytes(
                self.current_value.as_ref(),
            )?);
    }
}

pub struct ReadOnlyIndexIterator<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    session: Session,
    partition: TransactionalPartitionHandle,
    current_key: Vec<u8>,
    current_value: Vec<u8>,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<C, S> ReadOnlyIndexIterator<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    #[inline]
    pub fn next(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let next = {
            let tx = self.session.tx();
            let tx = tx.read().map_err(|_| {
                ChainbaseError::InternalError(format!("failed to read transaction"))
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

    #[inline]
    pub fn previous(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let prev = {
            let tx = self.session.tx();
            let tx = tx.read().map_err(|_| {
                ChainbaseError::InternalError(format!("failed to read transaction"))
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

    #[inline]
    pub fn get_object(&mut self) -> Result<S::Object, ChainbaseError> {
        return self
            .session
            .get::<S::Object>(S::Object::primary_key_from_bytes(
                self.current_value.as_slice(),
            )?);
    }
}

impl<C, S> PartialEq for ReadOnlyIndexIterator<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.current_key == other.current_key
    }
}
