use std::ops::Bound;

use fjall::{Slice, TransactionalKeyspace, TransactionalPartitionHandle};
use pulsevm_serialization::Write;

use crate::{ChainbaseError, ChainbaseObject, SecondaryIndex, UndoSession};

#[derive(Clone)]
pub struct Index<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    undo_session: UndoSession,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<C, S> Index<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    pub fn new(undo_session: UndoSession) -> Self {
        Index::<C, S> {
            undo_session,
            __phantom: std::marker::PhantomData,
        }
    }

    pub fn iterator_to(
        &mut self,
        object: &S::Object,
    ) -> Result<RangeIterator<C, S>, ChainbaseError> {
        Ok(RangeIterator::<C, S> {
            undo_session: self.undo_session.clone(),
            range: (Bound::Unbounded, Bound::Unbounded),
            current_key: S::secondary_key(object).into(),
            current_value: object.primary_key().into(),
            __phantom: std::marker::PhantomData,
        })
    }

    pub fn lower_bound(&mut self, key: impl Write) -> Result<RangeIterator<C, S>, ChainbaseError> {
        let key_bytes = key.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;
        let current_key = Slice::new(&key_bytes);

        Ok(RangeIterator::<C, S> {
            undo_session: self.undo_session.clone(),
            range: (Bound::Included(current_key.clone()), Bound::Unbounded),
            current_key: current_key,
            current_value: Slice::new(&[]),
            __phantom: std::marker::PhantomData,
        })
    }

    pub fn upper_bound(&mut self, key: impl Write) -> Result<RangeIterator<C, S>, ChainbaseError> {
        let key_bytes = key.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;
        let current_key = Slice::new(&key_bytes);

        Ok(RangeIterator::<C, S> {
            undo_session: self.undo_session.clone(),
            range: (Bound::Excluded(current_key.clone()), Bound::Unbounded),
            current_key: current_key,
            current_value: Slice::new(&[]),
            __phantom: std::marker::PhantomData,
        })
    }

    #[inline]
    pub fn range(
        &mut self,
        lower_bound: impl Write,
        upper_bound: impl Write,
    ) -> Result<RangeIterator<C, S>, ChainbaseError> {
        let lower_bound_bytes = lower_bound.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;
        let upper_bound_bytes = upper_bound.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;

        Ok(RangeIterator::<C, S> {
            undo_session: self.undo_session.clone(),
            range: (
                Bound::Included(lower_bound_bytes.clone().into()),
                Bound::Excluded(upper_bound_bytes.into()),
            ),
            current_key: lower_bound_bytes.into(),
            current_value: Slice::new(&[]),
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
    range: (Bound<Slice>, Bound<Slice>),
    current_key: Slice,
    current_value: Slice,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<C, S> RangeIterator<C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    #[inline]
    pub fn new(
        undo_session: UndoSession,
        range: (Bound<Slice>, Bound<Slice>),
    ) -> Self {
        RangeIterator::<C, S> {
            undo_session,
            range,
            current_key: Slice::new(&[]),
            current_value: Slice::new(&[]),
            __phantom: std::marker::PhantomData,
        }
    }

    #[inline]
    pub fn previous(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let next = self.undo_session.previous_key(S::index_name(), Some(self.current_key.to_vec()))?;

        match next {
            Some(next_key_bytes) => {
                self.current_key = Slice::new(&next_key_bytes);
                let object = self.get_object()?;
                Ok(Some(object))
            }
            None => Ok(None),
        }
    }

    #[inline]
    pub fn next(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let next = self.undo_session.next_key(S::index_name(), Some(self.current_key.to_vec()))?;

        match next {
            Some(next_key_bytes) => {
                self.current_key = Slice::new(&next_key_bytes);
                let object = self.get_object()?;
                Ok(Some(object))
            }
            None => Ok(None),
        }
    }

    #[inline]
    pub fn get_object(&mut self) -> Result<S::Object, ChainbaseError> {
        return self
            .undo_session
            .get::<S::Object>(S::Object::primary_key_from_bytes(
                self.current_value.as_ref(),
            )?);
    }
}