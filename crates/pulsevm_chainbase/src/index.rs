use std::ops::Bound;

use pulsevm_serialization::Write;

use crate::{ChainbaseError, ChainbaseObject, SecondaryIndex, Session, UndoSession};

#[derive(Clone)]
pub struct Index<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    undo_session: UndoSession<'a>,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<'a, C, S> Index<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    pub fn new(undo_session: UndoSession<'a>) -> Self {
        Index::<'a, C, S> {
            undo_session,
            __phantom: std::marker::PhantomData,
        }
    }

    pub fn iterator_to(
        &self,
        object: &S::Object,
    ) -> Result<IndexIterator<'a, C, S>, ChainbaseError> {
        Ok(IndexIterator::<C, S> {
            undo_session: self.undo_session.clone(),
            current_key: S::secondary_key(object).into(),
            current_value: object.primary_key().into(),
            __phantom: std::marker::PhantomData,
        })
    }

    pub fn lower_bound(
        &mut self,
        key: impl Write,
    ) -> Result<RangeIterator<'a, C, S>, ChainbaseError> {
        let key_bytes = key.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;

        Ok(RangeIterator::<'a, C, S> {
            undo_session: self.undo_session.clone(),
            range: (Bound::Included(key_bytes.clone()), Bound::Unbounded),
            current_key: key_bytes,
            current_value: Vec::new(),
            __phantom: std::marker::PhantomData,
        })
    }

    pub fn upper_bound(
        &mut self,
        key: impl Write,
    ) -> Result<RangeIterator<'a, C, S>, ChainbaseError> {
        let key_bytes = key.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;

        Ok(RangeIterator::<'a, C, S> {
            undo_session: self.undo_session.clone(),
            range: (Bound::Excluded(key_bytes.clone()), Bound::Unbounded),
            current_key: key_bytes,
            current_value: Vec::new(),
            __phantom: std::marker::PhantomData,
        })
    }
}

pub struct RangeIterator<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    undo_session: UndoSession<'a>,
    range: (Bound<Vec<u8>>, Bound<Vec<u8>>),
    current_key: Vec<u8>,
    current_value: Vec<u8>,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<'a, C, S> RangeIterator<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    #[inline]
    pub fn new(undo_session: UndoSession<'a>, range: (Bound<Vec<u8>>, Bound<Vec<u8>>)) -> Self {
        RangeIterator::<'a, C, S> {
            undo_session,
            range,
            current_key: Vec::new(),
            current_value: Vec::new(),
            __phantom: std::marker::PhantomData,
        }
    }

    #[inline]
    pub fn previous(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let prev = {
            let db = self.undo_session.get_database(S::index_name())?;
            let tx =
                self.undo_session.tx.read().map_err(|e| {
                    ChainbaseError::InternalError(format!("failed to lock tx: {}", e))
                })?;
            let res = db.get_lower_than(&tx, &self.current_key).map_err(|e| {
                ChainbaseError::InternalError(format!("failed to get previous element: {}", e))
            })?;
            match res {
                Some((key, value)) => Some((key.to_vec(), value.to_vec())),
                _ => None,
            }
        };

        if let Some((key, value)) = prev {
            self.current_key = key.to_vec();
            self.current_value = value.to_vec();
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
            let db = self.undo_session.get_database(S::index_name())?;
            let tx =
                self.undo_session.tx.read().map_err(|e| {
                    ChainbaseError::InternalError(format!("failed to lock tx: {}", e))
                })?;
            let res = db.get_greater_than(&tx, &self.current_key).map_err(|e| {
                ChainbaseError::InternalError(format!("failed to get next element: {}", e))
            })?;
            match res {
                Some((key, value)) => Some((key.to_vec(), value.to_vec())),
                _ => None,
            }
        };

        if let Some((key, value)) = next {
            self.current_key = key.to_vec();
            self.current_value = value.to_vec();
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
    pub fn get_object(&self) -> Result<S::Object, ChainbaseError> {
        return self
            .undo_session
            .get::<S::Object>(S::Object::primary_key_from_bytes(
                self.current_value.as_ref(),
            )?);
    }
}

pub struct IndexIterator<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    undo_session: UndoSession<'a>,
    current_key: Vec<u8>,
    current_value: Vec<u8>,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<'a, C, S> IndexIterator<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    #[inline]
    pub fn next(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let next = {
            let db = self.undo_session.get_database(S::index_name())?;
            let tx =
                self.undo_session.tx.read().map_err(|e| {
                    ChainbaseError::InternalError(format!("failed to lock tx: {}", e))
                })?;
            let res = db.get_greater_than(&tx, &self.current_key).map_err(|e| {
                ChainbaseError::InternalError(format!("failed to get next element: {}", e))
            })?;
            match res {
                Some((key, value)) => Some((key.to_vec(), value.to_vec())),
                _ => None,
            }
        };

        if let Some((key, value)) = next {
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
            let db = self.undo_session.get_database(S::index_name())?;
            let tx =
                self.undo_session.tx.read().map_err(|e| {
                    ChainbaseError::InternalError(format!("failed to lock tx: {}", e))
                })?;
            let res = db.get_lower_than(&tx, &self.current_key).map_err(|e| {
                ChainbaseError::InternalError(format!("failed to get previous element: {}", e))
            })?;
            match res {
                Some((key, value)) => Some((key.to_vec(), value.to_vec())),
                _ => None,
            }
        };

        if let Some((key, value)) = prev {
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
            .undo_session
            .get::<S::Object>(S::Object::primary_key_from_bytes(
                self.current_value.as_ref(),
            )?);
    }
}

impl<'a, C, S> PartialEq for IndexIterator<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    fn eq(&self, other: &Self) -> bool {
        self.current_key == other.current_key
    }
}
