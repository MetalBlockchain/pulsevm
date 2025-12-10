use std::ops::Bound;

use pulsevm_serialization::{Read, Write};

use crate::{
    ChainbaseError, ChainbaseObject, SecondaryIndex, Session, UndoSession, session::ReadOnlySession,
};

#[derive(Clone)]
pub struct ReadOnlyIndex<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    session: &'a ReadOnlySession<'a>,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<'a, C, S> ReadOnlyIndex<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    pub fn new(session: &'a ReadOnlySession<'a>) -> Self {
        ReadOnlyIndex::<'a, C, S> {
            session,
            __phantom: std::marker::PhantomData,
        }
    }

    pub fn iterator_to(
        &self,
        object: &S::Object,
    ) -> Result<ReadOnlyIndexIterator<'a, C, S>, ChainbaseError> {
        Ok(ReadOnlyIndexIterator::<C, S> {
            session: self.session,
            current_key: S::secondary_key(object).into(),
            current_value: object.primary_key().into(),
            __phantom: std::marker::PhantomData,
        })
    }

    #[inline]
    pub fn range(
        &self,
        lower_bound: impl Write,
        upper_bound: impl Write,
    ) -> Result<ReadOnlyRangeIterator<'a, C, S>, ChainbaseError> {
        let lower_bound_bytes = lower_bound.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;
        let upper_bound_bytes = upper_bound.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;

        Ok(ReadOnlyRangeIterator::<C, S> {
            session: self.session,
            range: (
                Bound::Included(lower_bound_bytes.clone().into()),
                Bound::Excluded(upper_bound_bytes.into()),
            ),
            current_key: lower_bound_bytes.into(),
            current_value: Vec::new(),
            __phantom: std::marker::PhantomData,
        })
    }

    pub fn lower_bound(
        &mut self,
        key: impl Write,
    ) -> Result<ReadOnlyRangeIterator<'a, C, S>, ChainbaseError> {
        let key_bytes = key.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;

        Ok(ReadOnlyRangeIterator::<'a, C, S> {
            session: self.session,
            range: (Bound::Included(key_bytes.clone()), Bound::Unbounded),
            current_key: key_bytes,
            current_value: Vec::new(),
            __phantom: std::marker::PhantomData,
        })
    }

    pub fn upper_bound(
        &mut self,
        key: impl Write,
    ) -> Result<ReadOnlyRangeIterator<'a, C, S>, ChainbaseError> {
        let key_bytes = key.pack().map_err(|e| {
            ChainbaseError::InternalError(format!("failed to serialize key: {}", e))
        })?;

        Ok(ReadOnlyRangeIterator::<'a, C, S> {
            session: self.session,
            range: (Bound::Excluded(key_bytes.clone()), Bound::Unbounded),
            current_key: key_bytes,
            current_value: Vec::new(),
            __phantom: std::marker::PhantomData,
        })
    }
}

pub struct ReadOnlyRangeIterator<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    session: &'a ReadOnlySession<'a>,
    range: (Bound<Vec<u8>>, Bound<Vec<u8>>),
    current_key: Vec<u8>,
    current_value: Vec<u8>,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<'a, C, S> ReadOnlyRangeIterator<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    #[inline]
    pub fn new(session: &'a ReadOnlySession<'a>, range: (Bound<Vec<u8>>, Bound<Vec<u8>>)) -> Self {
        ReadOnlyRangeIterator::<'a, C, S> {
            session,
            range,
            current_key: Vec::new(),
            current_value: Vec::new(),
            __phantom: std::marker::PhantomData,
        }
    }

    #[inline]
    pub fn previous(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let prev = {
            let db = self.session.get_database(S::index_name())?;
            let res = db
                .get_lower_than(&self.session.tx, &self.current_key)
                .map_err(|e| {
                    ChainbaseError::InternalError(format!("failed to get previous element: {}", e))
                })?;
            res
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
            let db = self.session.get_database(S::index_name())?;
            let res = db
                .get_greater_than(&self.session.tx, &self.current_key)
                .map_err(|e| {
                    ChainbaseError::InternalError(format!("failed to get next element: {}", e))
                })?;
            res
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
            .session
            .get::<S::Object>(S::Object::primary_key_from_bytes(
                self.current_value.as_ref(),
            )?);
    }
}

pub struct ReadOnlyIndexIterator<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    session: &'a ReadOnlySession<'a>,
    current_key: Vec<u8>,
    current_value: Vec<u8>,
    __phantom: std::marker::PhantomData<(C, S)>,
}

impl<'a, C, S> ReadOnlyIndexIterator<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    #[inline]
    pub fn next(&mut self) -> Result<Option<S::Object>, ChainbaseError> {
        let next = {
            let db = self.session.get_database(S::index_name())?;
            let res = db
                .get_greater_than(&self.session.tx, &self.current_key)
                .map_err(|e| {
                    ChainbaseError::InternalError(format!("failed to get next element: {}", e))
                })?;
            res
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
            let db = self.session.get_database(S::index_name())?;
            let res = db
                .get_lower_than(&self.session.tx, &self.current_key)
                .map_err(|e| {
                    ChainbaseError::InternalError(format!("failed to get previous element: {}", e))
                })?;
            res
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
            .session
            .get::<S::Object>(S::Object::primary_key_from_bytes(
                self.current_value.as_ref(),
            )?);
    }
}

impl<'a, C, S> PartialEq for ReadOnlyIndexIterator<'a, C, S>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    fn eq(&self, other: &Self) -> bool {
        self.current_key == other.current_key
    }
}
