use std::{error::Error, marker::PhantomData, sync::Arc};

use fjall::{KvPair, Result as FjallResult, TransactionalPartitionHandle};

use crate::{ChainbaseObject, SecondaryIndex, UndoSession};

pub struct OrderedIndex<'a, S, C>
where
    C: ChainbaseObject<'a>,
    S: SecondaryIndex<'a, C>,
{
    session: &'a UndoSession<'a>,
    _marker: std::marker::PhantomData<C>,
    _marker2: std::marker::PhantomData<S>,
}

impl<'a, S, C> OrderedIndex<'a, S, C>
where
    C: ChainbaseObject<'a> + 'static,
    S: SecondaryIndex<'a, C> + 'static,
{
    pub fn new(session: &'static UndoSession<'static>) -> Self {
        OrderedIndex::<S, C> {
            session,
            _marker: PhantomData,
            _marker2: PhantomData,
        }
    }

    pub fn equal_range(
        &'a self,
        lower_bound: S::Key,
        upper_bound: S::Key,
    ) -> Result<RangeIterator<'a, S, C>, Box<dyn Error>> {
        Ok(RangeIterator::new(self.session, lower_bound, upper_bound)?)
    }
}

pub struct RangeIterator<'a, S, C>
where
    C: ChainbaseObject<'a>,
    S: SecondaryIndex<'a, C>,
{
    partition: TransactionalPartitionHandle,
    inner_iterator: Option<Box<dyn DoubleEndedIterator<Item = FjallResult<KvPair>> + 'a>>,
    session: &'a UndoSession<'a>,
    lower_bound: S::Key,
    upper_bound: S::Key,
}

impl<'a, S, C> RangeIterator<'a, S, C>
where
    C: ChainbaseObject<'a> + 'static,
    S: SecondaryIndex<'a, C> + 'static,
{
    pub fn new(
        session: &'a UndoSession,
        lower_bound: S::Key,
        upper_bound: S::Key,
    ) -> Result<Self, Box<dyn Error>> {
        let partition = session
            .keyspace
            .open_partition(S::index_name(), Default::default())?;
        Ok(RangeIterator::<'a, S, C> {
            partition: partition,
            inner_iterator: None,
            session: session,
            lower_bound,
            upper_bound,
        })
    }

    pub fn next(&'a mut self) -> Result<Option<C::PrimaryKey>, Box<dyn Error>> {
        if self.inner_iterator.is_none() {
            let lower_bound_bytes = S::secondary_key_as_bytes(self.lower_bound.clone());
            let upper_bound_bytes = S::secondary_key_as_bytes(self.upper_bound.clone());
            let iter = self
                .session
                .tx
                .range(&self.partition, lower_bound_bytes..=upper_bound_bytes);
            self.inner_iterator = Some(Box::new(iter));
        }

        let iterator = self.inner_iterator.as_mut().unwrap();
        let result = iterator.next();

        if result.is_some() {
            let (_, value) = result.unwrap()?;
            let key = C::primary_key_from_bytes(&value)?;
            return Ok(Some(key));
        }

        Ok(None)
    }
}
