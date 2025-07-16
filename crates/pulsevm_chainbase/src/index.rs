use std::{cell::RefCell, error::Error, marker::PhantomData, rc::Rc, sync::Arc};

use fjall::{KvPair, Result as FjallResult, TransactionalPartitionHandle};

use crate::{ChainbaseObject, SecondaryIndex, UndoSession};

pub struct OrderedIndex<S, C>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    session: Rc<RefCell<UndoSession>>,
    _marker: std::marker::PhantomData<C>,
    _marker2: std::marker::PhantomData<S>,
}

impl<S, C> OrderedIndex<S, C>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    pub fn new(session: Rc<RefCell<UndoSession>>) -> Self {
        OrderedIndex::<S, C> {
            session,
            _marker: PhantomData,
            _marker2: PhantomData,
        }
    }

    pub fn equal_range(
        &self,
        lower_bound: S::Key,
        upper_bound: S::Key,
    ) -> Result<RangeIterator<S, C>, Box<dyn Error>> {
        Ok(RangeIterator::new(
            self.session.clone(),
            lower_bound,
            upper_bound,
        )?)
    }
}

pub struct RangeIterator<S, C>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    partition: TransactionalPartitionHandle,
    inner_iterator: Option<Box<dyn DoubleEndedIterator<Item = FjallResult<KvPair>>>>,
    session: Rc<RefCell<UndoSession>>,
    lower_bound: S::Key,
    upper_bound: S::Key,
}

impl<'a, S, C> RangeIterator<S, C>
where
    C: ChainbaseObject,
    S: SecondaryIndex<C>,
{
    pub fn new(
        session: Rc<RefCell<UndoSession>>,
        lower_bound: S::Key,
        upper_bound: S::Key,
    ) -> Result<Self, Box<dyn Error>> {
        let partition = session
            .borrow()
            .keyspace
            .open_partition(S::index_name(), Default::default())?;
        Ok(RangeIterator::<S, C> {
            partition: partition,
            inner_iterator: None,
            session: session,
            lower_bound,
            upper_bound,
        })
    }

    /* pub fn next(&mut self) -> Result<Option<C::PrimaryKey>, Box<dyn Error>> {
        if self.inner_iterator.is_none() {
            let lower_bound_bytes = S::secondary_key_as_bytes(self.lower_bound.clone());
            let upper_bound_bytes = S::secondary_key_as_bytes(self.upper_bound.clone());
            let mut session = self.session.borrow_mut();
            let iter = session
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
    } */
}
