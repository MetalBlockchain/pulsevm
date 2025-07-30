use std::{cell::RefCell, rc::Rc};

use fjall::{ReadTransaction, TransactionalKeyspace};

use crate::{ChainbaseError, ChainbaseObject, SecondaryIndex, ro_index::ReadOnlyIndex};

#[derive(Clone)]
pub struct Session {
    tx: Rc<RefCell<ReadTransaction>>,
    keyspace: TransactionalKeyspace,
}

impl Session {
    pub fn new(keyspace: &TransactionalKeyspace) -> Result<Self, ChainbaseError> {
        Ok(Self {
            tx: Rc::new(RefCell::new(keyspace.read_tx())),
            keyspace: keyspace.clone(),
        })
    }

    pub fn tx(&self) -> Rc<RefCell<ReadTransaction>> {
        self.tx.clone()
    }

    pub fn keyspace(&self) -> TransactionalKeyspace {
        self.keyspace.clone()
    }

    #[must_use]
    pub fn exists<T: ChainbaseObject>(
        &mut self,
        key: T::PrimaryKey,
    ) -> Result<bool, ChainbaseError> {
        let partition = self
            .keyspace
            .open_partition(T::table_name(), Default::default())
            .map_err(|_| ChainbaseError::InternalError(format!("failed to open partition")))?;
        let tx = self.tx.borrow();
        let res = tx
            .contains_key(&partition, T::primary_key_to_bytes(key))
            .map_err(|_| ChainbaseError::InternalError(format!("failed to check existence")))?;
        Ok(res)
    }

    #[must_use]
    pub fn find<T: ChainbaseObject>(
        &mut self,
        key: T::PrimaryKey,
    ) -> Result<Option<T>, ChainbaseError> {
        let partition = self
            .keyspace
            .open_partition(T::table_name(), Default::default())
            .map_err(|_| ChainbaseError::InternalError(format!("failed to open partition")))?;
        let tx = self.tx.borrow();
        let serialized = tx
            .get(&partition, T::primary_key_to_bytes(key))
            .map_err(|_| ChainbaseError::InternalError(format!("failed to get object")))?;
        if serialized.is_none() {
            return Ok(None);
        }
        let mut pos = 0 as usize;
        let object: T = T::read(&serialized.unwrap(), &mut pos).expect("failed to read object");
        Ok(Some(object))
    }

    #[must_use]
    pub fn get<T: ChainbaseObject>(&mut self, key: T::PrimaryKey) -> Result<T, ChainbaseError> {
        let found = self.find::<T>(key)?;
        if found.is_none() {
            return Err(ChainbaseError::NotFound);
        }
        let object = found.unwrap();
        Ok(object)
    }

    #[must_use]
    pub fn find_by_secondary<T: ChainbaseObject, S: SecondaryIndex<T>>(
        &mut self,
        key: S::Key,
    ) -> Result<Option<T>, ChainbaseError> {
        let partition = self
            .keyspace
            .open_partition(S::index_name(), Default::default())
            .map_err(|_| ChainbaseError::InternalError(format!("failed to open partition")))?;
        let tx = self.tx.borrow();
        let secondary_key = tx
            .get(&partition, S::secondary_key_as_bytes(key))
            .map_err(|_| ChainbaseError::InternalError(format!("failed to get secondary key")))?;
        if secondary_key.is_none() {
            return Ok(None);
        }
        let partition = self
            .keyspace
            .open_partition(T::table_name(), Default::default())
            .map_err(|_| ChainbaseError::InternalError(format!("failed to open partition")))?;
        let serialized = tx.get(&partition, secondary_key.unwrap()).map_err(|_| {
            ChainbaseError::InternalError(format!("failed to get object by secondary key"))
        })?;
        if serialized.is_none() {
            return Ok(None);
        }
        let mut pos = 0 as usize;
        let object: T = T::read(&serialized.unwrap(), &mut pos).expect("failed to read object");
        Ok(Some(object))
    }

    pub fn get_index<C, S>(&self) -> ReadOnlyIndex<C, S>
    where
        C: ChainbaseObject,
        S: SecondaryIndex<C>,
    {
        ReadOnlyIndex::<C, S>::new(self.clone(), self.keyspace.clone())
    }
}
