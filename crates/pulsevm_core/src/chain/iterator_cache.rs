use std::{collections::HashMap, hash::Hash};

use crate::chain::{error::ChainError, table::Table, utils::pulse_assert};

pub struct IteratorCache<T>
where
    T: Clone + Eq + Hash,
{
    table_cache: HashMap<u64, (Table, i32)>,
    end_iterator_to_table: Vec<Table>,
    iterator_to_object: Vec<Option<T>>,
    object_to_iterator: HashMap<T, i32>,
}

impl<T> IteratorCache<T>
where
    T: Clone + Eq + Hash,
{
    pub fn new() -> Self {
        Self {
            table_cache: HashMap::with_capacity(20),
            end_iterator_to_table: Vec::with_capacity(20),
            iterator_to_object: Vec::with_capacity(20),
            object_to_iterator: HashMap::with_capacity(20),
        }
    }

    pub fn cache_table(&mut self, table: &Table) -> i32 {
        let itr = self.table_cache.get(&table.id);
        if let Some((_, index)) = itr {
            return *index;
        }

        let ei = self.index_to_end_iterator(self.end_iterator_to_table.len());
        self.end_iterator_to_table.push(table.clone());
        self.table_cache.insert(table.id, (table.clone(), ei));
        return ei;
    }

    pub fn get_table(&self, id: u64) -> Result<&Table, ChainError> {
        let itr = self.table_cache.get(&id).map(|(table, _)| table);
        if let Some(table) = itr {
            return Ok(table);
        }

        return Err(ChainError::InternalError(Some(format!(
            "an invariant was broken, table should be in cache"
        ))));
    }

    pub fn get_end_iterator_by_table_id(&self, id: u64) -> Result<i32, ChainError> {
        let itr = self.table_cache.get(&id).map(|(_, ei)| *ei);
        if let Some(ei) = itr {
            return Ok(ei);
        }

        return Err(ChainError::InternalError(Some(format!(
            "an invariant was broken, table should be in cache"
        ))));
    }

    pub fn find_table_by_end_iterator(&self, ei: i32) -> Result<Option<&Table>, ChainError> {
        pulse_assert(
            ei < -1,
            ChainError::InternalError(Some(format!("not an end iterator"))),
        )?;

        let index = self.end_iterator_to_index(ei);
        if index >= self.end_iterator_to_table.len() {
            return Ok(None);
        }

        return Ok(self.end_iterator_to_table.get(index));
    }

    pub fn get(&self, iterator: i32) -> Result<&T, ChainError> {
        pulse_assert(
            iterator != -1,
            ChainError::TransactionError(format!("invalid iterator")),
        )?;
        pulse_assert(
            iterator >= 0,
            ChainError::TransactionError(format!("dereference of end iterator")),
        )?;
        pulse_assert(
            (iterator as usize) < self.iterator_to_object.len(),
            ChainError::TransactionError(format!("iterator out of range")),
        )?;
        let result = self.iterator_to_object.get(iterator as usize).unwrap();
        pulse_assert(
            result.is_some(),
            ChainError::TransactionError(format!("dereference of deleted object")),
        )?;
        return Ok(result.as_ref().unwrap());
    }

    pub fn remove(&mut self, iterator: i32) -> Result<(), ChainError> {
        pulse_assert(
            iterator != -1,
            ChainError::TransactionError(format!("invalid iterator")),
        )?;
        pulse_assert(
            iterator >= 0,
            ChainError::TransactionError(format!("cannot call remove on end iterators")),
        )?;
        pulse_assert(
            (iterator as usize) < self.iterator_to_object.len(),
            ChainError::TransactionError(format!("iterator out of range")),
        )?;
        let result = self.iterator_to_object.get_mut(iterator as usize).unwrap();

        if result.is_some() {
            self.object_to_iterator.remove(result.as_ref().unwrap());
            *result = None;
        }

        return Ok(());
    }

    pub fn add(&mut self, object: &T) -> i32 {
        if let Some(iterator) = self.object_to_iterator.get(object) {
            return *iterator;
        }

        self.iterator_to_object.push(Some(object.clone()));
        self.object_to_iterator
            .insert(object.clone(), self.iterator_to_object.len() as i32 - 1);

        return self.iterator_to_object.len() as i32 - 1;
    }

    pub fn end_iterator_to_index(&self, ei: i32) -> usize {
        return (-ei - 2) as usize;
    }

    pub fn index_to_end_iterator(&self, index: usize) -> i32 {
        return -(index as i32 + 2);
    }
}

#[cfg(test)]
mod tests {
    use pulsevm_crypto::Bytes;
    use pulsevm_proc_macros::name;

    use crate::chain::table::KeyValue;

    use super::*;

    #[test]
    fn test_iterator_cache() {
        let mut cache = IteratorCache::<KeyValue>::new();
        let iter_1 = cache.add(&KeyValue::default());
        let iter_2 = cache.add(&KeyValue::default());
        let iter_3 = cache.add(&KeyValue::new(
            1,
            2,
            3,
            name!("glenn").into(),
            Bytes::default(),
        ));
        assert_eq!(iter_1, 0);
        assert_eq!(iter_2, 0);
        assert_eq!(iter_3, 1);
    }
}
