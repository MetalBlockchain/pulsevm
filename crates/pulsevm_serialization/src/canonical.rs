use std::{
    collections::{
        BTreeMap,
        BTreeSet,
    },
    ops::{
        Deref,
        DerefMut,
    },
};

use crate::{
    NumBytes,
    Read,
    ReadError,
    Write,
    WriteError,
};

/// A protocol collection whose binary representation is sorted by key.
///
/// Use this only for Antelope `flat_map`-style fields. Wire-order fields must
/// remain vectors: converting one to this type deliberately discards insertion
/// order and duplicate keys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CanonicalMap<K, V>(BTreeMap<K, V>);

impl<K: Ord, V> CanonicalMap<K, V> {
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn into_inner(self) -> BTreeMap<K, V> {
        self.0
    }
}

impl<K, V> Deref for CanonicalMap<K, V> {
    type Target = BTreeMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> DerefMut for CanonicalMap<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K: Ord, V> From<BTreeMap<K, V>> for CanonicalMap<K, V> {
    fn from(value: BTreeMap<K, V>) -> Self {
        Self(value)
    }
}

impl<K: Ord, V> FromIterator<(K, V)> for CanonicalMap<K, V> {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<K, V> IntoIterator for CanonicalMap<K, V> {
    type Item = (K, V);
    type IntoIter = std::collections::btree_map::IntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, K, V> IntoIterator for &'a CanonicalMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = std::collections::btree_map::Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<K: NumBytes, V: NumBytes> NumBytes for CanonicalMap<K, V> {
    fn num_bytes(&self) -> usize {
        self.len().num_bytes()
            + self
                .iter()
                .map(|(key, value)| key.num_bytes() + value.num_bytes())
                .sum::<usize>()
    }
}

impl<K: Read + Ord, V: Read> Read for CanonicalMap<K, V> {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let len = usize::read(bytes, pos)?;
        let mut map = BTreeMap::new();
        for _ in 0..len {
            map.insert(K::read(bytes, pos)?, V::read(bytes, pos)?);
        }
        Ok(Self(map))
    }
}

impl<K: Write, V: Write> Write for CanonicalMap<K, V> {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.len().write(bytes, pos)?;
        for (key, value) in self.iter() {
            key.write(bytes, pos)?;
            value.write(bytes, pos)?;
        }
        Ok(())
    }
}

/// A protocol collection whose binary representation is sorted by value.
///
/// This models Antelope `flat_set` inputs. It must never be used for fields
/// whose source order or duplicates participate in a digest.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CanonicalSet<T>(BTreeSet<T>);

impl<T: Ord> CanonicalSet<T> {
    pub const fn new() -> Self {
        Self(BTreeSet::new())
    }

    pub fn into_inner(self) -> BTreeSet<T> {
        self.0
    }
}

impl<T> Deref for CanonicalSet<T> {
    type Target = BTreeSet<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for CanonicalSet<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Ord> From<BTreeSet<T>> for CanonicalSet<T> {
    fn from(value: BTreeSet<T>) -> Self {
        Self(value)
    }
}

impl<T: Ord> FromIterator<T> for CanonicalSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<T> IntoIterator for CanonicalSet<T> {
    type Item = T;
    type IntoIter = std::collections::btree_set::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a CanonicalSet<T> {
    type Item = &'a T;
    type IntoIter = std::collections::btree_set::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: NumBytes> NumBytes for CanonicalSet<T> {
    fn num_bytes(&self) -> usize {
        self.len().num_bytes() + self.iter().map(NumBytes::num_bytes).sum::<usize>()
    }
}

impl<T: Read + Ord> Read for CanonicalSet<T> {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let len = usize::read(bytes, pos)?;
        let mut set = BTreeSet::new();
        for _ in 0..len {
            set.insert(T::read(bytes, pos)?);
        }
        Ok(Self(set))
    }
}

impl<T: Write> Write for CanonicalSet<T> {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.len().write(bytes, pos)?;
        for value in self.iter() {
            value.write(bytes, pos)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_map_bytes_do_not_depend_on_insertion_order() {
        let left = CanonicalMap::from_iter([(2_u64, 20_u64), (1, 10)]);
        let right = CanonicalMap::from_iter([(1_u64, 10_u64), (2, 20)]);
        assert_eq!(left.pack().unwrap(), right.pack().unwrap());
    }

    #[test]
    fn canonical_set_bytes_do_not_depend_on_insertion_order() {
        let left = CanonicalSet::from_iter([3_u64, 1, 2]);
        let right = CanonicalSet::from_iter([1_u64, 2, 3]);
        assert_eq!(left.pack().unwrap(), right.pack().unwrap());
    }
}
