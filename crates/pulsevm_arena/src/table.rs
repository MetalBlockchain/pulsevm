use std::any::TypeId;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ops::Bound;

use crate::object::{ArenaObject, BlobRef, IndexedBy, KeyIndex, ObjectId, SecondaryIndex};

/// Errors from table operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableError {
    NotFound { type_name: &'static str, id: i64 },
    UnknownKey { type_name: &'static str },
    UniquenessViolation {
        type_name: &'static str,
        index_name: &'static str,
    },
    IdChanged { type_name: &'static str },
    Revision(&'static str),
    Corrupted(&'static str),
}

/// One entry of the undo stack (chainbase `undo_index::undo_state`).
///
/// - a key is *new* if `id >= old_next_id`
/// - a key is *modified* if it is in `old_values` (the value it had when the
///   session started; oldest value wins on repeated modifies)
/// - a key is *removed* if it is in `removed_values`; if it is also in
///   `old_values`, undo restores the older value.
struct UndoState<T> {
    old_values: HashMap<i64, T>,
    removed_values: HashMap<i64, T>,
    old_next_id: i64,
    /// Blob-arena length when the session started; undo truncates back to it,
    /// dropping every blob appended during the session.
    old_blob_len: usize,
}

/// A table of `T` stored in an index-addressed arena: rows live in a
/// contiguous `Vec` where the slot number *is* the id (`by_id` built in),
/// removed rows leave a `None` tombstone, and ids are never reused unless the
/// insertion that produced them is undone. Ordered-unique secondary indices map
/// `key -> id`. The recreation of chainbase `undo_index`, single-threaded and
/// handing out references rather than clones.
pub struct Table<T: ArenaObject> {
    /// Indexed by id; `primary.len()` is the next id to assign.
    primary: Vec<Option<T>>,
    /// Append-only byte arena for variable-length fields, addressed by
    /// [`BlobRef`]. Grows within a session and is truncated back on undo.
    blobs: Vec<u8>,
    secondaries: Vec<Box<dyn SecondaryIndex<T>>>,
    tag_positions: HashMap<TypeId, usize>,
    undo_stack: VecDeque<UndoState<T>>,
    row_count: usize,
    revision: i64,
}

impl<T: ArenaObject> Default for Table<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: ArenaObject> Table<T> {
    pub fn new() -> Self {
        let secondaries = T::secondary_indices();
        let mut tag_positions = HashMap::with_capacity(secondaries.len());
        for (pos, index) in secondaries.iter().enumerate() {
            let previous = tag_positions.insert(index.tag(), pos);
            assert!(
                previous.is_none(),
                "duplicate secondary index tag {} for {}",
                index.index_name(),
                T::type_name()
            );
        }
        Table {
            primary: Vec::new(),
            blobs: Vec::new(),
            secondaries,
            tag_positions,
            undo_stack: VecDeque::new(),
            row_count: 0,
            revision: 0,
        }
    }

    /// Appends `bytes` to the blob arena and returns a [`BlobRef`] to them, for
    /// a variable-length field. Call during `create`/`modify`, then store the
    /// ref on the object. Empty input yields the default empty ref.
    pub fn alloc_blob(&mut self, bytes: &[u8]) -> BlobRef {
        if bytes.is_empty() {
            return BlobRef::default();
        }
        let off = self.blobs.len() as u32;
        self.blobs.extend_from_slice(bytes);
        BlobRef {
            off,
            len: bytes.len() as u32,
        }
    }

    /// Resolves a [`BlobRef`] to its bytes.
    pub fn blob(&self, r: BlobRef) -> &[u8] {
        let start = r.off as usize;
        &self.blobs[start..start + r.len as usize]
    }

    fn next_id(&self) -> i64 {
        self.primary.len() as i64
    }

    /// Inserts a new object constructed by `f`. The id is assigned by the table
    /// before `f` runs and cannot be changed by it. Strong exception safety: on
    /// a uniqueness conflict nothing is inserted.
    pub fn emplace<F: FnOnce(&mut T)>(&mut self, f: F) -> Result<&T, TableError> {
        let id = self.next_id();
        let mut obj = T::default();
        obj.set_id(ObjectId::new(id));
        f(&mut obj);
        obj.set_id(ObjectId::new(id)); // the constructor must not pick the id

        try_insert_all(&mut self.secondaries, &obj)?;
        // A fresh id needs no undo record; `old_next_id` marks it as new.
        self.primary.push(Some(obj));
        self.row_count += 1;
        Ok(self.primary[id as usize].as_ref().unwrap())
    }

    /// Applies `m` to the stored object. On a uniqueness violation the object is
    /// left unchanged and an error is returned.
    pub fn modify<F: FnOnce(&mut T)>(
        &mut self,
        id: ObjectId<T>,
        m: F,
    ) -> Result<(), TableError> {
        let raw = id.raw();
        let Some(current) = self.primary.get(raw as usize).and_then(|s| s.as_ref()) else {
            return Err(TableError::NotFound {
                type_name: T::type_name(),
                id: raw,
            });
        };
        let mut updated = *current;
        m(&mut updated);
        if updated.id() != id {
            return Err(TableError::IdChanged {
                type_name: T::type_name(),
            });
        }

        // Move each secondary entry to its new key; unchanged keys cost no tree
        // operation. Roll back on a conflict (the old keys cannot conflict, they
        // were just vacated).
        for i in 0..self.secondaries.len() {
            if !self.secondaries[i].replace(current, &updated) {
                let index_name = self.secondaries[i].index_name();
                for prior in &mut self.secondaries[..i] {
                    let restored = prior.replace(&updated, current);
                    debug_assert!(restored);
                }
                return Err(TableError::UniquenessViolation {
                    type_name: T::type_name(),
                    index_name,
                });
            }
        }
        let slot = self.primary[raw as usize].as_mut().unwrap();
        let old = std::mem::replace(slot, updated);
        self.on_modify(raw, old);
        Ok(())
    }

    /// Removes the object with the given id.
    pub fn remove(&mut self, id: ObjectId<T>) -> Result<(), TableError> {
        let raw = id.raw();
        let obj = self
            .primary
            .get_mut(raw as usize)
            .and_then(|s| s.take())
            .ok_or(TableError::NotFound {
                type_name: T::type_name(),
                id: raw,
            })?;
        self.row_count -= 1;
        for index in &mut self.secondaries {
            index.erase(&obj);
        }
        if let Some(state) = self.undo_stack.back_mut() {
            // An object created in this session leaves no trace when removed.
            if raw < state.old_next_id {
                state.removed_values.insert(raw, obj);
            }
        }
        Ok(())
    }

    pub fn find(&self, id: ObjectId<T>) -> Option<&T> {
        self.primary.get(id.raw() as usize).and_then(|s| s.as_ref())
    }

    pub fn get(&self, id: ObjectId<T>) -> Result<&T, TableError> {
        self.find(id).ok_or(TableError::NotFound {
            type_name: T::type_name(),
            id: id.raw(),
        })
    }

    /// Typed view of a secondary index (chainbase `indices().get<Tag>()`).
    /// Panics if `Tag` is not declared by [`ArenaObject::secondary_indices`].
    pub fn get_index<Tag: IndexedBy<T>>(&self) -> IndexView<'_, T, Tag> {
        let pos = *self.tag_positions.get(&TypeId::of::<Tag>()).unwrap_or_else(|| {
            panic!(
                "index {} is not declared by {}",
                std::any::type_name::<Tag>(),
                T::type_name()
            )
        });
        let index = self.secondaries[pos]
            .as_any()
            .downcast_ref::<KeyIndex<T, Tag>>()
            .expect("tag registered with mismatching key index type");
        IndexView {
            map: &index.map,
            primary: &self.primary,
        }
    }

    /// Iterates live objects in id order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &T> + '_ {
        self.primary.iter().filter_map(|s| s.as_ref())
    }

    pub fn len(&self) -> usize {
        self.row_count
    }

    pub fn is_empty(&self) -> bool {
        self.row_count == 0
    }

    // ----- undo machinery ---------------------------------------------------

    /// Pushes a new undo state; changes until the matching
    /// `undo`/`squash`/`commit` are tracked. Returns the new revision.
    pub fn start_undo_session(&mut self) -> i64 {
        self.undo_stack.push_back(UndoState {
            old_values: HashMap::new(),
            removed_values: HashMap::new(),
            old_next_id: self.next_id(),
            old_blob_len: self.blobs.len(),
        });
        self.revision += 1;
        self.revision
    }

    pub fn revision(&self) -> i64 {
        self.revision
    }

    pub fn set_revision(&mut self, revision: i64) -> Result<(), TableError> {
        if !self.undo_stack.is_empty() {
            return Err(TableError::Revision(
                "cannot set revision while there is an existing undo stack",
            ));
        }
        if revision < self.revision {
            return Err(TableError::Revision("revision cannot decrease"));
        }
        self.revision = revision;
        Ok(())
    }

    pub fn undo_stack_revision_range(&self) -> (i64, i64) {
        (self.revision - self.undo_stack.len() as i64, self.revision)
    }

    pub fn has_undo_session(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Reverts to the state at the top of the undo stack.
    pub fn undo(&mut self) {
        let Some(state) = self.undo_stack.pop_back() else {
            return;
        };
        let UndoState {
            mut old_values,
            removed_values,
            old_next_id,
            old_blob_len,
        } = state;
        // Drop every blob appended during the session; restored objects only
        // reference bytes from before it started.
        self.blobs.truncate(old_blob_len);

        // Erase everything created during the session (ids >= old_next_id) and
        // drop those slots.
        for id in old_next_id as usize..self.primary.len() {
            if let Some(obj) = &self.primary[id] {
                for index in &mut self.secondaries {
                    index.erase(obj);
                }
                self.row_count -= 1;
            }
        }
        self.primary.truncate(old_next_id as usize);

        // A key in both old_values and removed_values restores the older one.
        let mut removed_restore = Vec::with_capacity(removed_values.len());
        for (id, removed) in removed_values {
            debug_assert!(id < old_next_id);
            removed_restore.push(old_values.remove(&id).unwrap_or(removed));
        }

        // Erase the current secondary keys of every surviving modified object
        // before re-inserting any old value, so restores that trade keys never
        // collide transiently.
        let mut modified_restore = Vec::with_capacity(old_values.len());
        for (id, old) in old_values {
            let current = self.primary[id as usize]
                .as_ref()
                .expect("undo invariant: modified object is present");
            for index in &mut self.secondaries {
                index.erase(current);
            }
            modified_restore.push(old);
        }
        for obj in modified_restore.into_iter().chain(removed_restore) {
            let id = obj.id().raw();
            for index in &mut self.secondaries {
                let inserted = index.try_insert(&obj);
                debug_assert!(inserted, "undo restore broke a uniqueness invariant");
            }
            let was_absent = self.primary[id as usize].is_none();
            self.primary[id as usize] = Some(obj);
            if was_absent {
                self.row_count += 1;
            }
        }

        self.revision -= 1;
    }

    pub fn undo_all(&mut self) {
        while !self.undo_stack.is_empty() {
            self.undo();
        }
    }

    /// Combines the top two states on the undo stack.
    pub fn squash(&mut self) {
        let Some(top) = self.undo_stack.pop_back() else {
            return;
        };
        self.revision -= 1;
        let Some(previous) = self.undo_stack.back_mut() else {
            // Squashing the only session makes its changes permanent.
            return;
        };
        for (id, old) in top.old_values {
            if id < previous.old_next_id {
                previous.old_values.entry(id).or_insert(old);
            }
        }
        for (id, removed) in top.removed_values {
            if id < previous.old_next_id {
                previous.removed_values.insert(id, removed);
            }
        }
    }

    /// Discards all undo history at or before `revision`.
    pub fn commit(&mut self, revision: i64) {
        let revision = revision.min(self.revision);
        if revision == self.revision {
            self.undo_stack.clear();
        } else if self.revision - revision < self.undo_stack.len() as i64 {
            let keep = (self.revision - revision) as usize;
            let drop_count = self.undo_stack.len() - keep;
            for _ in 0..drop_count {
                self.undo_stack.pop_front();
            }
        }
    }

    fn on_modify(&mut self, id: i64, old: T) {
        if let Some(state) = self.undo_stack.back_mut() {
            // Objects created during the session are dropped wholesale on undo;
            // only pre-existing objects need their first-seen value.
            if id < state.old_next_id {
                state.old_values.entry(id).or_insert(old);
            }
        }
    }

    // ----- persistence ------------------------------------------------------

    /// Appends `next_id`, the live-row count, then each live `(id, object)` as
    /// raw bytes. No per-field encoding: the object is fixed-size POD, so its
    /// bytes go out with a single copy. The undo stack is deliberately not
    /// persisted — a snapshot is committed state.
    pub(crate) fn pack_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.primary.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.row_count as u64).to_le_bytes());
        for (id, slot) in self.primary.iter().enumerate() {
            if let Some(obj) = slot {
                out.extend_from_slice(&(id as u64).to_le_bytes());
                out.extend_from_slice(obj.as_bytes());
            }
        }
        out.extend_from_slice(&(self.blobs.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.blobs);
    }

    /// Restores rows written by [`Table::pack_into`] into this freshly
    /// registered (empty) table, rebuilding the secondary indices.
    pub(crate) fn load_from(&mut self, bytes: &[u8]) -> Result<(), TableError> {
        debug_assert!(self.primary.is_empty() && self.undo_stack.is_empty());
        let obj_size = std::mem::size_of::<T>();
        let mut pos = 0usize;
        let next_id = read_u64(bytes, &mut pos)? as usize;
        let live = read_u64(bytes, &mut pos)? as usize;

        self.primary.resize_with(next_id, || None);
        for _ in 0..live {
            let id = read_u64(bytes, &mut pos)? as usize;
            let end = pos
                .checked_add(obj_size)
                .filter(|end| *end <= bytes.len())
                .ok_or(TableError::Corrupted("row extends past snapshot"))?;
            let obj = T::read_from_bytes(&bytes[pos..end])
                .map_err(|_| TableError::Corrupted("row bytes do not decode"))?;
            pos = end;
            if id >= next_id || self.primary[id].is_some() {
                return Err(TableError::Corrupted("row id out of range or duplicated"));
            }
            for index in &mut self.secondaries {
                if !index.try_insert(&obj) {
                    return Err(TableError::Corrupted("duplicate secondary key in snapshot"));
                }
            }
            self.primary[id] = Some(obj);
            self.row_count += 1;
        }
        let blob_len = read_u64(bytes, &mut pos)? as usize;
        let end = pos
            .checked_add(blob_len)
            .filter(|end| *end <= bytes.len())
            .ok_or(TableError::Corrupted("blob arena extends past snapshot"))?;
        self.blobs.extend_from_slice(&bytes[pos..end]);
        pos = end;
        if pos != bytes.len() {
            return Err(TableError::Corrupted("trailing bytes in table snapshot"));
        }
        Ok(())
    }
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, TableError> {
    let end = pos
        .checked_add(8)
        .filter(|end| *end <= bytes.len())
        .ok_or(TableError::Corrupted("snapshot truncated"))?;
    let v = u64::from_le_bytes(bytes[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(v)
}

/// Inserts an object into every secondary index, rolling back on a conflict so
/// the indices are left unchanged.
fn try_insert_all<T: ArenaObject>(
    secondaries: &mut [Box<dyn SecondaryIndex<T>>],
    obj: &T,
) -> Result<(), TableError> {
    for i in 0..secondaries.len() {
        if !secondaries[i].try_insert(obj) {
            let index_name = secondaries[i].index_name();
            for prior in &mut secondaries[..i] {
                prior.erase(obj);
            }
            return Err(TableError::UniquenessViolation {
                type_name: T::type_name(),
                index_name,
            });
        }
    }
    Ok(())
}

/// Read view over one secondary index, resolving ids through the primary arena.
pub struct IndexView<'a, T: ArenaObject, Tag: IndexedBy<T>> {
    map: &'a BTreeMap<Tag::Key, i64>,
    primary: &'a [Option<T>],
}

impl<'a, T: ArenaObject, Tag: IndexedBy<T>> IndexView<'a, T, Tag> {
    fn row(&self, id: i64) -> &'a T {
        self.primary[id as usize]
            .as_ref()
            .expect("secondary index points at a live row")
    }

    pub fn find(&self, key: &Tag::Key) -> Option<&'a T> {
        self.map.get(key).map(|&id| self.row(id))
    }

    pub fn get(&self, key: &Tag::Key) -> Result<&'a T, TableError> {
        self.find(key).ok_or(TableError::UnknownKey {
            type_name: T::type_name(),
        })
    }

    pub fn contains(&self, key: &Tag::Key) -> bool {
        self.map.contains_key(key)
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&'a Tag::Key, &'a T)> + '_ {
        self.map.iter().map(|(key, &id)| (key, self.row(id)))
    }

    /// Objects with key `>= key`, in key order (chainbase `lower_bound`).
    pub fn lower_bound(
        &self,
        key: &Tag::Key,
    ) -> impl DoubleEndedIterator<Item = (&'a Tag::Key, &'a T)> + '_ {
        self.range((Bound::Included(key.clone()), Bound::Unbounded))
    }

    /// Objects with key `> key`, in key order (chainbase `upper_bound`).
    pub fn upper_bound(
        &self,
        key: &Tag::Key,
    ) -> impl DoubleEndedIterator<Item = (&'a Tag::Key, &'a T)> + '_ {
        self.range((Bound::Excluded(key.clone()), Bound::Unbounded))
    }

    pub fn range<R: std::ops::RangeBounds<Tag::Key>>(
        &self,
        range: R,
    ) -> impl DoubleEndedIterator<Item = (&'a Tag::Key, &'a T)> + '_ {
        self.map
            .range((range.start_bound().cloned(), range.end_bound().cloned()))
            .map(|(key, &id)| (key, self.row(id)))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
