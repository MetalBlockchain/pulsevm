use std::any::TypeId;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ops::Bound;

use pulsevm_serialization::{Read as SerRead, Write as SerWrite};

use crate::error::ChainbaseError;
use crate::object::{ChainbaseObject, IndexedBy, KeyIndex, ObjectId, SecondaryIndex};

/// One entry of the undo stack, the equivalent of C++ `undo_index::undo_state`.
///
/// Where the C++ implementation records changes in shared singly linked lists
/// bounded by `old_values_end`/`removed_values_end` and disambiguates duplicate
/// modifies with monotonic `_mtime` stamps, value semantics let each state own
/// its changes directly:
///
/// - a key is *new* if `id >= old_next_id`
/// - a key is *modified* if it is in `old_values` (holding the value it had
///   when the session started; the oldest value wins on repeated modifies)
/// - a key is *removed* if it is in `removed_values` (holding the value at
///   removal; if it is also in `old_values`, undo restores the older value)
struct UndoState<T> {
    old_values: HashMap<i64, T>,
    removed_values: HashMap<i64, T>,
    old_next_id: i64,
}

/// A table of `T` with a built-in ordered id index, ordered unique secondary
/// indices and an undo stack — the recreation of C++ `chainbase::undo_index`
/// (aka `generic_index<MultiIndexType>`).
///
/// Operations on a given key must follow the sequence CREATE MODIFY* REMOVE?,
/// which is guaranteed by construction here since ids are assigned by the
/// index and never reused unless their insertion is undone.
pub struct UndoIndex<T: ChainbaseObject> {
    primary: BTreeMap<i64, T>,
    secondaries: Vec<Box<dyn SecondaryIndex<T>>>,
    tag_positions: HashMap<TypeId, usize>,
    undo_stack: VecDeque<UndoState<T>>,
    next_id: i64,
    revision: i64,
}

impl<T: ChainbaseObject> Default for UndoIndex<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: ChainbaseObject> UndoIndex<T> {
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
        UndoIndex {
            primary: BTreeMap::new(),
            secondaries,
            tag_positions,
            undo_stack: VecDeque::new(),
            next_id: 0,
            revision: 0,
        }
    }

    /// Inserts a new object constructed by `f`. The id is assigned by the
    /// index before `f` runs and cannot be changed by it.
    /// Exception safety (C++ `emplace`): strong — on a uniqueness conflict
    /// nothing is inserted.
    pub fn emplace<F: FnOnce(&mut T)>(&mut self, f: F) -> Result<&T, ChainbaseError> {
        let id = self.next_id;
        let mut obj = T::default();
        obj.set_id(ObjectId::new(id));
        f(&mut obj);
        obj.set_id(ObjectId::new(id)); // the constructor must not pick the id

        try_insert_all(&mut self.secondaries, &obj)?;
        self.next_id += 1;
        // C++ on_create: a fresh id needs no undo record, `old_next_id` marks it as new.
        match self.primary.entry(id) {
            std::collections::btree_map::Entry::Vacant(entry) => Ok(&*entry.insert(obj)),
            std::collections::btree_map::Entry::Occupied(_) => {
                unreachable!("fresh id already present in primary index")
            }
        }
    }

    /// Applies `m` to the stored object.
    ///
    /// Stronger than the C++ basic guarantee: if the result would violate a
    /// uniqueness constraint the object is left unchanged and an error is
    /// returned (C++ removes the object when it has no in-session backup).
    pub fn modify<F: FnOnce(&mut T)>(&mut self, id: ObjectId<T>, m: F) -> Result<(), ChainbaseError> {
        let raw = id.raw();
        let Some(current) = self.primary.get(&raw) else {
            return Err(ChainbaseError::NotFound {
                type_name: T::type_name(),
                id: raw,
            });
        };
        let mut updated = current.clone();
        m(&mut updated);
        if updated.id() != id {
            return Err(ChainbaseError::IdChanged {
                type_name: T::type_name(),
            });
        }

        // Move each secondary entry to its new key; unchanged keys cost no
        // tree operation. Roll back on a conflict (the old keys cannot
        // conflict, they were just vacated).
        for i in 0..self.secondaries.len() {
            if !self.secondaries[i].replace(current, &updated) {
                let index_name = self.secondaries[i].index_name();
                for prior in &mut self.secondaries[..i] {
                    let restored = prior.replace(&updated, current);
                    debug_assert!(restored);
                }
                return Err(ChainbaseError::UniquenessViolation {
                    type_name: T::type_name(),
                    index_name,
                });
            }
        }
        let slot = self.primary.get_mut(&raw).unwrap();
        let old = std::mem::replace(slot, updated);
        self.on_modify(raw, old);
        Ok(())
    }

    /// Removes the object with the given id.
    pub fn remove(&mut self, id: ObjectId<T>) -> Result<(), ChainbaseError> {
        let raw = id.raw();
        let obj = self.primary.remove(&raw).ok_or(ChainbaseError::NotFound {
            type_name: T::type_name(),
            id: raw,
        })?;
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

    /// C++ `remove_object( int64_t id )` from `abstract_index`.
    pub fn remove_object(&mut self, id: i64) -> Result<(), ChainbaseError> {
        self.remove(ObjectId::new(id))
    }

    pub fn find(&self, id: ObjectId<T>) -> Option<&T> {
        self.primary.get(&id.raw())
    }

    pub fn get(&self, id: ObjectId<T>) -> Result<&T, ChainbaseError> {
        self.find(id).ok_or(ChainbaseError::NotFound {
            type_name: T::type_name(),
            id: id.raw(),
        })
    }

    /// Typed view of a secondary index (C++ `indices().get<Tag>()`).
    ///
    /// Panics if `Tag` is not one of the indices declared in
    /// [`ChainbaseObject::secondary_indices`], mirroring the compile error the
    /// C++ template lookup would produce.
    pub fn get_index<Tag: IndexedBy<T>>(&self) -> IndexView<'_, T, Tag> {
        let pos = *self
            .tag_positions
            .get(&TypeId::of::<Tag>())
            .unwrap_or_else(|| {
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

    /// Iterates all objects in id order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &T> + '_ {
        self.primary.values()
    }

    pub fn len(&self) -> usize {
        self.primary.len()
    }

    pub fn is_empty(&self) -> bool {
        self.primary.is_empty()
    }

    pub fn next_id(&self) -> i64 {
        self.next_id
    }

    // ----- undo machinery ---------------------------------------------------

    /// Pushes a new undo state; all changes from now until the matching
    /// `undo`/`squash`/`commit` are tracked. Returns the new revision.
    pub fn start_undo_session(&mut self) -> i64 {
        self.undo_stack.push_back(UndoState {
            old_values: HashMap::new(),
            removed_values: HashMap::new(),
            old_next_id: self.next_id,
        });
        self.revision += 1;
        self.revision
    }

    pub fn revision(&self) -> i64 {
        self.revision
    }

    pub fn set_revision(&mut self, revision: i64) -> Result<(), ChainbaseError> {
        if !self.undo_stack.is_empty() {
            return Err(ChainbaseError::Revision(
                "cannot set revision while there is an existing undo stack".into(),
            ));
        }
        if revision < self.revision {
            return Err(ChainbaseError::Revision("revision cannot decrease".into()));
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

    /// Resets the contents to the state at the top of the undo stack.
    pub fn undo(&mut self) {
        let Some(state) = self.undo_stack.pop_back() else {
            return;
        };
        let UndoState {
            mut old_values,
            removed_values,
            old_next_id,
        } = state;

        // Erase everything created during the session.
        let new_ids: Vec<i64> = self.primary.range(old_next_id..).map(|(id, _)| *id).collect();
        for id in new_ids {
            let obj = self.primary.remove(&id).unwrap();
            for index in &mut self.secondaries {
                index.erase(&obj);
            }
        }

        // A key present in both old_values and removed_values restores the
        // older of the two.
        let mut removed_restore = Vec::with_capacity(removed_values.len());
        for (id, removed) in removed_values {
            debug_assert!(id < old_next_id);
            removed_restore.push(old_values.remove(&id).unwrap_or(removed));
        }

        // Erase the current secondary keys of every surviving modified object
        // before re-inserting any old value, so that restores which trade keys
        // with each other (or with removed objects) never collide transiently.
        let mut modified_restore = Vec::with_capacity(old_values.len());
        for (id, old) in old_values {
            let current = self
                .primary
                .get(&id)
                .expect("undo invariant: modified object is in the table or in removed_values");
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
            self.primary.insert(id, obj);
        }

        self.next_id = old_next_id;
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
            // Objects created in the previous session need no record; the
            // oldest saved value wins for everything else.
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
            // Objects created during the session are dropped wholesale on
            // undo; only pre-existing objects need their first-seen value.
            if id < state.old_next_id {
                state.old_values.entry(id).or_insert(old);
            }
        }
    }

    // ----- persistence ------------------------------------------------------

    /// Serializes the full index state — rows, id counter, revision and undo
    /// stack — in `pulsevm_serialization` format. In C++ all of this lives
    /// directly in the mapped segment; here it is written out on flush/close.
    pub(crate) fn pack_into(&self, out: &mut Vec<u8>) -> Result<(), ChainbaseError> {
        pack(out, &self.next_id)?;
        pack(out, &self.revision)?;
        pack(out, &(self.primary.len() as u64))?;
        for (id, obj) in &self.primary {
            pack(out, id)?;
            pack(out, obj)?;
        }
        pack(out, &(self.undo_stack.len() as u64))?;
        for state in &self.undo_stack {
            pack(out, &state.old_next_id)?;
            pack(out, &(state.old_values.len() as u64))?;
            for (id, obj) in &state.old_values {
                pack(out, id)?;
                pack(out, obj)?;
            }
            pack(out, &(state.removed_values.len() as u64))?;
            for (id, obj) in &state.removed_values {
                pack(out, id)?;
                pack(out, obj)?;
            }
        }
        Ok(())
    }

    /// Restores the state serialized by [`UndoIndex::pack_into`] into this
    /// (empty, freshly registered) index, rebuilding the secondary indices.
    pub(crate) fn unpack_from(&mut self, bytes: &[u8]) -> Result<(), ChainbaseError> {
        assert!(
            self.primary.is_empty() && self.undo_stack.is_empty(),
            "unpack into a non-empty index"
        );
        let pos = &mut 0usize;
        self.next_id = unpack(bytes, pos)?;
        let revision: i64 = unpack(bytes, pos)?;
        let row_count: u64 = unpack(bytes, pos)?;
        for _ in 0..row_count {
            let id: i64 = unpack(bytes, pos)?;
            let obj: T = unpack(bytes, pos)?;
            if obj.id().raw() != id || id >= self.next_id {
                return Err(corrupted::<T>("row with inconsistent id"));
            }
            for index in &mut self.secondaries {
                if !index.try_insert(&obj) {
                    return Err(corrupted::<T>("duplicate secondary key"));
                }
            }
            if self.primary.insert(id, obj).is_some() {
                return Err(corrupted::<T>("duplicate row id"));
            }
        }
        let state_count: u64 = unpack(bytes, pos)?;
        for _ in 0..state_count {
            let old_next_id: i64 = unpack(bytes, pos)?;
            let mut state = UndoState {
                old_values: HashMap::new(),
                removed_values: HashMap::new(),
                old_next_id,
            };
            let old_count: u64 = unpack(bytes, pos)?;
            for _ in 0..old_count {
                let id: i64 = unpack(bytes, pos)?;
                state.old_values.insert(id, unpack(bytes, pos)?);
            }
            let removed_count: u64 = unpack(bytes, pos)?;
            for _ in 0..removed_count {
                let id: i64 = unpack(bytes, pos)?;
                state.removed_values.insert(id, unpack(bytes, pos)?);
            }
            self.undo_stack.push_back(state);
        }
        if *pos != bytes.len() {
            return Err(corrupted::<T>("trailing bytes in index payload"));
        }
        // The persisted revision counts the persisted undo stack, so bypass
        // the no-undo-stack restriction of set_revision.
        self.revision = revision;
        Ok(())
    }
}

/// Appends the value's encoding directly to `out` (sized via `NumBytes`),
/// avoiding the temporary allocation `Write::pack` would make per value.
pub(crate) fn pack<V: SerWrite>(out: &mut Vec<u8>, value: &V) -> Result<(), ChainbaseError> {
    let start = out.len();
    out.resize(start + value.num_bytes(), 0);
    let mut pos = start;
    value
        .write(out, &mut pos)
        .map_err(|e| ChainbaseError::Serialization(e.to_string()))?;
    debug_assert_eq!(pos, out.len());
    Ok(())
}

/// Inserts an object into every secondary index, rolling back on a conflict
/// so the indices are left unchanged.
fn try_insert_all<T: ChainbaseObject>(
    secondaries: &mut [Box<dyn SecondaryIndex<T>>],
    obj: &T,
) -> Result<(), ChainbaseError> {
    for i in 0..secondaries.len() {
        if !secondaries[i].try_insert(obj) {
            let index_name = secondaries[i].index_name();
            for prior in &mut secondaries[..i] {
                prior.erase(obj);
            }
            return Err(ChainbaseError::UniquenessViolation {
                type_name: T::type_name(),
                index_name,
            });
        }
    }
    Ok(())
}

pub(crate) fn unpack<V: SerRead>(bytes: &[u8], pos: &mut usize) -> Result<V, ChainbaseError> {
    V::read(bytes, pos).map_err(|e| ChainbaseError::Serialization(e.to_string()))
}

fn corrupted<T: ChainbaseObject>(what: &str) -> ChainbaseError {
    ChainbaseError::Corrupted(format!("index for {}: {}", T::type_name(), what))
}

/// Read view over one secondary index, resolving ids through the primary
/// table. The equivalent of iterating a C++ `ordered_unique` index.
pub struct IndexView<'a, T: ChainbaseObject, Tag: IndexedBy<T>> {
    map: &'a BTreeMap<Tag::Key, i64>,
    primary: &'a BTreeMap<i64, T>,
}

impl<'a, T: ChainbaseObject, Tag: IndexedBy<T>> IndexView<'a, T, Tag> {
    pub fn find(&self, key: &Tag::Key) -> Option<&'a T> {
        self.map.get(key).map(|id| &self.primary[id])
    }

    pub fn get(&self, key: &Tag::Key) -> Result<&'a T, ChainbaseError> {
        self.find(key).ok_or(ChainbaseError::UnknownKey {
            type_name: T::type_name(),
        })
    }

    pub fn contains(&self, key: &Tag::Key) -> bool {
        self.map.contains_key(key)
    }

    /// All objects in key order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&'a Tag::Key, &'a T)> + '_ {
        self.map.iter().map(|(key, id)| (key, &self.primary[id]))
    }

    /// Objects with key `>= key`, in key order (C++ `lower_bound`).
    pub fn lower_bound(
        &self,
        key: &Tag::Key,
    ) -> impl DoubleEndedIterator<Item = (&'a Tag::Key, &'a T)> + '_ {
        self.range((Bound::Included(key), Bound::Unbounded))
    }

    /// Objects with key `> key`, in key order (C++ `upper_bound`).
    pub fn upper_bound(
        &self,
        key: &Tag::Key,
    ) -> impl DoubleEndedIterator<Item = (&'a Tag::Key, &'a T)> + '_ {
        self.range((Bound::Excluded(key), Bound::Unbounded))
    }

    pub fn range<R: std::ops::RangeBounds<Tag::Key>>(
        &self,
        range: R,
    ) -> impl DoubleEndedIterator<Item = (&'a Tag::Key, &'a T)> + '_ {
        self.map
            .range((range.start_bound().cloned(), range.end_bound().cloned()))
            .map(|(key, id)| (key, &self.primary[id]))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
