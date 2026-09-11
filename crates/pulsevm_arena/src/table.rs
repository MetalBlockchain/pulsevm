use std::{
    any::TypeId,
    collections::{
        BTreeMap,
        HashMap,
        VecDeque,
    },
    ops::Bound,
};

use crate::object::{
    ArenaObject,
    BlobRef,
    IndexedBy,
    KeyIndex,
    ObjectId,
    SecondaryIndex,
};

/// Errors from table operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableError {
    NotFound {
        type_name: &'static str,
        id: i64,
    },
    UnknownKey {
        type_name: &'static str,
    },
    UniquenessViolation {
        type_name: &'static str,
        index_name: &'static str,
    },
    IdChanged {
        type_name: &'static str,
    },
    Revision(&'static str),
    Corrupted(&'static str),
}

/// One entry of the undo stack (chainbase `undo_index::undo_state`).
///
/// - a key is *new* if `id >= old_next_id`
/// - a key is *modified* if it is in `old_values` (the value it had when the session started;
///   oldest value wins on repeated modifies)
/// - a key is *removed* if it is in `removed_values`; if it is also in `old_values`, undo restores
///   the older value.
struct UndoState<T> {
    old_values: HashMap<i64, T>,
    removed_values: HashMap<i64, T>,
    // Insertion order of `old_values` / `removed_values` keys (first touch wins,
    // matching the maps' first-write-wins values). chainbase pushes these onto
    // the front of intrusive lists, so its state-history delta emits reverse
    // first-touch order. The order is consensus-visible to a SHiP consumer and
    // must be preserved here, not recovered by sorting on id.
    old_order: Vec<i64>,
    removed_order: Vec<i64>,
    old_next_id: i64,
    /// Blob-arena length when the session started; undo truncates back to it,
    /// dropping every blob appended during the session.
    old_blob_len: usize,
    /// Committed blob spans this session freed (a modify/remove abandoned them).
    /// They only become reusable when the session commits — until then undo may
    /// restore a row that still points at them — so they are held here and moved
    /// to the free list on commit, or discarded on undo.
    freed: Vec<BlobRef>,
    /// Free spans this session's allocations consumed. On undo the allocations
    /// are reverted, so the spans go back to the free list.
    reused: Vec<BlobRef>,
}

/// A copied-out view of the innermost open undo session's change-sets, for
/// consumers (state-history delta packing) that need the block's modified and
/// removed rows without reaching into the private undo stack. Rows are POD, so
/// they are cloned out; the caller resolves current rows/blobs against the live
/// table.
pub struct UndoSessionChanges<T> {
    /// Next id at session start: a live row with `id >= old_next_id` is new.
    pub old_next_id: i64,
    /// `(id, pre-session value)` for every row modified during the session.
    pub old_values: Vec<(i64, T)>,
    /// `(id, removed value)` for every row removed during the session.
    pub removed_values: Vec<(i64, T)>,
}

const PRIMARY_PAGE_SIZE: usize = 1024;
const DIRTY_WORDS_PER_PAGE: usize = PRIMARY_PAGE_SIZE / u64::BITS as usize;

struct DirtyPages {
    pages: Vec<Option<Box<[u64; DIRTY_WORDS_PER_PAGE]>>>,
}

impl DirtyPages {
    fn new() -> Self {
        Self { pages: Vec::new() }
    }

    /// Returns true only when `id` was not already present.
    fn insert(&mut self, id: usize) -> bool {
        let page_id = id / PRIMARY_PAGE_SIZE;
        if self.pages.len() <= page_id {
            self.pages.resize_with(page_id + 1, || None);
        }
        let page = self.pages[page_id].get_or_insert_with(|| Box::new([0; DIRTY_WORDS_PER_PAGE]));
        let within_page = id % PRIMARY_PAGE_SIZE;
        let word = within_page / u64::BITS as usize;
        let mask = 1u64 << (within_page % u64::BITS as usize);
        let was_absent = page[word] & mask == 0;
        page[word] |= mask;
        was_absent
    }

    fn remove(&mut self, id: usize) {
        let page_id = id / PRIMARY_PAGE_SIZE;
        let Some(Some(page)) = self.pages.get_mut(page_id) else {
            return;
        };
        let within_page = id % PRIMARY_PAGE_SIZE;
        let word = within_page / u64::BITS as usize;
        page[word] &= !(1u64 << (within_page % u64::BITS as usize));
        if page.iter().all(|word| *word == 0) {
            self.pages[page_id] = None;
        }
    }
}

struct PrimaryPage<T> {
    slots: Box<[Option<T>]>,
    live: usize,
}

impl<T> PrimaryPage<T> {
    fn new() -> Self {
        Self {
            slots: std::iter::repeat_with(|| None)
                .take(PRIMARY_PAGE_SIZE)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            live: 0,
        }
    }
}

/// Sparse, directly indexed primary storage. Chainbase ids are monotonic and
/// high-churn tables can have a huge `next_id` with few live rows. Keeping one
/// `Option<T>` for every historical id made a small checkpoint expand to tens
/// of gigabytes. Fixed-size pages retain O(1) lookup and deterministic id-order
/// iteration while allocating row slots only near live ids.
struct PagedPrimary<T> {
    pages: Vec<Option<PrimaryPage<T>>>,
    len: usize,
}

impl<T> PagedPrimary<T> {
    fn new() -> Self {
        Self {
            pages: Vec::new(),
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn set_len(&mut self, len: usize) {
        if len < self.len {
            let first_removed = len;
            let first_page = first_removed / PRIMARY_PAGE_SIZE;
            let first_slot = first_removed % PRIMARY_PAGE_SIZE;
            if first_slot != 0
                && let Some(Some(page)) = self.pages.get_mut(first_page)
            {
                for slot in &mut page.slots[first_slot..] {
                    if slot.take().is_some() {
                        page.live -= 1;
                    }
                }
                if page.live == 0 {
                    self.pages[first_page] = None;
                }
            }
            let keep_pages = len.div_ceil(PRIMARY_PAGE_SIZE);
            self.pages.truncate(keep_pages);
        }
        self.len = len;
    }

    fn get(&self, id: usize) -> Option<&T> {
        if id >= self.len {
            return None;
        }
        self.pages
            .get(id / PRIMARY_PAGE_SIZE)
            .and_then(Option::as_ref)
            .and_then(|page| page.slots[id % PRIMARY_PAGE_SIZE].as_ref())
    }

    fn get_mut(&mut self, id: usize) -> Option<&mut T> {
        if id >= self.len {
            return None;
        }
        self.pages
            .get_mut(id / PRIMARY_PAGE_SIZE)
            .and_then(Option::as_mut)
            .and_then(|page| page.slots[id % PRIMARY_PAGE_SIZE].as_mut())
    }

    fn insert(&mut self, id: usize, obj: T) -> bool {
        assert!(id < self.len, "primary id is beyond next_id");
        let page_id = id / PRIMARY_PAGE_SIZE;
        if self.pages.len() <= page_id {
            self.pages.resize_with(page_id + 1, || None);
        }
        let page = self.pages[page_id].get_or_insert_with(PrimaryPage::new);
        let slot = &mut page.slots[id % PRIMARY_PAGE_SIZE];
        let was_absent = slot.is_none();
        *slot = Some(obj);
        if was_absent {
            page.live += 1;
        }
        was_absent
    }

    fn push(&mut self, obj: T) {
        let id = self.len;
        self.len += 1;
        let inserted = self.insert(id, obj);
        debug_assert!(inserted);
    }

    fn take(&mut self, id: usize) -> Option<T> {
        if id >= self.len {
            return None;
        }
        let page_id = id / PRIMARY_PAGE_SIZE;
        let page = self.pages.get_mut(page_id)?.as_mut()?;
        let obj = page.slots[id % PRIMARY_PAGE_SIZE].take()?;
        page.live -= 1;
        if page.live == 0 {
            self.pages[page_id] = None;
        }
        Some(obj)
    }

    fn iter_with_ids(&self) -> impl DoubleEndedIterator<Item = (usize, &T)> + '_ {
        self.pages.iter().enumerate().flat_map(|(page_id, page)| {
            let base = page_id * PRIMARY_PAGE_SIZE;
            page.as_ref().into_iter().flat_map(move |page| {
                page.slots
                    .iter()
                    .enumerate()
                    .filter_map(move |(slot, obj)| obj.as_ref().map(|obj| (base + slot, obj)))
            })
        })
    }
}

/// A table of `T` stored in a sparse, index-addressed arena. The slot number is
/// the id (`by_id` built in), removed rows leave logical tombstones, and ids are
/// never reused unless the insertion that produced them is undone.
pub struct Table<T: ArenaObject> {
    /// Indexed by id; `primary.len()` is the next id to assign.
    primary: PagedPrimary<T>,
    /// Append-only byte arena for variable-length fields, addressed by
    /// [`BlobRef`]. Grows within a session and is truncated back on undo.
    blobs: Vec<u8>,
    secondaries: Vec<Box<dyn SecondaryIndex<T>>>,
    tag_positions: HashMap<TypeId, usize>,
    undo_stack: VecDeque<UndoState<T>>,
    row_count: usize,
    revision: i64,
    /// Ids touched since the last incremental flush, in touch order, each at
    /// most once (deduped by `in_dirty`). Drives the delta log so persistence is
    /// O(changed). A plain `Vec` + membership flag instead of a `BTreeSet` keeps
    /// the write path O(1) — the delta record is order-independent, so no sort is
    /// needed.
    dirty: Vec<i64>,
    in_dirty: DirtyPages,
    /// Reusable blob spans, keyed by exact length, that earlier committed
    /// modifies/removes abandoned. `alloc_blob` reuses one instead of appending,
    /// so repeatedly rewriting a blob field (e.g. a contract row's value on every
    /// transfer) does not grow the arena. Exact-length only: fixed-layout contract
    /// rows re-fill their own slot; a differently-sized value just appends.
    free: HashMap<u32, Vec<u32>>,
    /// Blob spans reused (written in place) below `flushed_blob_len` since the
    /// last flush. The delta log records the tail beyond `flushed_blob_len`; a
    /// reuse writes *inside* the already-flushed region, so it must also be
    /// logged as a patch or a WAL replay would miss it.
    blob_patches: Vec<BlobRef>,
    /// Blob bytes already written to the log; the tail beyond this is new.
    flushed_blob_len: usize,
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
            primary: PagedPrimary::new(),
            blobs: Vec::new(),
            secondaries,
            tag_positions,
            undo_stack: VecDeque::new(),
            row_count: 0,
            revision: 0,
            dirty: Vec::new(),
            in_dirty: DirtyPages::new(),
            free: HashMap::new(),
            blob_patches: Vec::new(),
            flushed_blob_len: 0,
        }
    }

    /// Appends `bytes` to the blob arena and returns a [`BlobRef`] to them, for
    /// a variable-length field. Call during `create`/`modify`, then store the
    /// ref on the object. Empty input yields the default empty ref.
    pub fn alloc_blob(&mut self, bytes: &[u8]) -> BlobRef {
        if bytes.is_empty() {
            return BlobRef::default();
        }
        let len = bytes.len() as u32;
        // Reuse an abandoned span of the exact size before growing the arena.
        if let Some(off) = self.free.get_mut(&len).and_then(|offs| offs.pop()) {
            let start = off as usize;
            self.blobs[start..start + bytes.len()].copy_from_slice(bytes);
            let r = BlobRef { off, len };
            // This overwrote bytes inside the already-flushed region; log it so a
            // WAL replay reproduces them (the tail-only delta would not).
            if (off as usize) < self.flushed_blob_len {
                self.blob_patches.push(r);
            }
            // If a session is open the allocation can be undone, so remember to
            // hand the span back to the free list then.
            if let Some(state) = self.undo_stack.back_mut() {
                state.reused.push(r);
            }
            return r;
        }
        let off = self.blobs.len() as u32;
        self.blobs.extend_from_slice(bytes);
        BlobRef { off, len }
    }

    /// Marks the span a [`BlobRef`] points at as abandoned so a later
    /// [`alloc_blob`] of the same size can reuse it. Call when a blob field is
    /// overwritten or its row removed. While a session is open the span is held
    /// until the session commits (undo may restore a row that still points at
    /// it); with no session it is reusable at once.
    pub fn free_blob(&mut self, r: BlobRef) {
        if r.len == 0 {
            return;
        }
        if let Some(state) = self.undo_stack.back_mut() {
            state.freed.push(r);
        } else {
            self.free.entry(r.len).or_default().push(r.off);
        }
    }

    /// Frees `old` and allocates `bytes` in one call — the blob-field update path.
    pub fn realloc_blob(&mut self, old: BlobRef, bytes: &[u8]) -> BlobRef {
        self.free_blob(old);
        self.alloc_blob(bytes)
    }

    /// Resolves a [`BlobRef`] to its bytes.
    pub fn blob(&self, r: BlobRef) -> &[u8] {
        let start = r.off as usize;
        &self.blobs[start..start + r.len as usize]
    }

    /// Total bytes in the blob arena (live + not-yet-reused free spans). Used to
    /// check that repeatedly rewriting a blob field does not grow it unbounded.
    pub fn blob_arena_len(&self) -> usize {
        self.blobs.len()
    }

    fn next_id(&self) -> i64 {
        self.primary.len() as i64
    }

    /// Records `id` in the dirty set for the next delta flush, at most once per
    /// epoch. Ids can be reused after an undo truncates the slab; the flag stays
    /// set across that (the reused row is still pending), so the id is not pushed
    /// twice and the flush writes its current state.
    fn mark_dirty(&mut self, id: i64) {
        let idx = id as usize;
        if self.in_dirty.insert(idx) {
            self.dirty.push(id);
        }
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
        self.primary.push(obj);
        self.row_count += 1;
        self.mark_dirty(id);
        Ok(self.primary.get(id as usize).unwrap())
    }

    /// Applies `m` to the stored object. On a uniqueness violation the object is
    /// left unchanged and an error is returned.
    pub fn modify<F: FnOnce(&mut T)>(&mut self, id: ObjectId<T>, m: F) -> Result<(), TableError> {
        let raw = id.raw();
        let Some(current) = self.primary.get(raw as usize) else {
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
        let slot = self.primary.get_mut(raw as usize).unwrap();
        let old = std::mem::replace(slot, updated);
        self.on_modify(raw, old);
        self.mark_dirty(raw);
        Ok(())
    }

    /// Removes the object with the given id.
    pub fn remove(&mut self, id: ObjectId<T>) -> Result<(), TableError> {
        let raw = id.raw();
        let obj = self
            .primary
            .take(raw as usize)
            .ok_or(TableError::NotFound {
                type_name: T::type_name(),
                id: raw,
            })?;
        self.row_count -= 1;
        self.mark_dirty(raw);
        for index in &mut self.secondaries {
            index.erase(&obj);
        }
        if let Some(state) = self.undo_stack.back_mut() {
            // An object created in this session leaves no trace when removed.
            if raw < state.old_next_id {
                if !state.removed_values.contains_key(&raw) {
                    state.removed_order.push(raw);
                }
                state.removed_values.insert(raw, obj);
            }
        }
        Ok(())
    }

    pub fn find(&self, id: ObjectId<T>) -> Option<&T> {
        self.primary.get(id.raw() as usize)
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

    /// Typed view of a hash-backed secondary index (declared with `hash_index`).
    /// Point queries only — a hash has no order. Panics if `Tag` is not declared,
    /// or was declared ordered (`key_index`) rather than hashed.
    pub fn get_hash_index<Tag: IndexedBy<T>>(&self) -> HashIndexView<'_, T, Tag>
    where
        Tag::Key: std::hash::Hash + Eq,
    {
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
            .downcast_ref::<crate::object::HashKeyIndex<T, Tag>>()
            .expect("tag registered as ordered; use get_index, not get_hash_index");
        HashIndexView {
            map: &index.map,
            primary: &self.primary,
        }
    }

    /// Iterates live objects in id order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &T> + '_ {
        self.primary.iter_with_ids().map(|(_, obj)| obj)
    }

    pub fn len(&self) -> usize {
        self.row_count
    }

    pub fn is_empty(&self) -> bool {
        self.row_count == 0
    }

    #[cfg(test)]
    fn allocated_primary_pages(&self) -> usize {
        self.primary.pages.iter().flatten().count()
    }

    // ----- undo machinery ---------------------------------------------------

    /// Pushes a new undo state; changes until the matching
    /// `undo`/`squash`/`commit` are tracked. Returns the new revision.
    pub fn start_undo_session(&mut self) -> i64 {
        self.undo_stack.push_back(UndoState {
            old_values: HashMap::new(),
            removed_values: HashMap::new(),
            old_order: Vec::new(),
            removed_order: Vec::new(),
            old_next_id: self.next_id(),
            old_blob_len: self.blobs.len(),
            freed: Vec::new(),
            reused: Vec::new(),
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

    /// Copies out the innermost open undo session's change-sets (chainbase
    /// `last_undo_session`), for state-history delta packing. `None` if no
    /// session is open. `old_values` and `removed_values` come back in reverse
    /// first-touch order, matching chainbase's push-front intrusive lists. The
    /// caller must not re-sort them.
    pub fn last_undo_session_changes(&self) -> Option<UndoSessionChanges<T>>
    where
        T: Clone,
    {
        self.undo_stack.back().map(|state| UndoSessionChanges {
            old_next_id: state.old_next_id,
            old_values: state
                .old_order
                .iter()
                .rev()
                .map(|id| (*id, state.old_values[id]))
                .collect(),
            removed_values: state
                .removed_order
                .iter()
                .rev()
                .map(|id| (*id, state.removed_values[id]))
                .collect(),
        })
    }

    /// Reverts to the state at the top of the undo stack.
    pub fn undo(&mut self) {
        let Some(state) = self.undo_stack.pop_back() else {
            return;
        };
        let UndoState {
            mut old_values,
            removed_values,
            old_order: _,
            removed_order: _,
            old_next_id,
            old_blob_len,
            freed,
            reused,
        } = state;
        // Drop every blob appended during the session; restored objects only
        // reference bytes from before it started.
        self.blobs.truncate(old_blob_len);
        // The session's allocations are reverted, so its reused spans are free
        // again; the spans it abandoned stay live (their rows are being restored).
        for r in reused {
            if (r.off as usize) < old_blob_len {
                self.free.entry(r.len).or_default().push(r.off);
            }
        }
        drop(freed);

        // Erase everything created during the session (ids >= old_next_id) and
        // drop those slots.
        for id in old_next_id as usize..self.primary.len() {
            self.mark_dirty(id as i64);
            if let Some(obj) = self.primary.get(id) {
                for index in &mut self.secondaries {
                    index.erase(obj);
                }
                self.row_count -= 1;
            }
        }
        self.primary.set_len(old_next_id as usize);

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
            let current = self
                .primary
                .get(id as usize)
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
            let was_absent = self.primary.insert(id as usize, obj);
            if was_absent {
                self.row_count += 1;
            }
            self.mark_dirty(id);
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
        let Some(mut top) = self.undo_stack.pop_back() else {
            return;
        };
        self.revision -= 1;
        let freed = std::mem::take(&mut top.freed);
        let reused = std::mem::take(&mut top.reused);
        let Some(previous) = self.undo_stack.back_mut() else {
            // Squashing the only session makes its changes permanent: its freed
            // spans become reusable now.
            for r in freed {
                self.free.entry(r.len).or_default().push(r.off);
            }
            return;
        };
        // The blob spans this session freed/reused now belong to the parent
        // session, undone or committed with it.
        previous.freed.extend(freed);
        previous.reused.extend(reused);
        // Fold the child's change-sets into the parent in operation order. The
        // accessor reverses the combined timeline to match chainbase's
        // push-front lists. First-write wins for values, matching squash.
        for id in top.old_order {
            if id < previous.old_next_id
                && !previous.old_values.contains_key(&id)
                && let Some(old) = top.old_values.remove(&id)
            {
                previous.old_order.push(id);
                previous.old_values.insert(id, old);
            }
        }
        for id in top.removed_order {
            if id < previous.old_next_id
                && let Some(removed) = top.removed_values.remove(&id)
            {
                if !previous.removed_values.contains_key(&id) {
                    previous.removed_order.push(id);
                }
                previous.removed_values.insert(id, removed);
            }
        }
    }

    /// Discards all undo history at or before `revision`.
    pub fn commit(&mut self, revision: i64) {
        let revision = revision.min(self.revision);
        let drop_count = if revision == self.revision {
            self.undo_stack.len()
        } else if self.revision - revision < self.undo_stack.len() as i64 {
            self.undo_stack.len() - (self.revision - revision) as usize
        } else {
            0
        };
        // Committing a session makes it permanent, so the spans it abandoned are
        // now unreferenced and reusable.
        for _ in 0..drop_count {
            if let Some(state) = self.undo_stack.pop_front() {
                for r in state.freed {
                    self.free.entry(r.len).or_default().push(r.off);
                }
            }
        }
    }

    fn on_modify(&mut self, id: i64, old: T) {
        if let Some(state) = self.undo_stack.back_mut() {
            // Objects created during the session are dropped wholesale on undo;
            // only pre-existing objects need their first-seen value.
            if id < state.old_next_id && !state.old_values.contains_key(&id) {
                state.old_order.push(id);
                state.old_values.insert(id, old);
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
        for (id, obj) in self.primary.iter_with_ids() {
            out.extend_from_slice(&(id as u64).to_le_bytes());
            out.extend_from_slice(obj.as_bytes());
        }
        out.extend_from_slice(&(self.blobs.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.blobs);
    }

    /// Restores rows written by [`Table::pack_into`] into this freshly
    /// registered (empty) table, rebuilding the secondary indices.
    pub(crate) fn load_from(&mut self, bytes: &[u8]) -> Result<(), TableError> {
        debug_assert!(self.primary.len() == 0 && self.undo_stack.is_empty());
        let obj_size = std::mem::size_of::<T>();
        let mut pos = 0usize;
        let next_id = read_u64(bytes, &mut pos)? as usize;
        let live = read_u64(bytes, &mut pos)? as usize;

        self.primary.set_len(next_id);
        let mut live_rows = Vec::with_capacity(live);
        // Load the rows first; rebuild the secondary indexes in one bulk pass
        // afterwards (index reconstruction dominates open, and bulk-building is
        // ~10x cheaper than a try_insert per row).
        for _ in 0..live {
            let id = read_u64(bytes, &mut pos)? as usize;
            let end = pos
                .checked_add(obj_size)
                .filter(|end| *end <= bytes.len())
                .ok_or(TableError::Corrupted("row extends past snapshot"))?;
            let obj = T::read_from_bytes(&bytes[pos..end])
                .map_err(|_| TableError::Corrupted("row bytes do not decode"))?;
            pos = end;
            if id >= next_id || self.primary.get(id).is_some() {
                return Err(TableError::Corrupted("row id out of range or duplicated"));
            }
            self.primary.insert(id, obj);
            live_rows.push((id as i64, obj));
            self.row_count += 1;
        }
        for index in &mut self.secondaries {
            if !index.bulk_build(&live_rows) {
                return Err(TableError::Corrupted("duplicate secondary key in snapshot"));
            }
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
        self.flushed_blob_len = self.blobs.len();
        Ok(())
    }

    /// Encodes only the rows touched since the last flush (and the blob tail) —
    /// the delta-log record that makes persistence O(changed). Each dirty id is
    /// written as present (with bytes) or as a tombstone.
    pub(crate) fn pack_delta(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.primary.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.dirty.len() as u64).to_le_bytes());
        for &id in &self.dirty {
            out.extend_from_slice(&(id as u64).to_le_bytes());
            match self.primary.get(id as usize) {
                Some(obj) => {
                    out.push(1);
                    out.extend_from_slice(obj.as_bytes());
                }
                None => out.push(0),
            }
        }
        // In-place patches into the already-flushed region: dedup by offset
        // (the current bytes reflect the last write), then the appended tail.
        let mut seen = std::collections::HashSet::new();
        let patches: Vec<BlobRef> = self
            .blob_patches
            .iter()
            .rev()
            .filter(|r| (r.off as usize) < self.flushed_blob_len && seen.insert(r.off))
            .copied()
            .collect();
        out.extend_from_slice(&(patches.len() as u64).to_le_bytes());
        for r in patches {
            out.extend_from_slice(&(r.off as u64).to_le_bytes());
            out.extend_from_slice(&(r.len as u64).to_le_bytes());
            let start = r.off as usize;
            out.extend_from_slice(&self.blobs[start..start + r.len as usize]);
        }
        let tail = &self.blobs[self.flushed_blob_len..];
        out.extend_from_slice(&(tail.len() as u64).to_le_bytes());
        out.extend_from_slice(tail);
    }

    /// Replays a delta produced by [`Table::pack_delta`] onto the current state.
    pub(crate) fn apply_delta(&mut self, bytes: &[u8]) -> Result<(), TableError> {
        let obj_size = std::mem::size_of::<T>();
        let mut pos = 0usize;
        let next_id = read_u64(bytes, &mut pos)? as usize;
        if self.primary.len() < next_id {
            self.primary.set_len(next_id);
        }
        let count = read_u64(bytes, &mut pos)?;
        for _ in 0..count {
            let id = read_u64(bytes, &mut pos)? as usize;
            let tag = *bytes
                .get(pos)
                .ok_or(TableError::Corrupted("delta truncated"))?;
            pos += 1;
            if let Some(old) = self.primary.take(id) {
                for index in &mut self.secondaries {
                    index.erase(&old);
                }
                self.row_count -= 1;
            }
            if tag == 1 {
                let end = pos
                    .checked_add(obj_size)
                    .filter(|end| *end <= bytes.len())
                    .ok_or(TableError::Corrupted("delta row extends past record"))?;
                let obj = T::read_from_bytes(&bytes[pos..end])
                    .map_err(|_| TableError::Corrupted("delta row does not decode"))?;
                pos = end;
                if id >= self.primary.len() {
                    return Err(TableError::Corrupted("delta row id out of range"));
                }
                for index in &mut self.secondaries {
                    if !index.try_insert(&obj) {
                        return Err(TableError::Corrupted("delta secondary key conflict"));
                    }
                }
                self.primary.insert(id, obj);
                self.row_count += 1;
            }
        }
        // In-place patches (into bytes appended by earlier frames), then the tail.
        let patch_count = read_u64(bytes, &mut pos)?;
        for _ in 0..patch_count {
            let off = read_u64(bytes, &mut pos)? as usize;
            let len = read_u64(bytes, &mut pos)? as usize;
            let end = pos
                .checked_add(len)
                .filter(|end| *end <= bytes.len())
                .ok_or(TableError::Corrupted("delta patch extends past record"))?;
            if off + len > self.blobs.len() {
                return Err(TableError::Corrupted("delta patch out of range"));
            }
            self.blobs[off..off + len].copy_from_slice(&bytes[pos..end]);
            pos = end;
        }
        let blob_len = read_u64(bytes, &mut pos)? as usize;
        let end = pos
            .checked_add(blob_len)
            .filter(|end| *end <= bytes.len())
            .ok_or(TableError::Corrupted("delta blob extends past record"))?;
        self.blobs.extend_from_slice(&bytes[pos..end]);
        pos = end;
        if pos != bytes.len() {
            return Err(TableError::Corrupted("trailing bytes in delta"));
        }
        self.flushed_blob_len = self.blobs.len();
        Ok(())
    }

    pub(crate) fn mark_flushed(&mut self) {
        for &id in &self.dirty {
            self.in_dirty.remove(id as usize);
        }
        self.dirty.clear();
        self.blob_patches.clear();
        self.flushed_blob_len = self.blobs.len();
    }

    /// Feeds this table's committed content into the state hasher: the live rows
    /// in id order, then the blob arena. Order is deterministic, so equal state
    /// yields an equal digest.
    pub(crate) fn hash_state(&self, hasher: &mut sha2::Sha256) {
        use sha2::Digest;
        hasher.update((self.row_count as u64).to_le_bytes());
        for (id, obj) in self.primary.iter_with_ids() {
            hasher.update((id as u64).to_le_bytes());
            hasher.update(obj.as_bytes());
        }
        hasher.update((self.blobs.len() as u64).to_le_bytes());
        hasher.update(&self.blobs);
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
    primary: &'a PagedPrimary<T>,
}

impl<'a, T: ArenaObject, Tag: IndexedBy<T>> IndexView<'a, T, Tag> {
    fn row(&self, id: i64) -> &'a T {
        self.primary
            .get(id as usize)
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

/// Read view over a hash-backed secondary index: O(1) point lookups, no order.
pub struct HashIndexView<'a, T: ArenaObject, Tag: IndexedBy<T>>
where
    Tag::Key: std::hash::Hash + Eq,
{
    map: &'a std::collections::HashMap<Tag::Key, i64>,
    primary: &'a PagedPrimary<T>,
}

impl<'a, T: ArenaObject, Tag: IndexedBy<T>> HashIndexView<'a, T, Tag>
where
    Tag::Key: std::hash::Hash + Eq,
{
    fn row(&self, id: i64) -> &'a T {
        self.primary
            .get(id as usize)
            .expect("secondary index points at a live row")
    }

    pub fn find(&self, key: &Tag::Key) -> Option<&'a T> {
        self.map.get(key).map(|&id| self.row(id))
    }

    pub fn contains(&self, key: &Tag::Key) -> bool {
        self.map.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ObjectId;
    use zerocopy::{
        FromBytes,
        Immutable,
        IntoBytes,
        KnownLayout,
    };

    #[repr(C)]
    #[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
    struct TestRow {
        id: ObjectId<TestRow>,
        value: u64,
    }

    impl ArenaObject for TestRow {
        const TYPE_ID: u16 = 1;

        fn id(&self) -> ObjectId<Self> {
            self.id
        }

        fn set_id(&mut self, id: ObjectId<Self>) {
            self.id = id;
        }
    }

    #[test]
    fn empty_historical_ranges_do_not_retain_row_pages() {
        let mut table = Table::<TestRow>::new();
        for value in 0..(PRIMARY_PAGE_SIZE * 3 + 1) {
            table.emplace(|row| row.value = value as u64).unwrap();
        }
        for id in 0..(PRIMARY_PAGE_SIZE * 3) {
            table.remove(ObjectId::new(id as i64)).unwrap();
        }

        assert_eq!(table.len(), 1);
        assert_eq!(table.next_id(), (PRIMARY_PAGE_SIZE * 3 + 1) as i64);
        assert_eq!(table.allocated_primary_pages(), 1);
        assert_eq!(
            table.iter().next().unwrap().value,
            (PRIMARY_PAGE_SIZE * 3) as u64
        );
    }
}
