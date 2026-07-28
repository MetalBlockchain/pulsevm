use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::error::ChainbaseError;
use crate::mapped_file::MappedFile;
use crate::object::{ChainbaseObject, IndexedBy, ObjectId};
use crate::undo_index::{UndoIndex, pack, unpack};

/// C++ `database::open_flags`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenFlags {
    ReadOnly,
    ReadWrite,
}

/// Type-erased interface over an `UndoIndex<T>`, the recreation of C++
/// `chainbase::abstract_index`.
trait AbstractIndex: Send + Sync {
    fn set_revision(&mut self, revision: i64) -> Result<(), ChainbaseError>;
    fn start_undo_session(&mut self) -> i64;
    fn revision(&self) -> i64;
    fn undo(&mut self);
    fn squash(&mut self);
    fn commit(&mut self, revision: i64);
    fn undo_all(&mut self);
    fn row_count(&self) -> u64;
    fn type_name(&self) -> &'static str;
    fn undo_stack_revision_range(&self) -> (i64, i64);
    fn remove_object(&mut self, id: i64) -> Result<(), ChainbaseError>;
    fn pack_into(&self, out: &mut Vec<u8>) -> Result<(), ChainbaseError>;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: ChainbaseObject> AbstractIndex for UndoIndex<T> {
    fn set_revision(&mut self, revision: i64) -> Result<(), ChainbaseError> {
        UndoIndex::set_revision(self, revision)
    }
    fn start_undo_session(&mut self) -> i64 {
        UndoIndex::start_undo_session(self)
    }
    fn revision(&self) -> i64 {
        UndoIndex::revision(self)
    }
    fn undo(&mut self) {
        UndoIndex::undo(self)
    }
    fn squash(&mut self) {
        UndoIndex::squash(self)
    }
    fn commit(&mut self, revision: i64) {
        UndoIndex::commit(self, revision)
    }
    fn undo_all(&mut self) {
        UndoIndex::undo_all(self)
    }
    fn row_count(&self) -> u64 {
        self.len() as u64
    }
    fn type_name(&self) -> &'static str {
        T::type_name()
    }
    fn undo_stack_revision_range(&self) -> (i64, i64) {
        UndoIndex::undo_stack_revision_range(self)
    }
    fn remove_object(&mut self, id: i64) -> Result<(), ChainbaseError> {
        UndoIndex::remove_object(self, id)
    }
    fn pack_into(&self, out: &mut Vec<u8>) -> Result<(), ChainbaseError> {
        UndoIndex::pack_into(self, out)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

struct DatabaseInner {
    /// Indices in registration order (C++ `_index_list`).
    indices: Vec<Box<dyn AbstractIndex>>,
    /// `type_id` -> position in `indices` (C++ `_index_map`).
    by_type_id: HashMap<u16, usize>,
    /// Rust type -> position, for generic access without the `type_id`.
    by_rust_type: HashMap<TypeId, usize>,
    /// C++ `_read_only_mode`: modifications error while set. Toggleable,
    /// unlike `read_only`.
    read_only_mode: bool,
    /// C++ `_read_only`: fixed for the lifetime of a database opened with
    /// [`OpenFlags::ReadOnly`].
    read_only: bool,
    /// The memory mapped backing file; `None` for a purely in-memory database.
    persist: Option<MappedFile>,
    /// Index payloads loaded from the file but not yet claimed by
    /// `add_index` (C++ keeps unclaimed named segment objects untouched);
    /// preserved verbatim when the database is written back out.
    pending: HashMap<u16, Vec<u8>>,
    /// Test hook: skip the clean close so the file stays dirty, as a crash
    /// would leave it.
    skip_clean_close: bool,
}

/// Serializes every table (live and unclaimed) as
/// `count, (type_id, byte_len, bytes)*`, packing each index directly into
/// the output buffer and backpatching its length (the codec writes `u64` as
/// fixed-width little-endian).
fn build_payload(inner: &DatabaseInner) -> Result<Vec<u8>, ChainbaseError> {
    let mut type_ids: Vec<u16> = inner
        .by_type_id
        .keys()
        .chain(inner.pending.keys())
        .copied()
        .collect();
    type_ids.sort_unstable();

    let mut payload = Vec::new();
    pack(&mut payload, &(type_ids.len() as u32))?;
    for type_id in type_ids {
        pack(&mut payload, &type_id)?;
        let len_at = payload.len();
        pack(&mut payload, &0u64)?; // placeholder for the byte length
        let start = payload.len();
        match inner.by_type_id.get(&type_id) {
            Some(&pos) => inner.indices[pos].pack_into(&mut payload)?,
            None => payload.extend_from_slice(&inner.pending[&type_id]),
        }
        let len = (payload.len() - start) as u64;
        payload[len_at..len_at + 8].copy_from_slice(&len.to_le_bytes());
    }
    Ok(payload)
}

fn parse_payload(payload: &[u8]) -> Result<HashMap<u16, Vec<u8>>, ChainbaseError> {
    let pos = &mut 0usize;
    let count: u32 = unpack(payload, pos)?;
    let mut pending = HashMap::with_capacity(count as usize);
    for _ in 0..count {
        let type_id: u16 = unpack(payload, pos)?;
        let len: u64 = unpack(payload, pos)? ;
        let end = pos
            .checked_add(len as usize)
            .filter(|end| *end <= payload.len())
            .ok_or_else(|| {
                ChainbaseError::Corrupted("index payload length exceeds file payload".into())
            })?;
        if pending.insert(type_id, payload[*pos..end].to_vec()).is_some() {
            return Err(ChainbaseError::Corrupted(format!(
                "duplicate payload for type_id {type_id}"
            )));
        }
        *pos = end;
    }
    if *pos != payload.len() {
        return Err(ChainbaseError::Corrupted(
            "trailing bytes in database payload".into(),
        ));
    }
    Ok(pending)
}

impl Drop for DatabaseInner {
    /// The graceful close: persist the current state and clear the dirty
    /// flag, like the C++ database destructor unmapping its segment.
    fn drop(&mut self) {
        if self.skip_clean_close {
            return;
        }
        if self.persist.as_ref().is_none_or(|m| m.is_read_only()) {
            return;
        }
        let result = build_payload(self).and_then(|payload| {
            let mapped = self.persist.as_mut().unwrap();
            mapped.write_payload(&payload)?;
            mapped.set_dirty(false)
        });
        if let Err(err) = result {
            eprintln!("pulsevm_chainbase: failed to persist database on close: {err}");
        }
    }
}

impl DatabaseInner {
    fn index_pos<T: ChainbaseObject>(&self) -> Result<usize, ChainbaseError> {
        self.by_rust_type
            .get(&TypeId::of::<T>())
            .copied()
            .ok_or(ChainbaseError::IndexNotRegistered {
                type_name: T::type_name(),
            })
    }

    fn index<T: ChainbaseObject>(&self) -> Result<&UndoIndex<T>, ChainbaseError> {
        let pos = self.index_pos::<T>()?;
        Ok(self.indices[pos]
            .as_any()
            .downcast_ref::<UndoIndex<T>>()
            .expect("index registered under mismatching type"))
    }

    fn index_mut<T: ChainbaseObject>(&mut self) -> Result<&mut UndoIndex<T>, ChainbaseError> {
        self.ensure_writable("get mutable index")?;
        let pos = self.index_pos::<T>()?;
        Ok(self.indices[pos]
            .as_any_mut()
            .downcast_mut::<UndoIndex<T>>()
            .expect("index registered under mismatching type"))
    }

    fn ensure_writable(&self, operation: &'static str) -> Result<(), ChainbaseError> {
        if self.read_only_mode {
            return Err(ChainbaseError::ReadOnly { operation });
        }
        Ok(())
    }
}

/// The recreation of C++ `chainbase::database`: a set of [`UndoIndex`] tables
/// sharing one revision/undo lifecycle.
///
/// The handle is cheaply cloneable and thread-safe (`Arc<RwLock<..>>`
/// internally), matching how the FFI wrapper is shared today. Read accessors
/// return clones of the stored objects; use [`Database::with_index`] to
/// iterate by reference under the lock.
#[derive(Clone)]
pub struct Database {
    inner: Arc<RwLock<DatabaseInner>>,
}

impl Default for Database {
    fn default() -> Self {
        Self::new()
    }
}

impl Database {
    /// Creates an empty in-memory database with no backing file (useful for
    /// tests; state is lost on drop). For persistence use [`Database::open`].
    pub fn new() -> Self {
        Database {
            inner: Arc::new(RwLock::new(DatabaseInner {
                indices: Vec::new(),
                by_type_id: HashMap::new(),
                by_rust_type: HashMap::new(),
                read_only_mode: false,
                read_only: false,
                persist: None,
                pending: HashMap::new(),
                skip_clean_close: false,
            })),
        }
    }

    /// Opens (or, read-write, creates) the memory mapped database at
    /// `dir/shared_memory.bin`, the recreation of the C++
    /// `database(dir, flags, shared_file_size, allow_dirty, ...)` constructor.
    ///
    /// `size` is the initial file size when creating; unlike the fixed C++
    /// segment, the file grows automatically when the state outgrows it.
    ///
    /// The dirty-flag lifecycle matches chainbase: the file is marked dirty
    /// while open read-write and only marked clean by a graceful close (the
    /// drop of the last handle), so after a crash `open` fails with
    /// [`ChainbaseError::Dirty`] unless `allow_dirty` is set — in which case
    /// the state from the last [`Database::flush`] or clean close is loaded.
    ///
    /// Tables become visible once re-registered with [`Database::add_index`];
    /// persisted tables whose type is never re-registered are carried through
    /// untouched, as unclaimed named objects are in the C++ segment.
    pub fn open(
        dir: impl AsRef<Path>,
        flags: OpenFlags,
        size: u64,
        allow_dirty: bool,
    ) -> Result<Database, ChainbaseError> {
        let dir = dir.as_ref();
        let read_only = flags == OpenFlags::ReadOnly;
        if !read_only {
            fs::create_dir_all(dir)
                .map_err(|e| ChainbaseError::Io(format!("{}: {}", dir.display(), e)))?;
        }
        let (mapped, payload) = MappedFile::open(
            &dir.join("shared_memory.bin"),
            size,
            read_only,
            allow_dirty,
        )?;
        let pending = match payload {
            Some(payload) => parse_payload(&payload)?,
            None => HashMap::new(),
        };
        Ok(Database {
            inner: Arc::new(RwLock::new(DatabaseInner {
                indices: Vec::new(),
                by_type_id: HashMap::new(),
                by_rust_type: HashMap::new(),
                read_only_mode: read_only,
                read_only,
                persist: Some(mapped),
                pending,
                skip_clean_close: false,
            })),
        })
    }

    pub fn is_read_only(&self) -> bool {
        self.read().read_only
    }

    /// Serializes the current state into the mapped file and syncs it to
    /// disk. The dirty flag stays set (as in C++, where `flush` msyncs the
    /// live segment); only a graceful close marks the file clean, but a
    /// subsequent `allow_dirty` open recovers the flushed state.
    pub fn flush(&self) -> Result<(), ChainbaseError> {
        let mut inner = self.write();
        if inner.persist.as_ref().is_none_or(|m| m.is_read_only()) {
            return Ok(());
        }
        let payload = build_payload(&inner)?;
        inner.persist.as_mut().unwrap().write_payload(&payload)
    }

    /// Test hook: drop without the clean close, leaving the file dirty
    /// exactly as a crash would.
    #[doc(hidden)]
    pub fn simulate_crash(&self) {
        self.write().skip_clean_close = true;
    }

    fn read(&self) -> RwLockReadGuard<'_, DatabaseInner> {
        self.inner.read()
    }

    fn write(&self) -> RwLockWriteGuard<'_, DatabaseInner> {
        self.inner.write()
    }

    /// Registers the table for `T` (C++ `add_index<MultiIndexType>()`),
    /// loading its persisted rows and undo stack when the database was opened
    /// from a file that contains this table.
    ///
    /// As in C++: a freshly created index is brought up to the revision range
    /// of the already registered indices, while a *loaded* index whose range
    /// disagrees means the file is corrupted.
    pub fn add_index<T: ChainbaseObject>(&self) -> Result<(), ChainbaseError> {
        let mut inner = self.write();
        if inner.by_type_id.contains_key(&T::TYPE_ID) {
            return Err(ChainbaseError::TypeIdInUse {
                type_id: T::TYPE_ID,
                type_name: T::type_name(),
            });
        }
        let mut index = UndoIndex::<T>::new();
        let loaded = match inner.pending.remove(&T::TYPE_ID) {
            Some(bytes) => {
                index.unpack_from(&bytes)?;
                true
            }
            None => {
                if inner.read_only {
                    return Err(ChainbaseError::Corrupted(format!(
                        "unable to find index for {} in read only database",
                        T::type_name()
                    )));
                }
                false
            }
        };
        if let Some(first) = inner.indices.first() {
            let expected = first.undo_stack_revision_range();
            let added = index.undo_stack_revision_range();
            if added != expected {
                if loaded {
                    return Err(ChainbaseError::Corrupted(format!(
                        "existing index for {} has an undo stack (revision range [{}, {}]) that \
                         is inconsistent with other indices in the database (revision range \
                         [{}, {}])",
                        T::type_name(),
                        added.0,
                        added.1,
                        expected.0,
                        expected.1
                    )));
                }
                index.set_revision(expected.0)?;
                while index.revision() < expected.1 {
                    index.start_undo_session();
                }
            }
        }
        let pos = inner.indices.len();
        inner.indices.push(Box::new(index));
        inner.by_type_id.insert(T::TYPE_ID, pos);
        inner.by_rust_type.insert(TypeId::of::<T>(), pos);
        Ok(())
    }

    // ----- object operations ------------------------------------------------

    /// Creates an object, returning a copy including its assigned id.
    pub fn create<T: ChainbaseObject>(
        &self,
        f: impl FnOnce(&mut T),
    ) -> Result<T, ChainbaseError> {
        let mut inner = self.write();
        inner.ensure_writable("create a record")?;
        inner.index_mut::<T>()?.emplace(f).cloned()
    }

    /// Modifies the stored object with `obj`'s id.
    ///
    /// Like C++ `modify` (which returns void), this operates on the object
    /// currently in the database; `obj` only identifies it (here by value
    /// instead of by reference, since reads hand out clones).
    pub fn modify<T: ChainbaseObject>(
        &self,
        obj: &T,
        m: impl FnOnce(&mut T),
    ) -> Result<(), ChainbaseError> {
        let mut inner = self.write();
        inner.ensure_writable("modify a record")?;
        inner.index_mut::<T>()?.modify(obj.id(), m)
    }

    /// Removes the stored object with `obj`'s id.
    pub fn remove<T: ChainbaseObject>(&self, obj: &T) -> Result<(), ChainbaseError> {
        let mut inner = self.write();
        inner.ensure_writable("remove a record")?;
        inner.index_mut::<T>()?.remove(obj.id())
    }

    pub fn find<T: ChainbaseObject>(&self, id: ObjectId<T>) -> Result<Option<T>, ChainbaseError> {
        Ok(self.read().index::<T>()?.find(id).cloned())
    }

    pub fn get<T: ChainbaseObject>(&self, id: ObjectId<T>) -> Result<T, ChainbaseError> {
        self.read().index::<T>()?.get(id).cloned()
    }

    /// Lookup through a secondary index (C++ `find<ObjectType, IndexedByType>`).
    pub fn find_by<T: ChainbaseObject, Tag: IndexedBy<T>>(
        &self,
        key: &Tag::Key,
    ) -> Result<Option<T>, ChainbaseError> {
        Ok(self.read().index::<T>()?.get_index::<Tag>().find(key).cloned())
    }

    pub fn get_by<T: ChainbaseObject, Tag: IndexedBy<T>>(
        &self,
        key: &Tag::Key,
    ) -> Result<T, ChainbaseError> {
        self.read().index::<T>()?.get_index::<Tag>().get(key).cloned()
    }

    /// Runs `f` with shared access to the whole index, for iteration and
    /// range queries by reference (the C++ pattern of walking
    /// `get_index<I, Tag>()` iterators).
    pub fn with_index<T: ChainbaseObject, R>(
        &self,
        f: impl FnOnce(&UndoIndex<T>) -> R,
    ) -> Result<R, ChainbaseError> {
        Ok(f(self.read().index::<T>()?))
    }

    /// Runs `f` with mutable access to the whole index (C++
    /// `get_mutable_index`). All mutations through [`UndoIndex`] still
    /// maintain undo history.
    pub fn with_index_mut<T: ChainbaseObject, R>(
        &self,
        f: impl FnOnce(&mut UndoIndex<T>) -> R,
    ) -> Result<R, ChainbaseError> {
        let mut inner = self.write();
        Ok(f(inner.index_mut::<T>()?))
    }

    // ----- revision / undo lifecycle ---------------------------------------

    /// Starts an undo session covering every index. Dropping the returned
    /// session undoes its changes unless `push`/`squash`/`undo` was called.
    pub fn start_undo_session(&self, enabled: bool) -> Result<UndoSession, ChainbaseError> {
        if !enabled {
            return Ok(UndoSession { inner: None });
        }
        let mut inner = self.write();
        inner.ensure_writable("start_undo_session")?;
        for index in &mut inner.indices {
            index.start_undo_session();
        }
        Ok(UndoSession {
            inner: Some(self.inner.clone()),
        })
    }

    pub fn revision(&self) -> i64 {
        let inner = self.read();
        match inner.indices.first() {
            Some(index) => index.revision(),
            None => -1,
        }
    }

    pub fn set_revision(&self, revision: i64) -> Result<(), ChainbaseError> {
        let mut inner = self.write();
        inner.ensure_writable("set revision")?;
        for index in &mut inner.indices {
            index.set_revision(revision)?;
        }
        Ok(())
    }

    pub fn undo(&self) -> Result<(), ChainbaseError> {
        let mut inner = self.write();
        inner.ensure_writable("undo")?;
        for index in &mut inner.indices {
            index.undo();
        }
        Ok(())
    }

    pub fn squash(&self) -> Result<(), ChainbaseError> {
        let mut inner = self.write();
        inner.ensure_writable("squash")?;
        for index in &mut inner.indices {
            index.squash();
        }
        Ok(())
    }

    pub fn commit(&self, revision: i64) -> Result<(), ChainbaseError> {
        let mut inner = self.write();
        inner.ensure_writable("commit")?;
        for index in &mut inner.indices {
            index.commit(revision);
        }
        Ok(())
    }

    pub fn undo_all(&self) -> Result<(), ChainbaseError> {
        let mut inner = self.write();
        inner.ensure_writable("undo_all")?;
        for index in &mut inner.indices {
            index.undo_all();
        }
        Ok(())
    }

    pub fn set_read_only_mode(&self) {
        self.write().read_only_mode = true;
    }

    pub fn unset_read_only_mode(&self) -> Result<(), ChainbaseError> {
        let mut inner = self.write();
        if inner.read_only {
            return Err(ChainbaseError::ReadOnly {
                operation: "unset read_only_mode while database was opened as read only",
            });
        }
        inner.read_only_mode = false;
        Ok(())
    }

    /// Rows per table as `(count, type name)` pairs, sorted like the C++
    /// `row_count_per_index` multiset.
    pub fn row_count_per_index(&self) -> Vec<(u64, &'static str)> {
        let inner = self.read();
        let mut rows: Vec<(u64, &'static str)> = inner
            .indices
            .iter()
            .map(|index| (index.row_count(), index.type_name()))
            .collect();
        rows.sort();
        rows
    }

    /// Removes an object through the type-erased interface, as the C++
    /// `abstract_index::remove_object( id )` does.
    pub fn remove_object_raw(&self, type_id: u16, id: i64) -> Result<(), ChainbaseError> {
        let mut inner = self.write();
        inner.ensure_writable("remove a record")?;
        let pos = match inner.by_type_id.get(&type_id) {
            Some(pos) => *pos,
            None => {
                return Err(ChainbaseError::IndexNotRegistered {
                    type_name: "unknown type_id",
                });
            }
        };
        inner.indices[pos].remove_object(id)
    }
}

/// RAII undo session over the whole database, the recreation of C++
/// `chainbase::database::session`.
///
/// Dropping the session reverts every change made since it was started, unless
/// [`UndoSession::push`] (keep the undo state for a later `commit`/`undo`) or
/// [`UndoSession::squash`] (merge into the enclosing session) was called
/// first. Nested sessions must be resolved innermost-first, as in C++.
pub struct UndoSession {
    /// `None` once pushed/squashed/undone, or for a disabled session.
    inner: Option<Arc<RwLock<DatabaseInner>>>,
}

impl UndoSession {
    /// Keeps the changes and leaves the undo state on the stack; it becomes
    /// permanent when the database commits past its revision.
    pub fn push(&mut self) {
        self.inner = None;
    }

    /// Merges this session's changes into the previous session.
    pub fn squash(&mut self) {
        if let Some(inner) = self.inner.take() {
            let mut inner = inner.write();
            for index in &mut inner.indices {
                index.squash();
            }
        }
    }

    /// Reverts this session's changes now.
    pub fn undo(&mut self) {
        if let Some(inner) = self.inner.take() {
            let mut inner = inner.write();
            for index in &mut inner.indices {
                index.undo();
            }
        }
    }
}

impl Drop for UndoSession {
    fn drop(&mut self) {
        self.undo();
    }
}
