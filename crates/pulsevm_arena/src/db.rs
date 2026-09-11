use std::{
    any::{
        Any,
        TypeId,
    },
    path::Path,
};

use crate::{
    object::{
        ArenaObject,
        BlobRef,
        IndexedBy,
    },
    table::{
        Table,
        TableError,
    },
};

/// Errors from the database layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    NotRegistered {
        type_name: &'static str,
    },
    TypeIdInUse {
        type_id: u16,
        type_name: &'static str,
    },
    Corrupted(String),
    Io(String),
    Table(TableError),
}

impl From<TableError> for DbError {
    fn from(e: TableError) -> Self {
        DbError::Table(e)
    }
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, DbError> {
    let end = pos
        .checked_add(8)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| DbError::Corrupted("snapshot truncated".into()))?;
    let v = u64::from_le_bytes(bytes[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(v)
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> Result<u16, DbError> {
    let end = pos
        .checked_add(2)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| DbError::Corrupted("snapshot truncated".into()))?;
    let v = u16::from_le_bytes(bytes[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(v)
}

fn read_i64(bytes: &[u8], pos: &mut usize) -> Result<i64, DbError> {
    Ok(read_u64(bytes, pos)? as i64)
}

/// Reads a u64 without advancing, or `None` if fewer than 8 bytes remain.
fn try_read_u64(bytes: &[u8], pos: usize) -> Option<u64> {
    bytes
        .get(pos..pos + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// Writes `bytes` to a temp file, fsyncs it, then renames it over `path`, so a
/// crash never leaves a half-written file in place.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), DbError> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(|e| DbError::Io(e.to_string()))?;
    f.write_all(bytes).map_err(|e| DbError::Io(e.to_string()))?;
    f.sync_all().map_err(|e| DbError::Io(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| DbError::Io(e.to_string()))
}

/// Appends `[len][frame]` to the log and fsyncs.
fn append_frame(path: &Path, frame: &[u8]) -> Result<(), DbError> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| DbError::Io(e.to_string()))?;
    f.write_all(&(frame.len() as u64).to_le_bytes())
        .map_err(|e| DbError::Io(e.to_string()))?;
    f.write_all(frame).map_err(|e| DbError::Io(e.to_string()))?;
    f.sync_all().map_err(|e| DbError::Io(e.to_string()))
}

/// Type-erased view of a `Table<T>` so the database can drive the shared
/// revision/undo lifecycle across a heterogeneous set of tables.
trait AbstractTable: Send + Sync {
    fn start_undo_session(&mut self) -> i64;
    fn revision(&self) -> i64;
    fn set_revision(&mut self, revision: i64) -> Result<(), TableError>;
    fn undo(&mut self);
    fn squash(&mut self);
    fn commit(&mut self, revision: i64);
    fn undo_all(&mut self);
    fn undo_stack_revision_range(&self) -> (i64, i64);
    fn len(&self) -> usize;
    fn type_id_num(&self) -> u16;
    fn type_name(&self) -> &'static str;
    fn pack_into(&self, out: &mut Vec<u8>);
    fn load_from(&mut self, bytes: &[u8]) -> Result<(), TableError>;
    fn pack_delta(&self, out: &mut Vec<u8>);
    fn apply_delta(&mut self, bytes: &[u8]) -> Result<(), TableError>;
    fn mark_flushed(&mut self);
    fn hash_state(&self, hasher: &mut sha2::Sha256);
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: ArenaObject> AbstractTable for Table<T> {
    fn start_undo_session(&mut self) -> i64 {
        Table::start_undo_session(self)
    }
    fn revision(&self) -> i64 {
        Table::revision(self)
    }
    fn set_revision(&mut self, revision: i64) -> Result<(), TableError> {
        Table::set_revision(self, revision)
    }
    fn undo(&mut self) {
        Table::undo(self)
    }
    fn squash(&mut self) {
        Table::squash(self)
    }
    fn commit(&mut self, revision: i64) {
        Table::commit(self, revision)
    }
    fn undo_all(&mut self) {
        Table::undo_all(self)
    }
    fn undo_stack_revision_range(&self) -> (i64, i64) {
        Table::undo_stack_revision_range(self)
    }
    fn len(&self) -> usize {
        Table::len(self)
    }
    fn type_id_num(&self) -> u16 {
        T::TYPE_ID
    }
    fn type_name(&self) -> &'static str {
        T::type_name()
    }
    fn pack_into(&self, out: &mut Vec<u8>) {
        Table::pack_into(self, out)
    }
    fn load_from(&mut self, bytes: &[u8]) -> Result<(), TableError> {
        Table::load_from(self, bytes)
    }
    fn pack_delta(&self, out: &mut Vec<u8>) {
        Table::pack_delta(self, out)
    }
    fn apply_delta(&mut self, bytes: &[u8]) -> Result<(), TableError> {
        Table::apply_delta(self, bytes)
    }
    fn mark_flushed(&mut self) {
        Table::mark_flushed(self)
    }
    fn hash_state(&self, hasher: &mut sha2::Sha256) {
        Table::hash_state(self, hasher)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// A single-threaded set of [`Table`]s sharing one revision/undo lifecycle —
/// the recreation of chainbase `database`, without the lock. Reads hand out
/// references into the tables; there is no clone-out and no `RwLock`.
///
/// An undo session spans every table: [`Db::start_undo_session`] opens one on
/// all of them, and [`Db::undo`]/[`Db::squash`]/[`Db::commit`] fan out so the
/// tables stay at a single shared revision.
#[derive(Default)]
pub struct Db {
    tables: Vec<Box<dyn AbstractTable>>,
    // Arena type ids are compact consensus schema constants. Direct indexing
    // avoids hashing Rust TypeId on every row operation in the execution path.
    by_type_id: Vec<Option<(TypeId, usize)>>,
}

impl Db {
    pub fn new() -> Self {
        Db::default()
    }

    /// Registers the table for `T`. A freshly created table is brought up to the
    /// revision range of the already-registered tables, so every table shares
    /// one undo stack depth.
    pub fn add_table<T: ArenaObject>(&mut self) -> Result<(), DbError> {
        let type_id = usize::from(T::TYPE_ID);
        if self
            .by_type_id
            .get(type_id)
            .and_then(|entry| *entry)
            .is_some()
        {
            return Err(DbError::TypeIdInUse {
                type_id: T::TYPE_ID,
                type_name: T::type_name(),
            });
        }
        let mut table = Table::<T>::new();
        if let Some(first) = self.tables.first() {
            let (lo, hi) = first.undo_stack_revision_range();
            table.set_revision(lo)?;
            while table.revision() < hi {
                table.start_undo_session();
            }
        }
        let pos = self.tables.len();
        self.tables.push(Box::new(table));
        if self.by_type_id.len() <= type_id {
            self.by_type_id.resize(type_id + 1, None);
        }
        self.by_type_id[type_id] = Some((TypeId::of::<T>(), pos));
        Ok(())
    }

    fn pos<T: ArenaObject>(&self) -> Result<usize, DbError> {
        self.by_type_id
            .get(usize::from(T::TYPE_ID))
            .and_then(|entry| *entry)
            .filter(|(rust_type, _)| *rust_type == TypeId::of::<T>())
            .map(|(_, position)| position)
            .ok_or(DbError::NotRegistered {
                type_name: T::type_name(),
            })
    }

    /// Shared access to a whole table, for iteration and secondary-index scans.
    pub fn table<T: ArenaObject>(&self) -> Result<&Table<T>, DbError> {
        let pos = self.pos::<T>()?;
        Ok(self.tables[pos]
            .as_any()
            .downcast_ref::<Table<T>>()
            .expect("table registered under mismatching type"))
    }

    /// Mutable access to a whole table.
    pub fn table_mut<T: ArenaObject>(&mut self) -> Result<&mut Table<T>, DbError> {
        let pos = self.pos::<T>()?;
        Ok(self.tables[pos]
            .as_any_mut()
            .downcast_mut::<Table<T>>()
            .expect("table registered under mismatching type"))
    }

    // ----- object operations (conveniences over the table) ------------------

    pub fn create<T: ArenaObject>(&mut self, f: impl FnOnce(&mut T)) -> Result<&T, DbError> {
        Ok(self.table_mut::<T>()?.emplace(f)?)
    }

    pub fn modify<T: ArenaObject>(
        &mut self,
        id: crate::ObjectId<T>,
        m: impl FnOnce(&mut T),
    ) -> Result<(), DbError> {
        Ok(self.table_mut::<T>()?.modify(id, m)?)
    }

    pub fn remove<T: ArenaObject>(&mut self, id: crate::ObjectId<T>) -> Result<(), DbError> {
        Ok(self.table_mut::<T>()?.remove(id)?)
    }

    pub fn find<T: ArenaObject>(&self, id: crate::ObjectId<T>) -> Result<Option<&T>, DbError> {
        Ok(self.table::<T>()?.find(id))
    }

    pub fn get<T: ArenaObject>(&self, id: crate::ObjectId<T>) -> Result<&T, DbError> {
        Ok(self.table::<T>()?.get(id)?)
    }

    pub fn find_by<T: ArenaObject, Tag: IndexedBy<T>>(
        &self,
        key: &Tag::Key,
    ) -> Result<Option<&T>, DbError> {
        Ok(self.table::<T>()?.get_index::<Tag>().find(key))
    }

    /// Point lookup on a hash-backed index (declared with `hash_index`). O(1)
    /// where an ordered `find_by` is O(log n); use for indexes never scanned.
    pub fn find_by_hash<T: ArenaObject, Tag: IndexedBy<T>>(
        &self,
        key: &Tag::Key,
    ) -> Result<Option<&T>, DbError>
    where
        Tag::Key: std::hash::Hash + Eq,
    {
        Ok(self.table::<T>()?.get_hash_index::<Tag>().find(key))
    }

    /// Appends a variable-length value to `T`'s blob arena; store the returned
    /// ref on the object.
    pub fn alloc_blob<T: ArenaObject>(&mut self, bytes: &[u8]) -> Result<BlobRef, DbError> {
        Ok(self.table_mut::<T>()?.alloc_blob(bytes))
    }

    /// Frees `old` and allocates `bytes` in `T`'s blob arena — the update path
    /// for a blob field, reusing the abandoned span instead of only growing.
    pub fn realloc_blob<T: ArenaObject>(
        &mut self,
        old: BlobRef,
        bytes: &[u8],
    ) -> Result<BlobRef, DbError> {
        Ok(self.table_mut::<T>()?.realloc_blob(old, bytes))
    }

    /// Marks `T`'s blob span as reusable (call when a row carrying it is removed).
    pub fn free_blob<T: ArenaObject>(&mut self, r: BlobRef) -> Result<(), DbError> {
        self.table_mut::<T>()?.free_blob(r);
        Ok(())
    }

    /// Resolves a blob ref against `T`'s arena.
    pub fn blob<T: ArenaObject>(&self, r: BlobRef) -> Result<&[u8], DbError> {
        Ok(self.table::<T>()?.blob(r))
    }

    /// Total bytes in `T`'s blob arena — for checking reuse bounds growth.
    pub fn blob_arena_len<T: ArenaObject>(&self) -> Result<usize, DbError> {
        Ok(self.table::<T>()?.blob_arena_len())
    }

    // ----- revision / undo lifecycle ----------------------------------------

    pub fn revision(&self) -> i64 {
        self.tables.first().map(|t| t.revision()).unwrap_or(0)
    }

    pub fn set_revision(&mut self, revision: i64) -> Result<(), DbError> {
        for table in &mut self.tables {
            table.set_revision(revision)?;
        }
        Ok(())
    }

    /// Opens an undo session on every table. Returns the new shared revision.
    pub fn start_undo_session(&mut self) -> i64 {
        for table in &mut self.tables {
            table.start_undo_session();
        }
        self.revision()
    }

    pub fn undo(&mut self) {
        for table in &mut self.tables {
            table.undo();
        }
    }

    pub fn squash(&mut self) {
        for table in &mut self.tables {
            table.squash();
        }
    }

    pub fn commit(&mut self, revision: i64) {
        for table in &mut self.tables {
            table.commit(revision);
        }
    }

    pub fn undo_all(&mut self) {
        for table in &mut self.tables {
            table.undo_all();
        }
    }

    // ----- persistence ------------------------------------------------------

    /// Writes a full checkpoint of committed state to `path`: the revision plus
    /// every table's live rows as raw bytes, tagged by `type_id`. Fast because
    /// objects are POD — the per-row cost is a copy, not a serialization pass.
    /// The write is atomic (temp file + fsync + rename) so a crash mid-write
    /// leaves the previous checkpoint intact. Marks the tables flushed, so a
    /// following [`Db::flush_delta`] only records changes made after this.
    pub fn checkpoint(&mut self, path: impl AsRef<Path>) -> Result<(), DbError> {
        let mut ordered: Vec<usize> = (0..self.tables.len()).collect();
        ordered.sort_by_key(|&pos| self.tables[pos].type_id_num());

        let mut out = Vec::new();
        out.extend_from_slice(&self.revision().to_le_bytes());
        out.extend_from_slice(&(ordered.len() as u64).to_le_bytes());
        for pos in ordered {
            let table = &self.tables[pos];
            out.extend_from_slice(&table.type_id_num().to_le_bytes());
            let len_at = out.len();
            out.extend_from_slice(&0u64.to_le_bytes()); // section length placeholder
            let start = out.len();
            table.pack_into(&mut out);
            let len = (out.len() - start) as u64;
            out[len_at..len_at + 8].copy_from_slice(&len.to_le_bytes());
        }
        write_atomic(path.as_ref(), &out)?;
        for table in &mut self.tables {
            table.mark_flushed();
        }
        Ok(())
    }

    /// Back-compat alias for [`Db::checkpoint`].
    pub fn save(&mut self, path: impl AsRef<Path>) -> Result<(), DbError> {
        self.checkpoint(path)
    }

    /// Loads a checkpoint written by [`Db::checkpoint`] into the already-
    /// registered (empty) tables and restores the revision. Every section must
    /// map to a registered table. Registered tables absent from an older
    /// checkpoint remain empty, making additive Arena schema changes (such as
    /// the deferred-transaction table) backward-compatible. Unknown checkpoint
    /// table ids remain a hard error so a checkpoint is never partially read.
    pub fn load(&mut self, path: impl AsRef<Path>) -> Result<(), DbError> {
        let data = std::fs::read(path.as_ref()).map_err(|e| DbError::Io(e.to_string()))?;
        let mut pos = 0usize;
        let revision = read_i64(&data, &mut pos)?;
        let count = read_u64(&data, &mut pos)? as usize;
        for _ in 0..count {
            let type_id = read_u16(&data, &mut pos)?;
            let len = read_u64(&data, &mut pos)? as usize;
            let end = pos
                .checked_add(len)
                .filter(|end| *end <= data.len())
                .ok_or_else(|| DbError::Corrupted("section extends past checkpoint".into()))?;
            let table_pos = self
                .by_type_id
                .get(usize::from(type_id))
                .and_then(|entry| *entry)
                .map(|(_, position)| position)
                .ok_or_else(|| {
                    DbError::Corrupted(format!("checkpoint has unregistered type_id {type_id}"))
                })?;
            self.tables[table_pos].load_from(&data[pos..end])?;
            pos = end;
        }
        self.set_revision(revision)?;
        Ok(())
    }

    /// Appends the changes since the last flush/checkpoint to the write-ahead
    /// log at `path` as one framed record (length-prefixed, so a torn final
    /// frame from a crash is detectable), then fsyncs. Cost is O(rows changed),
    /// not O(total state) — the chainbase dirty-page profile, in software.
    pub fn flush_delta(&mut self, path: impl AsRef<Path>) -> Result<(), DbError> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&self.revision().to_le_bytes());
        frame.extend_from_slice(&(self.tables.len() as u64).to_le_bytes());
        for table in &self.tables {
            frame.extend_from_slice(&table.type_id_num().to_le_bytes());
            let len_at = frame.len();
            frame.extend_from_slice(&0u64.to_le_bytes());
            let start = frame.len();
            table.pack_delta(&mut frame);
            let len = (frame.len() - start) as u64;
            frame[len_at..len_at + 8].copy_from_slice(&len.to_le_bytes());
        }
        append_frame(path.as_ref(), &frame)?;
        for table in &mut self.tables {
            table.mark_flushed();
        }
        Ok(())
    }

    /// Replays every complete frame in the log at `path` onto the current state
    /// (typically right after [`Db::load`]), restoring the revision. A trailing
    /// partial frame — a crash during the last flush — is ignored.
    pub fn replay_log(&mut self, path: impl AsRef<Path>) -> Result<(), DbError> {
        let data = match std::fs::read(path.as_ref()) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(DbError::Io(e.to_string())),
        };
        let mut pos = 0usize;
        let mut last_revision: Option<i64> = None;
        while pos < data.len() {
            let Some(frame_len) = try_read_u64(&data, pos) else {
                break; // torn length prefix
            };
            let frame_start = pos + 8;
            let frame_end = frame_start + frame_len as usize;
            if frame_end > data.len() {
                break; // torn frame; stop cleanly
            }
            let frame = &data[frame_start..frame_end];
            self.apply_frame(frame)?;
            let mut fp = 0usize;
            last_revision = Some(read_i64(frame, &mut fp)?);
            pos = frame_end;
        }
        if let Some(rev) = last_revision {
            for table in &mut self.tables {
                table.mark_flushed();
            }
            self.set_revision(rev)?;
        }
        Ok(())
    }

    fn apply_frame(&mut self, frame: &[u8]) -> Result<(), DbError> {
        let mut pos = 0usize;
        let _revision = read_i64(frame, &mut pos)?;
        let count = read_u64(frame, &mut pos)? as usize;
        for _ in 0..count {
            let type_id = read_u16(frame, &mut pos)?;
            let len = read_u64(frame, &mut pos)? as usize;
            let end = pos
                .checked_add(len)
                .filter(|end| *end <= frame.len())
                .ok_or_else(|| DbError::Corrupted("delta extends past frame".into()))?;
            let table_pos = self
                .by_type_id
                .get(usize::from(type_id))
                .and_then(|entry| *entry)
                .map(|(_, position)| position)
                .ok_or_else(|| {
                    DbError::Corrupted(format!("delta for unregistered type_id {type_id}"))
                })?;
            self.tables[table_pos].apply_delta(&frame[pos..end])?;
            pos = end;
        }
        Ok(())
    }

    /// A deterministic SHA-256 over all committed state — every table's live
    /// rows (in id order) and blob arena, tables in `type_id` order. Equal state
    /// gives an equal root, so it is the fingerprint a block-level differential
    /// test compares after each block.
    ///
    /// This is canonical across reloads of this store. A cross-implementation
    /// root (vs C++ chainbase) additionally needs blob refs resolved to their
    /// bytes per object — a small extension once the object schemas are wired.
    pub fn state_root(&self) -> [u8; 32] {
        use sha2::{
            Digest,
            Sha256,
        };
        let mut ordered: Vec<usize> = (0..self.tables.len()).collect();
        ordered.sort_by_key(|&pos| self.tables[pos].type_id_num());
        let mut hasher = Sha256::new();
        for pos in ordered {
            hasher.update(self.tables[pos].type_id_num().to_le_bytes());
            self.tables[pos].hash_state(&mut hasher);
        }
        hasher.finalize().into()
    }

    /// Rows per table as `(count, type name)`, sorted like chainbase
    /// `row_count_per_index`.
    pub fn row_count_per_table(&self) -> Vec<(usize, &'static str)> {
        let mut rows: Vec<(usize, &'static str)> = self
            .tables
            .iter()
            .map(|t| (t.len(), t.type_name()))
            .collect();
        rows.sort();
        rows
    }
}
