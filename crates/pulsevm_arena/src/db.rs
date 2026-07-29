use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::path::Path;

use crate::object::{ArenaObject, IndexedBy};
use crate::table::{Table, TableError};

/// Errors from the database layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    NotRegistered { type_name: &'static str },
    TypeIdInUse { type_id: u16, type_name: &'static str },
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

/// Type-erased view of a `Table<T>` so the database can drive the shared
/// revision/undo lifecycle across a heterogeneous set of tables.
trait AbstractTable: Send {
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
    by_type_id: HashMap<u16, usize>,
    by_rust_type: HashMap<TypeId, usize>,
}

impl Db {
    pub fn new() -> Self {
        Db::default()
    }

    /// Registers the table for `T`. A freshly created table is brought up to the
    /// revision range of the already-registered tables, so every table shares
    /// one undo stack depth.
    pub fn add_table<T: ArenaObject>(&mut self) -> Result<(), DbError> {
        if self.by_type_id.contains_key(&T::TYPE_ID) {
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
        self.by_type_id.insert(T::TYPE_ID, pos);
        self.by_rust_type.insert(TypeId::of::<T>(), pos);
        Ok(())
    }

    fn pos<T: ArenaObject>(&self) -> Result<usize, DbError> {
        self.by_rust_type
            .get(&TypeId::of::<T>())
            .copied()
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

    pub fn create<T: ArenaObject>(
        &mut self,
        f: impl FnOnce(&mut T),
    ) -> Result<&T, DbError> {
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

    pub fn find<T: ArenaObject>(
        &self,
        id: crate::ObjectId<T>,
    ) -> Result<Option<&T>, DbError> {
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

    /// Writes a snapshot of committed state to `path`: every table's live rows
    /// as raw bytes, tagged by `type_id`. Fast because objects are POD — the
    /// per-row cost is a copy, not a serialization pass. The undo stack is not
    /// part of a snapshot.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), DbError> {
        let mut ordered: Vec<usize> = (0..self.tables.len()).collect();
        ordered.sort_by_key(|&pos| self.tables[pos].type_id_num());

        let mut out = Vec::new();
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
        std::fs::write(path.as_ref(), &out).map_err(|e| DbError::Io(e.to_string()))
    }

    /// Loads a snapshot written by [`Db::save`] into the already-registered
    /// (empty) tables. Every section must map to a registered table and every
    /// registered table must appear in the file.
    pub fn load(&mut self, path: impl AsRef<Path>) -> Result<(), DbError> {
        let data = std::fs::read(path.as_ref()).map_err(|e| DbError::Io(e.to_string()))?;
        let mut pos = 0usize;
        let count = read_u64(&data, &mut pos)? as usize;
        let mut seen = 0usize;
        for _ in 0..count {
            let type_id = read_u16(&data, &mut pos)?;
            let len = read_u64(&data, &mut pos)? as usize;
            let end = pos
                .checked_add(len)
                .filter(|end| *end <= data.len())
                .ok_or_else(|| DbError::Corrupted("section extends past snapshot".into()))?;
            let table_pos = *self.by_type_id.get(&type_id).ok_or_else(|| {
                DbError::Corrupted(format!("snapshot has unregistered type_id {type_id}"))
            })?;
            self.tables[table_pos].load_from(&data[pos..end])?;
            pos = end;
            seen += 1;
        }
        if seen != self.tables.len() {
            return Err(DbError::Corrupted(
                "snapshot is missing a registered table".into(),
            ));
        }
        Ok(())
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
