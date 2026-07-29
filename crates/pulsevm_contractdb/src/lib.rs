//! The EOS/PulseVM contract database — the `db_*_i64` primary-key table API
//! contracts use — built on [`pulsevm_arena`]. This is the layer whose iterator
//! semantics are consensus-critical: contracts observe iterator handles, the
//! per-table end iterator, and traversal order, so they must match EOS exactly.
//!
//! Rows live in a `key_value_object` table keyed by `(t_id, primary_key)`, where
//! `t_id` is a `table_id_object` identified by `(code, scope, table)`. Iterator
//! handles are assigned by [`IteratorCache`] with EOS's encoding: real rows get
//! non-negative handles, each table gets a negative end iterator
//! `-(index + 2)`, and `-1` means "no such table".
//!
//! Names (`code`/`scope`/`table`) are plain `u64` here (the packed name), so the
//! crate has no dependency on the FFI.
//!
//! Implemented: the primary i64 API. The secondary indices (idx64/128/256/
//! double) follow the same shape and are not built yet.

use std::collections::HashMap;
use std::ops::Bound;

use pulsevm_arena::{
    ArenaObject, BlobRef, Db, IndexedBy, ObjectId, SecondaryIndex, key_index,
};

/// `chainbase::table_id_object` — one contract table, identified by
/// `(code, scope, table)`.
#[repr(C)]
#[derive(
    Clone, Copy, Default, zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct TableIdObject {
    id: ObjectId<TableIdObject>,
    code: u64,
    scope: u64,
    table: u64,
    payer: u64,
    count: u32,
    _pad: u32,
}

struct ByCodeScopeTable;
impl IndexedBy<TableIdObject> for ByCodeScopeTable {
    type Key = (u64, u64, u64);
    fn key(o: &TableIdObject) -> Self::Key {
        (o.code, o.scope, o.table)
    }
}
impl ArenaObject for TableIdObject {
    const TYPE_ID: u16 = 0;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![key_index::<Self, ByCodeScopeTable>()]
    }
}

/// `chainbase::key_value_object` — one row, keyed by `(t_id, primary_key)`.
#[repr(C)]
#[derive(
    Clone, Copy, Default, zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct KeyValueObject {
    id: ObjectId<KeyValueObject>,
    t_id: i64,
    primary_key: u64,
    payer: u64,
    value: BlobRef,
}

struct ByScopePrimary;
impl IndexedBy<KeyValueObject> for ByScopePrimary {
    type Key = (i64, u64);
    fn key(o: &KeyValueObject) -> Self::Key {
        (o.t_id, o.primary_key)
    }
}
impl ArenaObject for KeyValueObject {
    const TYPE_ID: u16 = 1;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![key_index::<Self, ByScopePrimary>()]
    }
}

/// Assigns stable iterator handles for one transaction, with EOS's encoding:
/// real rows get non-negative handles; each table gets a negative end iterator
/// `-(index + 2)`.
#[derive(Default)]
pub struct IteratorCache {
    end_to_table: Vec<i64>,
    table_to_end: HashMap<i64, i32>,
    iter_to_kv: Vec<i64>,
    kv_to_iter: HashMap<i64, i32>,
}

impl IteratorCache {
    /// Ensures the table has an end iterator and returns it.
    fn cache_table(&mut self, t_id: i64) -> i32 {
        if let Some(&ei) = self.table_to_end.get(&t_id) {
            return ei;
        }
        let ei = -(self.end_to_table.len() as i32 + 2);
        self.end_to_table.push(t_id);
        self.table_to_end.insert(t_id, ei);
        ei
    }

    fn end_iterator_of(&self, t_id: i64) -> i32 {
        self.table_to_end[&t_id]
    }

    fn table_of_end_iterator(&self, ei: i32) -> i64 {
        self.end_to_table[(-ei - 2) as usize]
    }

    fn add(&mut self, kv_id: i64) -> i32 {
        if let Some(&h) = self.kv_to_iter.get(&kv_id) {
            return h;
        }
        let h = self.iter_to_kv.len() as i32;
        self.iter_to_kv.push(kv_id);
        self.kv_to_iter.insert(kv_id, h);
        h
    }

    fn kv_of(&self, handle: i32) -> i64 {
        self.iter_to_kv[handle as usize]
    }
}

/// The contract database and its per-transaction iterator cache.
pub struct ContractDb {
    db: Db,
    cache: IteratorCache,
}

impl Default for ContractDb {
    fn default() -> Self {
        Self::new()
    }
}

impl ContractDb {
    pub fn new() -> Self {
        let mut db = Db::new();
        db.add_table::<TableIdObject>().unwrap();
        db.add_table::<KeyValueObject>().unwrap();
        ContractDb {
            db,
            cache: IteratorCache::default(),
        }
    }

    /// Clears iterator handles (a new transaction starts fresh).
    pub fn reset_iterators(&mut self) {
        self.cache = IteratorCache::default();
    }

    fn find_table(&self, code: u64, scope: u64, table: u64) -> Option<i64> {
        self.db
            .find_by::<TableIdObject, ByCodeScopeTable>(&(code, scope, table))
            .unwrap()
            .map(|t| t.id().raw())
    }

    fn find_or_create_table(&mut self, code: u64, scope: u64, table: u64, payer: u64) -> i64 {
        if let Some(t) = self.find_table(code, scope, table) {
            return t;
        }
        self.db
            .create::<TableIdObject>(|t| {
                t.code = code;
                t.scope = scope;
                t.table = table;
                t.payer = payer;
                t.count = 0;
            })
            .unwrap()
            .id()
            .raw()
    }

    fn kv(&self, kv_id: i64) -> KeyValueObject {
        *self.db.get::<KeyValueObject>(ObjectId::new(kv_id)).unwrap()
    }

    /// First row with `(t_id, key) > (t_id, primary)` still in this table.
    fn next_row(&self, t_id: i64, primary: u64) -> Option<(u64, i64)> {
        self.db
            .table::<KeyValueObject>()
            .unwrap()
            .get_index::<ByScopePrimary>()
            .range((Bound::Excluded((t_id, primary)), Bound::Unbounded))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(k, o)| (k.1, o.id().raw()))
    }

    /// Largest row with `(t_id, key) < (t_id, primary)` still in this table.
    fn prev_row(&self, t_id: i64, primary: u64) -> Option<(u64, i64)> {
        self.db
            .table::<KeyValueObject>()
            .unwrap()
            .get_index::<ByScopePrimary>()
            .range((Bound::Unbounded, Bound::Excluded((t_id, primary))))
            .next_back()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(k, o)| (k.1, o.id().raw()))
    }

    /// First row with key `>= (t_id, primary)` in this table.
    fn lower_row(&self, t_id: i64, primary: u64) -> Option<(u64, i64)> {
        self.db
            .table::<KeyValueObject>()
            .unwrap()
            .get_index::<ByScopePrimary>()
            .range((Bound::Included((t_id, primary)), Bound::Unbounded))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(k, o)| (k.1, o.id().raw()))
    }

    /// Last row of the table (for `previous` of an end iterator).
    fn last_row(&self, t_id: i64) -> Option<(u64, i64)> {
        self.db
            .table::<KeyValueObject>()
            .unwrap()
            .get_index::<ByScopePrimary>()
            .range((
                Bound::Included((t_id, u64::MIN)),
                Bound::Included((t_id, u64::MAX)),
            ))
            .next_back()
            .map(|(k, o)| (k.1, o.id().raw()))
    }

    // ----- the db_*_i64 API -------------------------------------------------

    pub fn db_store_i64(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        id: u64,
        value: &[u8],
    ) -> i32 {
        let t_id = self.find_or_create_table(code, scope, table, payer);
        let blob = self.db.alloc_blob::<KeyValueObject>(value).unwrap();
        let kv_id = self
            .db
            .create::<KeyValueObject>(|k| {
                k.t_id = t_id;
                k.primary_key = id;
                k.payer = payer;
                k.value = blob;
            })
            .unwrap()
            .id()
            .raw();
        self.db
            .modify::<TableIdObject>(ObjectId::new(t_id), |t| t.count += 1)
            .unwrap();
        self.cache.cache_table(t_id);
        self.cache.add(kv_id)
    }

    pub fn db_update_i64(&mut self, itr: i32, payer: u64, value: &[u8]) {
        let kv_id = self.cache.kv_of(itr);
        let blob = self.db.alloc_blob::<KeyValueObject>(value).unwrap();
        self.db
            .modify::<KeyValueObject>(ObjectId::new(kv_id), |k| {
                k.value = blob;
                k.payer = payer;
            })
            .unwrap();
    }

    pub fn db_remove_i64(&mut self, itr: i32) {
        let kv_id = self.cache.kv_of(itr);
        let t_id = self.kv(kv_id).t_id;
        self.db.remove::<KeyValueObject>(ObjectId::new(kv_id)).unwrap();
        self.db
            .modify::<TableIdObject>(ObjectId::new(t_id), |t| t.count -= 1)
            .unwrap();
    }

    pub fn db_get_i64(&self, itr: i32) -> Vec<u8> {
        let kv = self.kv(self.cache.kv_of(itr));
        self.db.blob::<KeyValueObject>(kv.value).unwrap().to_vec()
    }

    pub fn db_find_i64(&mut self, code: u64, scope: u64, table: u64, id: u64) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.cache.cache_table(t_id);
        match self
            .db
            .find_by::<KeyValueObject, ByScopePrimary>(&(t_id, id))
            .unwrap()
            .map(|k| k.id().raw())
        {
            Some(kv_id) => self.cache.add(kv_id),
            None => end,
        }
    }

    pub fn db_lowerbound_i64(&mut self, code: u64, scope: u64, table: u64, id: u64) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.cache.cache_table(t_id);
        match self.lower_row(t_id, id) {
            Some((_, kv_id)) => self.cache.add(kv_id),
            None => end,
        }
    }

    pub fn db_upperbound_i64(&mut self, code: u64, scope: u64, table: u64, id: u64) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.cache.cache_table(t_id);
        match self.next_row(t_id, id) {
            Some((_, kv_id)) => self.cache.add(kv_id),
            None => end,
        }
    }

    pub fn db_end_i64(&mut self, code: u64, scope: u64, table: u64) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        self.cache.cache_table(t_id)
    }

    pub fn db_next_i64(&mut self, itr: i32, primary: &mut u64) -> i32 {
        if itr < -1 {
            return itr; // an end iterator has no next
        }
        let kv = self.kv(self.cache.kv_of(itr));
        match self.next_row(kv.t_id, kv.primary_key) {
            Some((p, kv_id)) => {
                *primary = p;
                self.cache.add(kv_id)
            }
            None => self.cache.end_iterator_of(kv.t_id),
        }
    }

    pub fn db_previous_i64(&mut self, itr: i32, primary: &mut u64) -> i32 {
        if itr < -1 {
            // previous of an end iterator is the table's last row
            let t_id = self.cache.table_of_end_iterator(itr);
            return match self.last_row(t_id) {
                Some((p, kv_id)) => {
                    *primary = p;
                    self.cache.add(kv_id)
                }
                None => -1,
            };
        }
        let kv = self.kv(self.cache.kv_of(itr));
        match self.prev_row(kv.t_id, kv.primary_key) {
            Some((p, kv_id)) => {
                *primary = p;
                self.cache.add(kv_id)
            }
            None => -1,
        }
    }
}
