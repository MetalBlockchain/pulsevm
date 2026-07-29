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

/// RAM overhead billed per row, matching EOS `config::billable_size_v<...>`.
/// RAM usage is consensus state, so these must equal the C++ constants; the
/// values below mirror EOS and should be calibrated against `pulsevm_billable_size`
/// before mainnet use.
const KV_OVERHEAD: i64 = 112; // billable_size_v<key_value_object>
const IDX64_OVERHEAD: i64 = 80; // billable_size_v<index64_object>
const TABLE_OVERHEAD: i64 = 44; // billable_size_v<table_id_object>

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

/// `chainbase::index64_object` — a `uint64` secondary-index entry, ordered by
/// `(t_id, secondary_key, primary_key)`. A multi-index table has one of these
/// tables per secondary index, sharing the `table_id_object` with the primary
/// `key_value_object`.
#[repr(C)]
#[derive(
    Clone, Copy, Default, zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct Index64Object {
    id: ObjectId<Index64Object>,
    t_id: i64,
    primary_key: u64,
    secondary_key: u64,
    payer: u64,
}

struct Idx64ByPrimary;
impl IndexedBy<Index64Object> for Idx64ByPrimary {
    type Key = (i64, u64);
    fn key(o: &Index64Object) -> Self::Key {
        (o.t_id, o.primary_key)
    }
}
struct Idx64BySecondary;
impl IndexedBy<Index64Object> for Idx64BySecondary {
    type Key = (i64, u64, u64);
    fn key(o: &Index64Object) -> Self::Key {
        (o.t_id, o.secondary_key, o.primary_key)
    }
}
impl ArenaObject for Index64Object {
    const TYPE_ID: u16 = 2;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, Idx64ByPrimary>(),
            key_index::<Self, Idx64BySecondary>(),
        ]
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

/// The contract database and its per-transaction iterator caches (one per
/// index, as in EOS — a primary handle and an idx64 handle never collide).
pub struct ContractDb {
    db: Db,
    cache: IteratorCache,
    idx64_cache: IteratorCache,
    /// RAM bytes billed per account (chainbase bills the row payer on write).
    ram: HashMap<u64, i64>,
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
        db.add_table::<Index64Object>().unwrap();
        ContractDb {
            db,
            cache: IteratorCache::default(),
            idx64_cache: IteratorCache::default(),
            ram: HashMap::new(),
        }
    }

    /// Clears iterator handles (a new transaction starts fresh).
    pub fn reset_iterators(&mut self) {
        self.cache = IteratorCache::default();
        self.idx64_cache = IteratorCache::default();
    }

    /// RAM bytes currently billed to `account`.
    pub fn ram_usage(&self, account: u64) -> i64 {
        self.ram.get(&account).copied().unwrap_or(0)
    }

    fn bill(&mut self, account: u64, delta: i64) {
        *self.ram.entry(account).or_insert(0) += delta;
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
        let t_id = self
            .db
            .create::<TableIdObject>(|t| {
                t.code = code;
                t.scope = scope;
                t.table = table;
                t.payer = payer;
                t.count = 0;
            })
            .unwrap()
            .id()
            .raw();
        self.bill(payer, TABLE_OVERHEAD);
        t_id
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
        self.bill(payer, value.len() as i64 + KV_OVERHEAD);
        self.cache.cache_table(t_id);
        self.cache.add(kv_id)
    }

    pub fn db_update_i64(&mut self, itr: i32, payer: u64, value: &[u8]) {
        let kv_id = self.cache.kv_of(itr);
        let old = self.kv(kv_id);
        let old_bytes = old.value.len as i64 + KV_OVERHEAD;
        let new_bytes = value.len() as i64 + KV_OVERHEAD;
        // Move the billed bytes to the new payer, or adjust the delta if same.
        if old.payer == payer {
            self.bill(payer, new_bytes - old_bytes);
        } else {
            self.bill(old.payer, -old_bytes);
            self.bill(payer, new_bytes);
        }
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
        let kv = self.kv(kv_id);
        self.bill(kv.payer, -(kv.value.len as i64 + KV_OVERHEAD));
        self.db.remove::<KeyValueObject>(ObjectId::new(kv_id)).unwrap();
        self.db
            .modify::<TableIdObject>(ObjectId::new(kv.t_id), |t| t.count -= 1)
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

    // ----- the db_idx64_* secondary-index API -------------------------------

    fn idx64(&self, id: i64) -> Index64Object {
        *self.db.get::<Index64Object>(ObjectId::new(id)).unwrap()
    }

    /// First idx64 entry with `(secondary, primary) >= (sec, prim)` in the table.
    fn idx64_from(&self, t_id: i64, sec: u64, prim: u64) -> Option<Index64Object> {
        self.db
            .table::<Index64Object>()
            .unwrap()
            .get_index::<Idx64BySecondary>()
            .range((Bound::Included((t_id, sec, prim)), Bound::Unbounded))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    /// First idx64 entry with `secondary > sec` in the table (upper bound
    /// ignores the primary key, as in EOS).
    fn idx64_above(&self, t_id: i64, sec: u64) -> Option<Index64Object> {
        self.db
            .table::<Index64Object>()
            .unwrap()
            .get_index::<Idx64BySecondary>()
            .range((Bound::Excluded((t_id, sec, u64::MAX)), Bound::Unbounded))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx64_after(&self, t_id: i64, sec: u64, prim: u64) -> Option<Index64Object> {
        self.db
            .table::<Index64Object>()
            .unwrap()
            .get_index::<Idx64BySecondary>()
            .range((Bound::Excluded((t_id, sec, prim)), Bound::Unbounded))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx64_before(&self, t_id: i64, sec: u64, prim: u64) -> Option<Index64Object> {
        self.db
            .table::<Index64Object>()
            .unwrap()
            .get_index::<Idx64BySecondary>()
            .range((Bound::Unbounded, Bound::Excluded((t_id, sec, prim))))
            .next_back()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx64_last(&self, t_id: i64) -> Option<Index64Object> {
        self.db
            .table::<Index64Object>()
            .unwrap()
            .get_index::<Idx64BySecondary>()
            .range((
                Bound::Included((t_id, u64::MIN, u64::MIN)),
                Bound::Included((t_id, u64::MAX, u64::MAX)),
            ))
            .next_back()
            .map(|(_, o)| *o)
    }

    pub fn db_idx64_store(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary: u64,
        secondary: u64,
    ) -> i32 {
        let t_id = self.find_or_create_table(code, scope, table, payer);
        let id = self
            .db
            .create::<Index64Object>(|e| {
                e.t_id = t_id;
                e.primary_key = primary;
                e.secondary_key = secondary;
                e.payer = payer;
            })
            .unwrap()
            .id()
            .raw();
        self.bill(payer, IDX64_OVERHEAD);
        self.idx64_cache.cache_table(t_id);
        self.idx64_cache.add(id)
    }

    pub fn db_idx64_update(&mut self, itr: i32, secondary: u64) {
        let id = self.idx64_cache.kv_of(itr);
        self.db
            .modify::<Index64Object>(ObjectId::new(id), |e| e.secondary_key = secondary)
            .unwrap();
    }

    pub fn db_idx64_remove(&mut self, itr: i32) {
        let id = self.idx64_cache.kv_of(itr);
        let payer = self.idx64(id).payer;
        self.bill(payer, -IDX64_OVERHEAD);
        self.db.remove::<Index64Object>(ObjectId::new(id)).unwrap();
    }

    /// Find the first entry with the given secondary key; sets `primary` to it.
    pub fn db_idx64_find_secondary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx64_cache.cache_table(t_id);
        match self.idx64_from(t_id, secondary, 0) {
            Some(e) if e.secondary_key == secondary => {
                *primary = e.primary_key;
                self.idx64_cache.add(e.id().raw())
            }
            _ => end,
        }
    }

    /// Find the entry for a primary key; sets `secondary` to its secondary key.
    pub fn db_idx64_find_primary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary: u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx64_cache.cache_table(t_id);
        match self
            .db
            .find_by::<Index64Object, Idx64ByPrimary>(&(t_id, primary))
            .unwrap()
            .map(|e| (e.secondary_key, e.id().raw()))
        {
            Some((sec, id)) => {
                *secondary = sec;
                self.idx64_cache.add(id)
            }
            None => end,
        }
    }

    pub fn db_idx64_lowerbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx64_cache.cache_table(t_id);
        match self.idx64_from(t_id, *secondary, 0) {
            Some(e) => {
                *secondary = e.secondary_key;
                *primary = e.primary_key;
                self.idx64_cache.add(e.id().raw())
            }
            None => end,
        }
    }

    pub fn db_idx64_upperbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx64_cache.cache_table(t_id);
        match self.idx64_above(t_id, *secondary) {
            Some(e) => {
                *secondary = e.secondary_key;
                *primary = e.primary_key;
                self.idx64_cache.add(e.id().raw())
            }
            None => end,
        }
    }

    pub fn db_idx64_end(&mut self, code: u64, scope: u64, table: u64) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        self.idx64_cache.cache_table(t_id)
    }

    pub fn db_idx64_next(&mut self, itr: i32, primary: &mut u64) -> i32 {
        if itr < -1 {
            return itr;
        }
        let e = self.idx64(self.idx64_cache.kv_of(itr));
        match self.idx64_after(e.t_id, e.secondary_key, e.primary_key) {
            Some(n) => {
                *primary = n.primary_key;
                self.idx64_cache.add(n.id().raw())
            }
            None => self.idx64_cache.end_iterator_of(e.t_id),
        }
    }

    pub fn db_idx64_previous(&mut self, itr: i32, primary: &mut u64) -> i32 {
        if itr < -1 {
            let t_id = self.idx64_cache.table_of_end_iterator(itr);
            return match self.idx64_last(t_id) {
                Some(e) => {
                    *primary = e.primary_key;
                    self.idx64_cache.add(e.id().raw())
                }
                None => -1,
            };
        }
        let e = self.idx64(self.idx64_cache.kv_of(itr));
        match self.idx64_before(e.t_id, e.secondary_key, e.primary_key) {
            Some(p) => {
                *primary = p.primary_key;
                self.idx64_cache.add(p.id().raw())
            }
            None => -1,
        }
    }
}
