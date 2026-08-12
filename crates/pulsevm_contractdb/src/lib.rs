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
//! Implemented: the primary i64 API and the secondary indices (idx64/128/256/
//! double), which share one shape — each with its own object table and iterator
//! cache.

use std::{
    collections::HashMap,
    ops::Bound,
};

use pulsevm_arena::{
    ArenaObject,
    BlobRef,
    Db,
    IndexedBy,
    ObjectId,
    SecondaryIndex,
    key_index,
};

/// RAM overhead billed per row, matching EOS `config::billable_size_v<...>` —
/// the raw `value` from `contract_table_objects.hpp` aligned up to 16
/// (`billable_size_v = ceil(value/16)*16`). RAM usage is consensus state, so
/// these must equal the C++ constants exactly.
const KV_OVERHEAD: i64 = 112; // billable_size_v<key_value_object>
const IDX64_OVERHEAD: i64 = 128; // billable_size_v<index64_object>
const IDX128_OVERHEAD: i64 = 144; // billable_size_v<index128_object>
const IDX256_OVERHEAD: i64 = 160; // billable_size_v<index256_object>
const IDX_DOUBLE_OVERHEAD: i64 = 128; // billable_size_v<index_double_object>
const IDX_LONG_DOUBLE_OVERHEAD: i64 = 144; // billable_size_v<index_long_double_object>
const TABLE_OVERHEAD: i64 = 112; // billable_size_v<table_id_object>

/// `chainbase::table_id_object` — one contract table, identified by
/// `(code, scope, table)`.
#[repr(C)]
#[derive(
    Clone,
    Copy,
    Default,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
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
    Clone,
    Copy,
    Default,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
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
    Clone,
    Copy,
    Default,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
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

/// `chainbase::index128_object` — a `uint128` secondary-index entry. The 128-bit
/// key is stored as two `u64` words to keep the object 8-byte aligned (a real
/// `u128` field would force 16-byte alignment and thus padding, which
/// `zerocopy::IntoBytes` rejects); [`Index128Object::secondary_key`] rejoins them.
#[repr(C)]
#[derive(
    Clone,
    Copy,
    Default,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct Index128Object {
    id: ObjectId<Index128Object>,
    t_id: i64,
    primary_key: u64,
    sec_lo: u64,
    sec_hi: u64,
    payer: u64,
}

impl Index128Object {
    fn secondary_key(&self) -> u128 {
        join_u128(self.sec_lo, self.sec_hi)
    }
}

struct Idx128ByPrimary;
impl IndexedBy<Index128Object> for Idx128ByPrimary {
    type Key = (i64, u64);
    fn key(o: &Index128Object) -> Self::Key {
        (o.t_id, o.primary_key)
    }
}
struct Idx128BySecondary;
impl IndexedBy<Index128Object> for Idx128BySecondary {
    type Key = (i64, u128, u64);
    fn key(o: &Index128Object) -> Self::Key {
        (o.t_id, o.secondary_key(), o.primary_key)
    }
}
impl ArenaObject for Index128Object {
    const TYPE_ID: u16 = 4;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, Idx128ByPrimary>(),
            key_index::<Self, Idx128BySecondary>(),
        ]
    }
}

/// `chainbase::index256_object` — a `key256_t` (`std::array<uint128_t, 2>`)
/// secondary-index entry. EOS orders it with the array's default `operator<`:
/// lexicographic over the two words, element `[0]` most significant. We keep the
/// two words as `s0`/`s1` (word `[0]`/`[1]`), each split into `u64` halves for
/// the same 8-byte-alignment reason as [`Index128Object`], and order the index
/// by `(s0, s1)` so it matches the C++ comparison exactly.
#[repr(C)]
#[derive(
    Clone,
    Copy,
    Default,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct Index256Object {
    id: ObjectId<Index256Object>,
    t_id: i64,
    primary_key: u64,
    s0_lo: u64,
    s0_hi: u64,
    s1_lo: u64,
    s1_hi: u64,
    payer: u64,
}

impl Index256Object {
    /// The key as `[word0, word1]`, word `[0]` most significant — the order EOS
    /// compares in.
    fn secondary_key(&self) -> [u128; 2] {
        [
            join_u128(self.s0_lo, self.s0_hi),
            join_u128(self.s1_lo, self.s1_hi),
        ]
    }
}

struct Idx256ByPrimary;
impl IndexedBy<Index256Object> for Idx256ByPrimary {
    type Key = (i64, u64);
    fn key(o: &Index256Object) -> Self::Key {
        (o.t_id, o.primary_key)
    }
}
struct Idx256BySecondary;
impl IndexedBy<Index256Object> for Idx256BySecondary {
    type Key = (i64, u128, u128, u64);
    fn key(o: &Index256Object) -> Self::Key {
        let [s0, s1] = o.secondary_key();
        (o.t_id, s0, s1, o.primary_key)
    }
}
impl ArenaObject for Index256Object {
    const TYPE_ID: u16 = 5;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, Idx256ByPrimary>(),
            key_index::<Self, Idx256BySecondary>(),
        ]
    }
}

/// Total order over the idx_double secondary key, matching EOS
/// `soft_double_less` (`f64_lt`): numeric order, with `-0.0` and `+0.0` equal.
///
/// EOS asserts the key is not NaN before it reaches the index, so a well-formed
/// caller never inserts one; f64_lt makes NaN "not less than" everything, which
/// is not a strict weak ordering, so a stored NaN would corrupt a BTree. We
/// canonicalize `-0.0` to `+0.0` (making the two compare equal, as f64_lt does)
/// and lean on `total_cmp` for the rest — that reproduces f64_lt on every
/// non-NaN input and, unlike f64_lt, still gives a valid total order if a NaN
/// ever slips through rather than triggering undefined behaviour.
#[derive(Clone, Copy)]
struct DoubleKey(f64);

impl DoubleKey {
    fn canonical(self) -> f64 {
        // `-0.0 == 0.0` is true, so this folds both zeros onto `+0.0`.
        if self.0 == 0.0 { 0.0 } else { self.0 }
    }
}
impl PartialEq for DoubleKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}
impl Eq for DoubleKey {}
impl PartialOrd for DoubleKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for DoubleKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.canonical().total_cmp(&other.canonical())
    }
}

/// `chainbase::index_double_object` — an IEEE-754 `double` secondary-index entry,
/// ordered by [`DoubleKey`] to match EOS's software-float comparison.
#[repr(C)]
#[derive(
    Clone,
    Copy,
    Default,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct IndexDoubleObject {
    id: ObjectId<IndexDoubleObject>,
    t_id: i64,
    primary_key: u64,
    secondary_key: f64,
    payer: u64,
}

struct IdxDoubleByPrimary;
impl IndexedBy<IndexDoubleObject> for IdxDoubleByPrimary {
    type Key = (i64, u64);
    fn key(o: &IndexDoubleObject) -> Self::Key {
        (o.t_id, o.primary_key)
    }
}
struct IdxDoubleBySecondary;
impl IndexedBy<IndexDoubleObject> for IdxDoubleBySecondary {
    type Key = (i64, DoubleKey, u64);
    fn key(o: &IndexDoubleObject) -> Self::Key {
        (o.t_id, DoubleKey(o.secondary_key), o.primary_key)
    }
}
impl ArenaObject for IndexDoubleObject {
    const TYPE_ID: u16 = 6;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, IdxDoubleByPrimary>(),
            key_index::<Self, IdxDoubleBySecondary>(),
        ]
    }
}

/// Total order over the idx_long_double secondary key matching chainbase
/// `soft_long_double_less` (`f128_lt`): the IEEE binary128 numeric order, with
/// `-0.0` and `+0.0` folded together. softfloat is not reachable from a BTree
/// comparator, so this reproduces IEEE-754 total ordering on the 128-bit pattern
/// the same way `f64::total_cmp` does for 64 bits — flip the sign bit for
/// positives, flip all bits for negatives, then compare as a signed integer.
/// That equals `f128_lt` on every non-NaN input, and (unlike `f128_lt`) still
/// yields a valid total order if a NaN ever slips through instead of corrupting
/// the BTree. The float128 pattern is carried as its two `u64` words.
#[derive(Clone, Copy)]
struct LongDoubleKey {
    lo: u64,
    hi: u64,
}

impl LongDoubleKey {
    /// The binary128 `-inf` pattern — the smallest ordering key over any
    /// non-NaN input, so a valid inclusive lower bound for a full-table scan.
    const NEG_INF: LongDoubleKey = LongDoubleKey {
        lo: 0,
        hi: 0xFFFF_0000_0000_0000,
    };
    /// The binary128 `+inf` pattern — the largest ordering key over any non-NaN
    /// input, so a valid inclusive upper bound for a full-table scan.
    const POS_INF: LongDoubleKey = LongDoubleKey {
        lo: 0,
        hi: 0x7FFF_0000_0000_0000,
    };

    fn from_u128(v: u128) -> Self {
        LongDoubleKey {
            lo: v as u64,
            hi: (v >> 64) as u64,
        }
    }

    fn from_words(lo: u64, hi: u64) -> Self {
        LongDoubleKey { lo, hi }
    }

    fn ordering_key(self) -> i128 {
        let bits: u128 = ((self.hi as u128) << 64) | self.lo as u128;
        let sign_mask: u128 = 1u128 << 127;
        // Fold both zeros (exponent and mantissa all zero, either sign) onto
        // `+0.0` so they compare equal, as `f128_lt` treats them.
        let bits = if bits & !sign_mask == 0 { 0 } else { bits };
        let mut key = bits as i128;
        key ^= (((key >> 127) as u128) >> 1) as i128;
        key
    }
}
impl PartialEq for LongDoubleKey {
    fn eq(&self, other: &Self) -> bool {
        self.ordering_key() == other.ordering_key()
    }
}
impl Eq for LongDoubleKey {}
impl PartialOrd for LongDoubleKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for LongDoubleKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ordering_key().cmp(&other.ordering_key())
    }
}

/// `chainbase::index_long_double_object` — a `float128_t` secondary-index entry.
/// Rust has no stable 128-bit float, so the pattern is stored as two `u64` words
/// (`zerocopy` needs 8-byte-aligned POD fields) and ordered by [`LongDoubleKey`]
/// to match EOS's software-float comparison.
#[repr(C)]
#[derive(
    Clone,
    Copy,
    Default,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct IndexLongDoubleObject {
    id: ObjectId<IndexLongDoubleObject>,
    t_id: i64,
    primary_key: u64,
    sec_lo: u64,
    sec_hi: u64,
    payer: u64,
}

impl IndexLongDoubleObject {
    /// Rejoins the two stored words into the raw 128-bit float pattern.
    fn secondary_key(&self) -> u128 {
        join_u128(self.sec_lo, self.sec_hi)
    }
}

struct IdxLongDoubleByPrimary;
impl IndexedBy<IndexLongDoubleObject> for IdxLongDoubleByPrimary {
    type Key = (i64, u64);
    fn key(o: &IndexLongDoubleObject) -> Self::Key {
        (o.t_id, o.primary_key)
    }
}
struct IdxLongDoubleBySecondary;
impl IndexedBy<IndexLongDoubleObject> for IdxLongDoubleBySecondary {
    type Key = (i64, LongDoubleKey, u64);
    fn key(o: &IndexLongDoubleObject) -> Self::Key {
        (
            o.t_id,
            LongDoubleKey::from_words(o.sec_lo, o.sec_hi),
            o.primary_key,
        )
    }
}
impl ArenaObject for IndexLongDoubleObject {
    const TYPE_ID: u16 = 7;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, IdxLongDoubleByPrimary>(),
            key_index::<Self, IdxLongDoubleBySecondary>(),
        ]
    }
}

/// Splits a `u128` into `(low, high)` `u64` words.
fn u128_words(v: u128) -> (u64, u64) {
    (v as u64, (v >> 64) as u64)
}

/// Rejoins `(low, high)` `u64` words into a `u128`.
fn join_u128(lo: u64, hi: u64) -> u128 {
    ((hi as u128) << 64) | lo as u128
}

/// Per-account RAM usage. Held in the database (not a side map) so that a failed
/// transaction's `undo` reverts the billing along with the rows — RAM usage is
/// consensus state and must roll back exactly like everything else.
#[repr(C)]
#[derive(
    Clone,
    Copy,
    Default,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct ResourceUsageObject {
    id: ObjectId<ResourceUsageObject>,
    account: u64,
    ram_bytes: i64,
}
struct UsageByAccount;
impl IndexedBy<ResourceUsageObject> for UsageByAccount {
    type Key = u64;
    fn key(o: &ResourceUsageObject) -> u64 {
        o.account
    }
}
impl ArenaObject for ResourceUsageObject {
    const TYPE_ID: u16 = 3;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![key_index::<Self, UsageByAccount>()]
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
    idx128_cache: IteratorCache,
    idx256_cache: IteratorCache,
    idx_double_cache: IteratorCache,
    idx_long_double_cache: IteratorCache,
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
        db.add_table::<Index128Object>().unwrap();
        db.add_table::<Index256Object>().unwrap();
        db.add_table::<IndexDoubleObject>().unwrap();
        db.add_table::<IndexLongDoubleObject>().unwrap();
        db.add_table::<ResourceUsageObject>().unwrap();
        ContractDb {
            db,
            cache: IteratorCache::default(),
            idx64_cache: IteratorCache::default(),
            idx128_cache: IteratorCache::default(),
            idx256_cache: IteratorCache::default(),
            idx_double_cache: IteratorCache::default(),
            idx_long_double_cache: IteratorCache::default(),
        }
    }

    /// Clears iterator handles (a new transaction starts fresh).
    pub fn reset_iterators(&mut self) {
        self.cache = IteratorCache::default();
        self.idx64_cache = IteratorCache::default();
        self.idx128_cache = IteratorCache::default();
        self.idx256_cache = IteratorCache::default();
        self.idx_double_cache = IteratorCache::default();
        self.idx_long_double_cache = IteratorCache::default();
    }

    // ----- block/transaction lifecycle --------------------------------------

    pub fn revision(&self) -> i64 {
        self.db.revision()
    }
    /// Opens an undo session (a block or a transaction).
    pub fn start_undo_session(&mut self) -> i64 {
        self.db.start_undo_session()
    }
    /// Reverts the innermost session — a failed transaction, leaving no trace
    /// (rows *and* RAM). Iterator handles are invalidated.
    pub fn undo(&mut self) {
        self.db.undo();
        self.reset_iterators();
    }
    /// Folds the innermost session into the one below (a successful tx).
    pub fn squash(&mut self) {
        self.db.squash();
    }
    pub fn commit(&mut self, revision: i64) {
        self.db.commit(revision);
    }

    /// A deterministic root over all contract state, including RAM.
    pub fn state_root(&self) -> [u8; 32] {
        self.db.state_root()
    }

    /// Canonical logical state for differential testing: the sorted primary
    /// rows `(code, scope, table, primary, payer, value)` and the sorted
    /// non-zero RAM `(account, bytes)`.
    #[allow(clippy::type_complexity)]
    pub fn dump(&self) -> (Vec<(u64, u64, u64, u64, u64, Vec<u8>)>, Vec<(u64, i64)>) {
        let tid = self.db.table::<TableIdObject>().unwrap();
        let mut names: HashMap<i64, (u64, u64, u64)> = HashMap::new();
        for t in tid.iter() {
            names.insert(t.id().raw(), (t.code, t.scope, t.table));
        }
        let mut rows = Vec::new();
        for kv in self.db.table::<KeyValueObject>().unwrap().iter() {
            let (code, scope, table) = names[&kv.t_id];
            let value = self.db.blob::<KeyValueObject>(kv.value).unwrap().to_vec();
            rows.push((code, scope, table, kv.primary_key, kv.payer, value));
        }
        rows.sort();
        let mut ram = Vec::new();
        for u in self.db.table::<ResourceUsageObject>().unwrap().iter() {
            if u.ram_bytes != 0 {
                ram.push((u.account, u.ram_bytes));
            }
        }
        ram.sort();
        (rows, ram)
    }

    /// RAM bytes currently billed to `account`.
    pub fn ram_usage(&self, account: u64) -> i64 {
        self.db
            .find_by::<ResourceUsageObject, UsageByAccount>(&account)
            .unwrap()
            .map(|u| u.ram_bytes)
            .unwrap_or(0)
    }

    fn bill(&mut self, account: u64, delta: i64) {
        let existing = self
            .db
            .find_by::<ResourceUsageObject, UsageByAccount>(&account)
            .unwrap()
            .map(|u| u.id());
        match existing {
            Some(id) => self
                .db
                .modify::<ResourceUsageObject>(id, |u| u.ram_bytes += delta)
                .unwrap(),
            None => {
                self.db
                    .create::<ResourceUsageObject>(|u| {
                        u.account = account;
                        u.ram_bytes = delta;
                    })
                    .unwrap();
            }
        }
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
        self.db
            .remove::<KeyValueObject>(ObjectId::new(kv_id))
            .unwrap();
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

    // ----- the db_idx128_* secondary-index API ------------------------------

    fn idx128(&self, id: i64) -> Index128Object {
        *self.db.get::<Index128Object>(ObjectId::new(id)).unwrap()
    }

    fn idx128_from(&self, t_id: i64, sec: u128, prim: u64) -> Option<Index128Object> {
        self.db
            .table::<Index128Object>()
            .unwrap()
            .get_index::<Idx128BySecondary>()
            .range((Bound::Included((t_id, sec, prim)), Bound::Unbounded))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx128_above(&self, t_id: i64, sec: u128) -> Option<Index128Object> {
        self.db
            .table::<Index128Object>()
            .unwrap()
            .get_index::<Idx128BySecondary>()
            .range((Bound::Excluded((t_id, sec, u64::MAX)), Bound::Unbounded))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx128_after(&self, t_id: i64, sec: u128, prim: u64) -> Option<Index128Object> {
        self.db
            .table::<Index128Object>()
            .unwrap()
            .get_index::<Idx128BySecondary>()
            .range((Bound::Excluded((t_id, sec, prim)), Bound::Unbounded))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx128_before(&self, t_id: i64, sec: u128, prim: u64) -> Option<Index128Object> {
        self.db
            .table::<Index128Object>()
            .unwrap()
            .get_index::<Idx128BySecondary>()
            .range((Bound::Unbounded, Bound::Excluded((t_id, sec, prim))))
            .next_back()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx128_last(&self, t_id: i64) -> Option<Index128Object> {
        self.db
            .table::<Index128Object>()
            .unwrap()
            .get_index::<Idx128BySecondary>()
            .range((
                Bound::Included((t_id, u128::MIN, u64::MIN)),
                Bound::Included((t_id, u128::MAX, u64::MAX)),
            ))
            .next_back()
            .map(|(_, o)| *o)
    }

    pub fn db_idx128_store(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary: u64,
        secondary: u128,
    ) -> i32 {
        let t_id = self.find_or_create_table(code, scope, table, payer);
        let (lo, hi) = u128_words(secondary);
        let id = self
            .db
            .create::<Index128Object>(|e| {
                e.t_id = t_id;
                e.primary_key = primary;
                e.sec_lo = lo;
                e.sec_hi = hi;
                e.payer = payer;
            })
            .unwrap()
            .id()
            .raw();
        self.bill(payer, IDX128_OVERHEAD);
        self.idx128_cache.cache_table(t_id);
        self.idx128_cache.add(id)
    }

    pub fn db_idx128_update(&mut self, itr: i32, secondary: u128) {
        let id = self.idx128_cache.kv_of(itr);
        let (lo, hi) = u128_words(secondary);
        self.db
            .modify::<Index128Object>(ObjectId::new(id), |e| {
                e.sec_lo = lo;
                e.sec_hi = hi;
            })
            .unwrap();
    }

    pub fn db_idx128_remove(&mut self, itr: i32) {
        let id = self.idx128_cache.kv_of(itr);
        let payer = self.idx128(id).payer;
        self.bill(payer, -IDX128_OVERHEAD);
        self.db.remove::<Index128Object>(ObjectId::new(id)).unwrap();
    }

    pub fn db_idx128_find_secondary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u128,
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx128_cache.cache_table(t_id);
        match self.idx128_from(t_id, secondary, 0) {
            Some(e) if e.secondary_key() == secondary => {
                *primary = e.primary_key;
                self.idx128_cache.add(e.id().raw())
            }
            _ => end,
        }
    }

    pub fn db_idx128_find_primary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u128,
        primary: u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx128_cache.cache_table(t_id);
        match self
            .db
            .find_by::<Index128Object, Idx128ByPrimary>(&(t_id, primary))
            .unwrap()
            .map(|e| (e.secondary_key(), e.id().raw()))
        {
            Some((sec, id)) => {
                *secondary = sec;
                self.idx128_cache.add(id)
            }
            None => end,
        }
    }

    pub fn db_idx128_lowerbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u128,
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx128_cache.cache_table(t_id);
        match self.idx128_from(t_id, *secondary, 0) {
            Some(e) => {
                *secondary = e.secondary_key();
                *primary = e.primary_key;
                self.idx128_cache.add(e.id().raw())
            }
            None => end,
        }
    }

    pub fn db_idx128_upperbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u128,
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx128_cache.cache_table(t_id);
        match self.idx128_above(t_id, *secondary) {
            Some(e) => {
                *secondary = e.secondary_key();
                *primary = e.primary_key;
                self.idx128_cache.add(e.id().raw())
            }
            None => end,
        }
    }

    pub fn db_idx128_end(&mut self, code: u64, scope: u64, table: u64) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        self.idx128_cache.cache_table(t_id)
    }

    pub fn db_idx128_next(&mut self, itr: i32, primary: &mut u64) -> i32 {
        if itr < -1 {
            return itr;
        }
        let e = self.idx128(self.idx128_cache.kv_of(itr));
        match self.idx128_after(e.t_id, e.secondary_key(), e.primary_key) {
            Some(n) => {
                *primary = n.primary_key;
                self.idx128_cache.add(n.id().raw())
            }
            None => self.idx128_cache.end_iterator_of(e.t_id),
        }
    }

    pub fn db_idx128_previous(&mut self, itr: i32, primary: &mut u64) -> i32 {
        if itr < -1 {
            let t_id = self.idx128_cache.table_of_end_iterator(itr);
            return match self.idx128_last(t_id) {
                Some(e) => {
                    *primary = e.primary_key;
                    self.idx128_cache.add(e.id().raw())
                }
                None => -1,
            };
        }
        let e = self.idx128(self.idx128_cache.kv_of(itr));
        match self.idx128_before(e.t_id, e.secondary_key(), e.primary_key) {
            Some(p) => {
                *primary = p.primary_key;
                self.idx128_cache.add(p.id().raw())
            }
            None => -1,
        }
    }

    // ----- the db_idx256_* secondary-index API ------------------------------

    fn idx256(&self, id: i64) -> Index256Object {
        *self.db.get::<Index256Object>(ObjectId::new(id)).unwrap()
    }

    fn idx256_from(&self, t_id: i64, sec: [u128; 2], prim: u64) -> Option<Index256Object> {
        self.db
            .table::<Index256Object>()
            .unwrap()
            .get_index::<Idx256BySecondary>()
            .range((
                Bound::Included((t_id, sec[0], sec[1], prim)),
                Bound::Unbounded,
            ))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx256_above(&self, t_id: i64, sec: [u128; 2]) -> Option<Index256Object> {
        self.db
            .table::<Index256Object>()
            .unwrap()
            .get_index::<Idx256BySecondary>()
            .range((
                Bound::Excluded((t_id, sec[0], sec[1], u64::MAX)),
                Bound::Unbounded,
            ))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx256_after(&self, t_id: i64, sec: [u128; 2], prim: u64) -> Option<Index256Object> {
        self.db
            .table::<Index256Object>()
            .unwrap()
            .get_index::<Idx256BySecondary>()
            .range((
                Bound::Excluded((t_id, sec[0], sec[1], prim)),
                Bound::Unbounded,
            ))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx256_before(&self, t_id: i64, sec: [u128; 2], prim: u64) -> Option<Index256Object> {
        self.db
            .table::<Index256Object>()
            .unwrap()
            .get_index::<Idx256BySecondary>()
            .range((
                Bound::Unbounded,
                Bound::Excluded((t_id, sec[0], sec[1], prim)),
            ))
            .next_back()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx256_last(&self, t_id: i64) -> Option<Index256Object> {
        self.db
            .table::<Index256Object>()
            .unwrap()
            .get_index::<Idx256BySecondary>()
            .range((
                Bound::Included((t_id, u128::MIN, u128::MIN, u64::MIN)),
                Bound::Included((t_id, u128::MAX, u128::MAX, u64::MAX)),
            ))
            .next_back()
            .map(|(_, o)| *o)
    }

    pub fn db_idx256_store(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary: u64,
        secondary: [u128; 2],
    ) -> i32 {
        let t_id = self.find_or_create_table(code, scope, table, payer);
        let (s0_lo, s0_hi) = u128_words(secondary[0]);
        let (s1_lo, s1_hi) = u128_words(secondary[1]);
        let id = self
            .db
            .create::<Index256Object>(|e| {
                e.t_id = t_id;
                e.primary_key = primary;
                e.s0_lo = s0_lo;
                e.s0_hi = s0_hi;
                e.s1_lo = s1_lo;
                e.s1_hi = s1_hi;
                e.payer = payer;
            })
            .unwrap()
            .id()
            .raw();
        self.bill(payer, IDX256_OVERHEAD);
        self.idx256_cache.cache_table(t_id);
        self.idx256_cache.add(id)
    }

    pub fn db_idx256_update(&mut self, itr: i32, secondary: [u128; 2]) {
        let id = self.idx256_cache.kv_of(itr);
        let (s0_lo, s0_hi) = u128_words(secondary[0]);
        let (s1_lo, s1_hi) = u128_words(secondary[1]);
        self.db
            .modify::<Index256Object>(ObjectId::new(id), |e| {
                e.s0_lo = s0_lo;
                e.s0_hi = s0_hi;
                e.s1_lo = s1_lo;
                e.s1_hi = s1_hi;
            })
            .unwrap();
    }

    pub fn db_idx256_remove(&mut self, itr: i32) {
        let id = self.idx256_cache.kv_of(itr);
        let payer = self.idx256(id).payer;
        self.bill(payer, -IDX256_OVERHEAD);
        self.db.remove::<Index256Object>(ObjectId::new(id)).unwrap();
    }

    pub fn db_idx256_find_secondary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: [u128; 2],
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx256_cache.cache_table(t_id);
        match self.idx256_from(t_id, secondary, 0) {
            Some(e) if e.secondary_key() == secondary => {
                *primary = e.primary_key;
                self.idx256_cache.add(e.id().raw())
            }
            _ => end,
        }
    }

    pub fn db_idx256_find_primary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut [u128; 2],
        primary: u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx256_cache.cache_table(t_id);
        match self
            .db
            .find_by::<Index256Object, Idx256ByPrimary>(&(t_id, primary))
            .unwrap()
            .map(|e| (e.secondary_key(), e.id().raw()))
        {
            Some((sec, id)) => {
                *secondary = sec;
                self.idx256_cache.add(id)
            }
            None => end,
        }
    }

    pub fn db_idx256_lowerbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut [u128; 2],
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx256_cache.cache_table(t_id);
        match self.idx256_from(t_id, *secondary, 0) {
            Some(e) => {
                *secondary = e.secondary_key();
                *primary = e.primary_key;
                self.idx256_cache.add(e.id().raw())
            }
            None => end,
        }
    }

    pub fn db_idx256_upperbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut [u128; 2],
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx256_cache.cache_table(t_id);
        match self.idx256_above(t_id, *secondary) {
            Some(e) => {
                *secondary = e.secondary_key();
                *primary = e.primary_key;
                self.idx256_cache.add(e.id().raw())
            }
            None => end,
        }
    }

    pub fn db_idx256_end(&mut self, code: u64, scope: u64, table: u64) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        self.idx256_cache.cache_table(t_id)
    }

    pub fn db_idx256_next(&mut self, itr: i32, primary: &mut u64) -> i32 {
        if itr < -1 {
            return itr;
        }
        let e = self.idx256(self.idx256_cache.kv_of(itr));
        match self.idx256_after(e.t_id, e.secondary_key(), e.primary_key) {
            Some(n) => {
                *primary = n.primary_key;
                self.idx256_cache.add(n.id().raw())
            }
            None => self.idx256_cache.end_iterator_of(e.t_id),
        }
    }

    pub fn db_idx256_previous(&mut self, itr: i32, primary: &mut u64) -> i32 {
        if itr < -1 {
            let t_id = self.idx256_cache.table_of_end_iterator(itr);
            return match self.idx256_last(t_id) {
                Some(e) => {
                    *primary = e.primary_key;
                    self.idx256_cache.add(e.id().raw())
                }
                None => -1,
            };
        }
        let e = self.idx256(self.idx256_cache.kv_of(itr));
        match self.idx256_before(e.t_id, e.secondary_key(), e.primary_key) {
            Some(p) => {
                *primary = p.primary_key;
                self.idx256_cache.add(p.id().raw())
            }
            None => -1,
        }
    }

    // ----- the db_idx_double_* secondary-index API --------------------------

    fn idx_double(&self, id: i64) -> IndexDoubleObject {
        *self.db.get::<IndexDoubleObject>(ObjectId::new(id)).unwrap()
    }

    fn idx_double_from(&self, t_id: i64, sec: f64, prim: u64) -> Option<IndexDoubleObject> {
        self.db
            .table::<IndexDoubleObject>()
            .unwrap()
            .get_index::<IdxDoubleBySecondary>()
            .range((
                Bound::Included((t_id, DoubleKey(sec), prim)),
                Bound::Unbounded,
            ))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx_double_above(&self, t_id: i64, sec: f64) -> Option<IndexDoubleObject> {
        self.db
            .table::<IndexDoubleObject>()
            .unwrap()
            .get_index::<IdxDoubleBySecondary>()
            .range((
                Bound::Excluded((t_id, DoubleKey(sec), u64::MAX)),
                Bound::Unbounded,
            ))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx_double_after(&self, t_id: i64, sec: f64, prim: u64) -> Option<IndexDoubleObject> {
        self.db
            .table::<IndexDoubleObject>()
            .unwrap()
            .get_index::<IdxDoubleBySecondary>()
            .range((
                Bound::Excluded((t_id, DoubleKey(sec), prim)),
                Bound::Unbounded,
            ))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx_double_before(&self, t_id: i64, sec: f64, prim: u64) -> Option<IndexDoubleObject> {
        self.db
            .table::<IndexDoubleObject>()
            .unwrap()
            .get_index::<IdxDoubleBySecondary>()
            .range((
                Bound::Unbounded,
                Bound::Excluded((t_id, DoubleKey(sec), prim)),
            ))
            .next_back()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx_double_last(&self, t_id: i64) -> Option<IndexDoubleObject> {
        self.db
            .table::<IndexDoubleObject>()
            .unwrap()
            .get_index::<IdxDoubleBySecondary>()
            .range((
                Bound::Included((t_id, DoubleKey(f64::NEG_INFINITY), u64::MIN)),
                Bound::Included((t_id, DoubleKey(f64::INFINITY), u64::MAX)),
            ))
            .next_back()
            .map(|(_, o)| *o)
    }

    pub fn db_idx_double_store(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary: u64,
        secondary: f64,
    ) -> i32 {
        let t_id = self.find_or_create_table(code, scope, table, payer);
        let id = self
            .db
            .create::<IndexDoubleObject>(|e| {
                e.t_id = t_id;
                e.primary_key = primary;
                e.secondary_key = secondary;
                e.payer = payer;
            })
            .unwrap()
            .id()
            .raw();
        self.bill(payer, IDX_DOUBLE_OVERHEAD);
        self.idx_double_cache.cache_table(t_id);
        self.idx_double_cache.add(id)
    }

    pub fn db_idx_double_update(&mut self, itr: i32, secondary: f64) {
        let id = self.idx_double_cache.kv_of(itr);
        self.db
            .modify::<IndexDoubleObject>(ObjectId::new(id), |e| e.secondary_key = secondary)
            .unwrap();
    }

    pub fn db_idx_double_remove(&mut self, itr: i32) {
        let id = self.idx_double_cache.kv_of(itr);
        let payer = self.idx_double(id).payer;
        self.bill(payer, -IDX_DOUBLE_OVERHEAD);
        self.db
            .remove::<IndexDoubleObject>(ObjectId::new(id))
            .unwrap();
    }

    pub fn db_idx_double_find_secondary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: f64,
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx_double_cache.cache_table(t_id);
        match self.idx_double_from(t_id, secondary, 0) {
            Some(e) if DoubleKey(e.secondary_key) == DoubleKey(secondary) => {
                *primary = e.primary_key;
                self.idx_double_cache.add(e.id().raw())
            }
            _ => end,
        }
    }

    pub fn db_idx_double_find_primary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut f64,
        primary: u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx_double_cache.cache_table(t_id);
        match self
            .db
            .find_by::<IndexDoubleObject, IdxDoubleByPrimary>(&(t_id, primary))
            .unwrap()
            .map(|e| (e.secondary_key, e.id().raw()))
        {
            Some((sec, id)) => {
                *secondary = sec;
                self.idx_double_cache.add(id)
            }
            None => end,
        }
    }

    pub fn db_idx_double_lowerbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut f64,
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx_double_cache.cache_table(t_id);
        match self.idx_double_from(t_id, *secondary, 0) {
            Some(e) => {
                *secondary = e.secondary_key;
                *primary = e.primary_key;
                self.idx_double_cache.add(e.id().raw())
            }
            None => end,
        }
    }

    pub fn db_idx_double_upperbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut f64,
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx_double_cache.cache_table(t_id);
        match self.idx_double_above(t_id, *secondary) {
            Some(e) => {
                *secondary = e.secondary_key;
                *primary = e.primary_key;
                self.idx_double_cache.add(e.id().raw())
            }
            None => end,
        }
    }

    pub fn db_idx_double_end(&mut self, code: u64, scope: u64, table: u64) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        self.idx_double_cache.cache_table(t_id)
    }

    pub fn db_idx_double_next(&mut self, itr: i32, primary: &mut u64) -> i32 {
        if itr < -1 {
            return itr;
        }
        let e = self.idx_double(self.idx_double_cache.kv_of(itr));
        match self.idx_double_after(e.t_id, e.secondary_key, e.primary_key) {
            Some(n) => {
                *primary = n.primary_key;
                self.idx_double_cache.add(n.id().raw())
            }
            None => self.idx_double_cache.end_iterator_of(e.t_id),
        }
    }

    pub fn db_idx_double_previous(&mut self, itr: i32, primary: &mut u64) -> i32 {
        if itr < -1 {
            let t_id = self.idx_double_cache.table_of_end_iterator(itr);
            return match self.idx_double_last(t_id) {
                Some(e) => {
                    *primary = e.primary_key;
                    self.idx_double_cache.add(e.id().raw())
                }
                None => -1,
            };
        }
        let e = self.idx_double(self.idx_double_cache.kv_of(itr));
        match self.idx_double_before(e.t_id, e.secondary_key, e.primary_key) {
            Some(p) => {
                *primary = p.primary_key;
                self.idx_double_cache.add(p.id().raw())
            }
            None => -1,
        }
    }

    // ----- idx_long_double (float128) ---------------------------------------

    fn idx_long_double(&self, id: i64) -> IndexLongDoubleObject {
        *self
            .db
            .get::<IndexLongDoubleObject>(ObjectId::new(id))
            .unwrap()
    }

    fn idx_long_double_from(
        &self,
        t_id: i64,
        sec: u128,
        prim: u64,
    ) -> Option<IndexLongDoubleObject> {
        self.db
            .table::<IndexLongDoubleObject>()
            .unwrap()
            .get_index::<IdxLongDoubleBySecondary>()
            .range((
                Bound::Included((t_id, LongDoubleKey::from_u128(sec), prim)),
                Bound::Unbounded,
            ))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx_long_double_above(&self, t_id: i64, sec: u128) -> Option<IndexLongDoubleObject> {
        self.db
            .table::<IndexLongDoubleObject>()
            .unwrap()
            .get_index::<IdxLongDoubleBySecondary>()
            .range((
                Bound::Excluded((t_id, LongDoubleKey::from_u128(sec), u64::MAX)),
                Bound::Unbounded,
            ))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx_long_double_after(
        &self,
        t_id: i64,
        sec: u128,
        prim: u64,
    ) -> Option<IndexLongDoubleObject> {
        self.db
            .table::<IndexLongDoubleObject>()
            .unwrap()
            .get_index::<IdxLongDoubleBySecondary>()
            .range((
                Bound::Excluded((t_id, LongDoubleKey::from_u128(sec), prim)),
                Bound::Unbounded,
            ))
            .next()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx_long_double_before(
        &self,
        t_id: i64,
        sec: u128,
        prim: u64,
    ) -> Option<IndexLongDoubleObject> {
        self.db
            .table::<IndexLongDoubleObject>()
            .unwrap()
            .get_index::<IdxLongDoubleBySecondary>()
            .range((
                Bound::Unbounded,
                Bound::Excluded((t_id, LongDoubleKey::from_u128(sec), prim)),
            ))
            .next_back()
            .filter(|(k, _)| k.0 == t_id)
            .map(|(_, o)| *o)
    }

    fn idx_long_double_last(&self, t_id: i64) -> Option<IndexLongDoubleObject> {
        self.db
            .table::<IndexLongDoubleObject>()
            .unwrap()
            .get_index::<IdxLongDoubleBySecondary>()
            .range((
                Bound::Included((t_id, LongDoubleKey::NEG_INF, u64::MIN)),
                Bound::Included((t_id, LongDoubleKey::POS_INF, u64::MAX)),
            ))
            .next_back()
            .map(|(_, o)| *o)
    }

    pub fn db_idx_long_double_store(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
        primary: u64,
        secondary: u128,
    ) -> i32 {
        let t_id = self.find_or_create_table(code, scope, table, payer);
        let (lo, hi) = u128_words(secondary);
        let id = self
            .db
            .create::<IndexLongDoubleObject>(|e| {
                e.t_id = t_id;
                e.primary_key = primary;
                e.sec_lo = lo;
                e.sec_hi = hi;
                e.payer = payer;
            })
            .unwrap()
            .id()
            .raw();
        self.bill(payer, IDX_LONG_DOUBLE_OVERHEAD);
        self.idx_long_double_cache.cache_table(t_id);
        self.idx_long_double_cache.add(id)
    }

    pub fn db_idx_long_double_update(&mut self, itr: i32, secondary: u128) {
        let id = self.idx_long_double_cache.kv_of(itr);
        let (lo, hi) = u128_words(secondary);
        self.db
            .modify::<IndexLongDoubleObject>(ObjectId::new(id), |e| {
                e.sec_lo = lo;
                e.sec_hi = hi;
            })
            .unwrap();
    }

    pub fn db_idx_long_double_remove(&mut self, itr: i32) {
        let id = self.idx_long_double_cache.kv_of(itr);
        let payer = self.idx_long_double(id).payer;
        self.bill(payer, -IDX_LONG_DOUBLE_OVERHEAD);
        self.db
            .remove::<IndexLongDoubleObject>(ObjectId::new(id))
            .unwrap();
    }

    pub fn db_idx_long_double_find_secondary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u128,
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx_long_double_cache.cache_table(t_id);
        match self.idx_long_double_from(t_id, secondary, 0) {
            Some(e)
                if LongDoubleKey::from_u128(e.secondary_key())
                    == LongDoubleKey::from_u128(secondary) =>
            {
                *primary = e.primary_key;
                self.idx_long_double_cache.add(e.id().raw())
            }
            _ => end,
        }
    }

    pub fn db_idx_long_double_find_primary(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u128,
        primary: u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx_long_double_cache.cache_table(t_id);
        match self
            .db
            .find_by::<IndexLongDoubleObject, IdxLongDoubleByPrimary>(&(t_id, primary))
            .unwrap()
            .map(|e| (e.secondary_key(), e.id().raw()))
        {
            Some((sec, id)) => {
                *secondary = sec;
                self.idx_long_double_cache.add(id)
            }
            None => end,
        }
    }

    pub fn db_idx_long_double_lowerbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u128,
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx_long_double_cache.cache_table(t_id);
        match self.idx_long_double_from(t_id, *secondary, 0) {
            Some(e) => {
                *secondary = e.secondary_key();
                *primary = e.primary_key;
                self.idx_long_double_cache.add(e.id().raw())
            }
            None => end,
        }
    }

    pub fn db_idx_long_double_upperbound(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u128,
        primary: &mut u64,
    ) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        let end = self.idx_long_double_cache.cache_table(t_id);
        match self.idx_long_double_above(t_id, *secondary) {
            Some(e) => {
                *secondary = e.secondary_key();
                *primary = e.primary_key;
                self.idx_long_double_cache.add(e.id().raw())
            }
            None => end,
        }
    }

    pub fn db_idx_long_double_end(&mut self, code: u64, scope: u64, table: u64) -> i32 {
        let Some(t_id) = self.find_table(code, scope, table) else {
            return -1;
        };
        self.idx_long_double_cache.cache_table(t_id)
    }

    pub fn db_idx_long_double_next(&mut self, itr: i32, primary: &mut u64) -> i32 {
        if itr < -1 {
            return itr;
        }
        let e = self.idx_long_double(self.idx_long_double_cache.kv_of(itr));
        match self.idx_long_double_after(e.t_id, e.secondary_key(), e.primary_key) {
            Some(n) => {
                *primary = n.primary_key;
                self.idx_long_double_cache.add(n.id().raw())
            }
            None => self.idx_long_double_cache.end_iterator_of(e.t_id),
        }
    }

    pub fn db_idx_long_double_previous(&mut self, itr: i32, primary: &mut u64) -> i32 {
        if itr < -1 {
            let t_id = self.idx_long_double_cache.table_of_end_iterator(itr);
            return match self.idx_long_double_last(t_id) {
                Some(e) => {
                    *primary = e.primary_key;
                    self.idx_long_double_cache.add(e.id().raw())
                }
                None => -1,
            };
        }
        let e = self.idx_long_double(self.idx_long_double_cache.kv_of(itr));
        match self.idx_long_double_before(e.t_id, e.secondary_key(), e.primary_key) {
            Some(p) => {
                *primary = p.primary_key;
                self.idx_long_double_cache.add(p.id().raw())
            }
            None => -1,
        }
    }
}
