use std::{
    any::{
        Any,
        TypeId,
    },
    collections::{
        BTreeMap,
        HashMap,
    },
    fmt,
    hash::{
        Hash,
        Hasher,
    },
    marker::PhantomData,
};

use zerocopy::{
    FromBytes,
    Immutable,
    IntoBytes,
    KnownLayout,
};

/// Typed primary key of a stored object, the equivalent of chainbase `oid<T>`.
/// Ids are assigned sequentially by the table in insertion order and are never
/// reused unless the insertion that produced them is undone.
///
/// `repr(transparent)` over the raw id keeps it plain-old-data, so objects can
/// hold it and still be dumped to the arena as raw bytes.
#[repr(transparent)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ObjectId<T: ?Sized> {
    raw: i64,
    _marker: PhantomData<fn() -> T>,
}

impl<T: ?Sized> ObjectId<T> {
    pub const fn new(raw: i64) -> Self {
        ObjectId {
            raw,
            _marker: PhantomData,
        }
    }

    pub const fn raw(&self) -> i64 {
        self.raw
    }
}

// Manual impls so `ObjectId<T>` is Copy/Ord/... regardless of `T`.
impl<T: ?Sized> Clone for ObjectId<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T: ?Sized> Copy for ObjectId<T> {}
impl<T: ?Sized> Default for ObjectId<T> {
    fn default() -> Self {
        ObjectId::new(0)
    }
}
impl<T: ?Sized> PartialEq for ObjectId<T> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}
impl<T: ?Sized> Eq for ObjectId<T> {}
impl<T: ?Sized> PartialOrd for ObjectId<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T: ?Sized> Ord for ObjectId<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}
impl<T: ?Sized> Hash for ObjectId<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}
impl<T: ?Sized> fmt::Debug for ObjectId<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({})", self.raw)
    }
}
impl<T: ?Sized> From<i64> for ObjectId<T> {
    fn from(raw: i64) -> Self {
        ObjectId::new(raw)
    }
}

/// Reference into a table's blob arena, for a variable-length field on an
/// otherwise fixed-size object (chainbase's `shared_blob`). The bytes live in
/// the table's byte arena, addressed by offset — still pointer-free, so the
/// object stays POD. A default `BlobRef` is the empty slice.
#[repr(C)]
#[derive(
    Clone, Copy, Default, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub struct BlobRef {
    pub off: u32,
    pub len: u32,
}

/// A type stored in a [`Table`]. The `by_id` index is built in; this trait only
/// declares the additional ordered-unique secondary indices.
///
/// The engine core keeps `T` as an ordinary owned value in the arena; the POD
/// layout required for mmap persistence is layered on later.
pub trait ArenaObject:
    Copy + Default + Send + Sync + FromBytes + IntoBytes + Immutable + KnownLayout + 'static
{
    /// Unique per-database table number (chainbase `object::type_id`).
    const TYPE_ID: u16;

    fn id(&self) -> ObjectId<Self>;
    fn set_id(&mut self, id: ObjectId<Self>);

    /// Freshly constructed (empty) secondary indices for this type.
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        Vec::new()
    }

    fn type_name() -> &'static str {
        std::any::type_name::<Self>()
    }
}

/// An ordered-unique secondary index declaration, the equivalent of a
/// `boost::multi_index::ordered_unique<tag<Tag>, key<...>>` entry. Implement it
/// on an empty tag type and return the index from
/// [`ArenaObject::secondary_indices`] via [`key_index`].
pub trait IndexedBy<T: ArenaObject>: Send + Sync + 'static {
    type Key: Ord + Clone + Send + Sync + 'static;

    fn key(obj: &T) -> Self::Key;
}

/// Object-safe interface used by [`Table`] to maintain a secondary index
/// without knowing its key type.
pub trait SecondaryIndex<T: ArenaObject>: Send + Sync {
    fn tag(&self) -> TypeId;
    fn index_name(&self) -> &'static str;
    /// Inserts the object's key -> id in a single tree operation; returns
    /// `false` (index unchanged) if the key is already taken.
    fn try_insert(&mut self, obj: &T) -> bool;
    /// Moves the entry for `old` to `new`'s key; a no-op when the key is
    /// unchanged. Returns `false` (index unchanged) if `new`'s key is taken.
    fn replace(&mut self, old: &T, new: &T) -> bool;
    fn erase(&mut self, obj: &T);
    /// Rebuild the whole index from a table's live rows in one pass — the open
    /// path. Bulk-building (sort + bottom-up) is an order of magnitude cheaper
    /// than one `try_insert` per row, and index reconstruction dominates open.
    /// Returns `false` if two live rows share a key (a corrupt snapshot).
    fn bulk_build(&mut self, rows: &[(i64, T)]) -> bool;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn as_any(&self) -> &dyn Any;
}

/// Concrete secondary index: an ordered map from `Tag::Key` to object id.
pub struct KeyIndex<T: ArenaObject, Tag: IndexedBy<T>> {
    pub(crate) map: BTreeMap<Tag::Key, i64>,
    _marker: PhantomData<fn() -> (T, Tag)>,
}

/// Creates the boxed index registered from [`ArenaObject::secondary_indices`].
pub fn key_index<T: ArenaObject, Tag: IndexedBy<T>>() -> Box<dyn SecondaryIndex<T>> {
    Box::new(KeyIndex::<T, Tag> {
        map: BTreeMap::new(),
        _marker: PhantomData,
    })
}

impl<T: ArenaObject, Tag: IndexedBy<T>> SecondaryIndex<T> for KeyIndex<T, Tag> {
    fn tag(&self) -> TypeId {
        TypeId::of::<Tag>()
    }

    fn index_name(&self) -> &'static str {
        std::any::type_name::<Tag>()
    }

    fn try_insert(&mut self, obj: &T) -> bool {
        match self.map.entry(Tag::key(obj)) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(obj.id().raw());
                true
            }
            std::collections::btree_map::Entry::Occupied(_) => false,
        }
    }

    fn replace(&mut self, old: &T, new: &T) -> bool {
        let old_key = Tag::key(old);
        let new_key = Tag::key(new);
        if old_key == new_key {
            return true;
        }
        match self.map.entry(new_key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(old.id().raw());
            }
            std::collections::btree_map::Entry::Occupied(_) => return false,
        }
        let removed = self.map.remove(&old_key);
        debug_assert_eq!(
            removed,
            Some(old.id().raw()),
            "replaced entry did not belong to the object in index {}",
            self.index_name()
        );
        true
    }

    fn erase(&mut self, obj: &T) {
        let removed = self.map.remove(&Tag::key(obj));
        debug_assert_eq!(
            removed,
            Some(obj.id().raw()),
            "erased entry did not belong to the object in index {}",
            self.index_name()
        );
    }

    fn bulk_build(&mut self, rows: &[(i64, T)]) -> bool {
        // `BTreeMap::from_iter` sorts the pairs and builds the tree bottom-up,
        // far cheaper than inserting each row into an empty map. Row position is
        // the object id.
        let mut live = 0usize;
        self.map = rows
            .iter()
            .map(|(id, obj)| {
                live += 1;
                (Tag::key(obj), *id)
            })
            .collect();
        // Unique index: a dropped entry means two rows collided on a key.
        self.map.len() == live
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Unordered secondary index: a hash map from `Tag::Key` to object id. Use for
/// indexes that are only ever point-queried (`find`/`contains`) — it answers
/// those in O(1) instead of the BTree's O(log n). It supports no range/iteration
/// (a hash has no order), so [`IndexView`] panics if those are called on it.
pub struct HashKeyIndex<T: ArenaObject, Tag: IndexedBy<T>>
where
    Tag::Key: Hash + Eq,
{
    pub(crate) map: HashMap<Tag::Key, i64>,
    _marker: PhantomData<fn() -> (T, Tag)>,
}

/// Creates a hash-backed secondary index. `Tag::Key` must be `Hash + Eq` in
/// addition to the `Ord` that [`IndexedBy`] already requires.
pub fn hash_index<T: ArenaObject, Tag: IndexedBy<T>>() -> Box<dyn SecondaryIndex<T>>
where
    Tag::Key: Hash + Eq,
{
    Box::new(HashKeyIndex::<T, Tag> {
        map: HashMap::new(),
        _marker: PhantomData,
    })
}

impl<T: ArenaObject, Tag: IndexedBy<T>> SecondaryIndex<T> for HashKeyIndex<T, Tag>
where
    Tag::Key: Hash + Eq,
{
    fn tag(&self) -> TypeId {
        TypeId::of::<Tag>()
    }

    fn index_name(&self) -> &'static str {
        std::any::type_name::<Tag>()
    }

    fn try_insert(&mut self, obj: &T) -> bool {
        match self.map.entry(Tag::key(obj)) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(obj.id().raw());
                true
            }
            std::collections::hash_map::Entry::Occupied(_) => false,
        }
    }

    fn replace(&mut self, old: &T, new: &T) -> bool {
        let old_key = Tag::key(old);
        let new_key = Tag::key(new);
        if old_key == new_key {
            return true;
        }
        match self.map.entry(new_key) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(old.id().raw());
            }
            std::collections::hash_map::Entry::Occupied(_) => return false,
        }
        let removed = self.map.remove(&old_key);
        debug_assert_eq!(
            removed,
            Some(old.id().raw()),
            "replaced entry did not belong to the object in index {}",
            self.index_name()
        );
        true
    }

    fn erase(&mut self, obj: &T) {
        let removed = self.map.remove(&Tag::key(obj));
        debug_assert_eq!(
            removed,
            Some(obj.id().raw()),
            "erased entry did not belong to the object in index {}",
            self.index_name()
        );
    }

    fn bulk_build(&mut self, rows: &[(i64, T)]) -> bool {
        let mut live = 0usize;
        self.map = rows
            .iter()
            .map(|(id, obj)| {
                live += 1;
                (Tag::key(obj), *id)
            })
            .collect();
        self.map.len() == live
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
