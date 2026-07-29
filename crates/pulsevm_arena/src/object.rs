use std::any::{Any, TypeId};
use std::collections::BTreeMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

/// Typed primary key of a stored object, the equivalent of chainbase `oid<T>`.
/// Ids are assigned sequentially by the table in insertion order and are never
/// reused unless the insertion that produced them is undone.
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

/// A type stored in a [`Table`]. The `by_id` index is built in; this trait only
/// declares the additional ordered-unique secondary indices.
///
/// The engine core keeps `T` as an ordinary owned value in the arena; the POD
/// layout required for mmap persistence is layered on later.
pub trait ArenaObject: Clone + Default + Send + 'static {
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
pub trait IndexedBy<T: ArenaObject>: 'static {
    type Key: Ord + Clone + Send + 'static;

    fn key(obj: &T) -> Self::Key;
}

/// Object-safe interface used by [`Table`] to maintain a secondary index
/// without knowing its key type.
pub trait SecondaryIndex<T: ArenaObject>: Send {
    fn tag(&self) -> TypeId;
    fn index_name(&self) -> &'static str;
    /// Inserts the object's key -> id in a single tree operation; returns
    /// `false` (index unchanged) if the key is already taken.
    fn try_insert(&mut self, obj: &T) -> bool;
    /// Moves the entry for `old` to `new`'s key; a no-op when the key is
    /// unchanged. Returns `false` (index unchanged) if `new`'s key is taken.
    fn replace(&mut self, old: &T, new: &T) -> bool;
    fn erase(&mut self, obj: &T);
    fn len(&self) -> usize;
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

    fn len(&self) -> usize {
        self.map.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
