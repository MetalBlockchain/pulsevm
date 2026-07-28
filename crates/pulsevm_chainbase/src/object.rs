use std::any::{Any, TypeId};
use std::collections::BTreeMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use pulsevm_serialization::{NumBytes, Read as SerRead, ReadError, Write as SerWrite, WriteError};

/// Typed primary key of a chainbase object, the equivalent of C++
/// `chainbase::oid<T>`. Ids are assigned sequentially by the index in order of
/// insertion; an id is only reused if the insertion that produced it is undone.
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
impl<T: ?Sized> fmt::Display for ObjectId<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}
impl<T: ?Sized> From<i64> for ObjectId<T> {
    fn from(raw: i64) -> Self {
        ObjectId::new(raw)
    }
}

// Serialized as the bare i64, so objects holding ids can derive the
// `pulsevm_serialization` traits.
impl<T: ?Sized> NumBytes for ObjectId<T> {
    fn num_bytes(&self) -> usize {
        self.raw.num_bytes()
    }
}
impl<T: ?Sized> SerWrite for ObjectId<T> {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.raw.write(bytes, pos)
    }
}
impl<T: ?Sized> SerRead for ObjectId<T> {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        i64::read(bytes, pos).map(ObjectId::new)
    }
}

/// A type stored in the database, the equivalent of deriving from C++
/// `chainbase::object<TypeNumber, Derived>` plus the index declaration that
/// `CHAINBASE_SET_INDEX_TYPE` associates with it.
///
/// The first index of every C++ multi-index is `by_id`; here the id map is
/// built in and [`ChainbaseObject::secondary_indices`] lists only the
/// additional ordered unique indices.
///
/// The `pulsevm_serialization` bounds make every object persistable; a
/// database file stores objects in that binary format (typically via
/// `#[derive(Read, Write, NumBytes)]` from `pulsevm_proc_macros`).
pub trait ChainbaseObject:
    Clone + Default + Send + Sync + SerRead + SerWrite + NumBytes + 'static
{
    /// Unique per-database table number (C++ `object::type_id`).
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

/// An ordered unique secondary index declaration, the equivalent of a
/// `boost::multi_index::ordered_unique<tag<Tag>, key<...>>` entry.
///
/// Implement this on an empty tag type (e.g. `struct ByName;`) and return the
/// index from [`ChainbaseObject::secondary_indices`] via [`key_index`]:
///
/// ```ignore
/// struct ByName;
/// impl IndexedBy<AccountObject> for ByName {
///     type Key = Name;
///     fn key(obj: &AccountObject) -> Name { obj.name }
/// }
/// ```
pub trait IndexedBy<T: ChainbaseObject>: 'static {
    type Key: Ord + Clone + Send + Sync + 'static;

    fn key(obj: &T) -> Self::Key;
}

/// Object-safe interface used by `UndoIndex` to maintain a secondary index
/// without knowing its key type.
pub trait SecondaryIndex<T: ChainbaseObject>: Send + Sync {
    fn tag(&self) -> TypeId;
    fn index_name(&self) -> &'static str;
    /// Inserts the object's key in a single tree operation; returns `false`
    /// (leaving the index unchanged) if the key is already taken.
    fn try_insert(&mut self, obj: &T) -> bool;
    /// Moves the entry for `old` to `new`'s key; a no-op when the key is
    /// unchanged. Returns `false` (leaving the index unchanged) if `new`'s
    /// key is taken.
    fn replace(&mut self, old: &T, new: &T) -> bool;
    fn erase(&mut self, obj: &T);
    fn clear(&mut self);
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn as_any(&self) -> &dyn Any;
}

/// Concrete secondary index: an ordered map from `Tag::Key` to object id.
pub struct KeyIndex<T: ChainbaseObject, Tag: IndexedBy<T>> {
    pub(crate) map: BTreeMap<Tag::Key, i64>,
    _marker: PhantomData<fn() -> (T, Tag)>,
}

/// Creates the boxed index registered from [`ChainbaseObject::secondary_indices`].
pub fn key_index<T: ChainbaseObject, Tag: IndexedBy<T>>() -> Box<dyn SecondaryIndex<T>> {
    Box::new(KeyIndex::<T, Tag> {
        map: BTreeMap::new(),
        _marker: PhantomData,
    })
}

impl<T: ChainbaseObject, Tag: IndexedBy<T>> SecondaryIndex<T> for KeyIndex<T, Tag> {
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

    fn clear(&mut self) {
        self.map.clear();
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
