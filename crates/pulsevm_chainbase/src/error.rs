use std::fmt;

/// Errors reported by the chainbase database.
///
/// The C++ library throws `std::logic_error` / `std::out_of_range` /
/// `std::runtime_error`; this enum is the typed equivalent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainbaseError {
    /// An insert or modify would break an ordered-unique index.
    UniquenessViolation {
        type_name: &'static str,
        index_name: &'static str,
    },
    /// Lookup by key failed in a `get` style call (C++ `std::out_of_range`).
    UnknownKey { type_name: &'static str },
    /// The object referenced by id does not exist.
    NotFound { type_name: &'static str, id: i64 },
    /// `add_index` was called twice for the same `type_id`.
    TypeIdInUse { type_id: u16, type_name: &'static str },
    /// The object type was never registered with `add_index`.
    IndexNotRegistered { type_name: &'static str },
    /// A mutating operation was attempted while in read-only mode.
    ReadOnly { operation: &'static str },
    /// `set_revision` while an undo stack exists, decreasing revision, etc.
    Revision(String),
    /// A modifier callback changed the primary id of an object.
    IdChanged { type_name: &'static str },
    /// The database file was not closed gracefully (C++ "database dirty flag
    /// set"); it must be discarded or opened with `allow_dirty`.
    Dirty { path: String },
    /// Filesystem or memory-mapping failure.
    Io(String),
    /// Object (de)serialization failure while persisting or loading.
    Serialization(String),
    /// The database file content is not usable (bad magic/version, revision
    /// ranges out of sync, invalid index payload).
    Corrupted(String),
}

impl fmt::Display for ChainbaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainbaseError::UniquenessViolation {
                type_name,
                index_name,
            } => write!(
                f,
                "could not insert or modify object of type {type_name}, most likely a uniqueness constraint on index {index_name} was violated"
            ),
            ChainbaseError::UnknownKey { type_name } => {
                write!(f, "unknown key looking up object of type {type_name}")
            }
            ChainbaseError::NotFound { type_name, id } => {
                write!(f, "object of type {type_name} with id {id} not found")
            }
            ChainbaseError::TypeIdInUse { type_id, type_name } => {
                write!(f, "{type_name}::type_id {type_id} is already in use")
            }
            ChainbaseError::IndexNotRegistered { type_name } => {
                write!(f, "no index registered for object of type {type_name}")
            }
            ChainbaseError::ReadOnly { operation } => {
                write!(f, "attempting to {operation} in read-only mode")
            }
            ChainbaseError::Revision(msg) => write!(f, "{msg}"),
            ChainbaseError::IdChanged { type_name } => {
                write!(f, "modifier changed the id of an object of type {type_name}")
            }
            ChainbaseError::Dirty { path } => {
                write!(
                    f,
                    "database dirty flag set (not closed gracefully): {path}"
                )
            }
            ChainbaseError::Io(msg) => write!(f, "database io error: {msg}"),
            ChainbaseError::Serialization(msg) => {
                write!(f, "database serialization error: {msg}")
            }
            ChainbaseError::Corrupted(msg) => write!(f, "corrupted database: {msg}"),
        }
    }
}

impl std::error::Error for ChainbaseError {}
