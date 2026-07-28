//! A Rust recreation of EOS/Spring's `chainbase` library
//! (`pulsevm_ffi/pulsevm/libraries/chainbase`).
//!
//! Chainbase is a transactional object database: each object type lives in its
//! own table with an auto-assigned primary id and any number of ordered unique
//! secondary indices, and every table maintains an undo stack so that groups of
//! changes (blocks, transactions, actions) can be reverted, merged into their
//! parent session ("squash") or made permanent ("commit").
//!
//! Mapping from the C++ library:
//!
//! | C++                                   | Rust                                   |
//! |---------------------------------------|----------------------------------------|
//! | `chainbase::oid<T>`                   | [`ObjectId<T>`]                        |
//! | `chainbase::object<TypeNumber, T>`    | [`ChainbaseObject`] trait              |
//! | `ordered_unique<tag<Tag>, key<...>>`  | [`IndexedBy`] impl on a tag type       |
//! | `chainbase::undo_index` / `generic_index` | [`UndoIndex<T>`]                   |
//! | `chainbase::database`                 | [`Database`]                           |
//! | `chainbase::database::session`        | [`UndoSession`]                        |
//!
//! Persistence is a memory mapped file with chainbase's exact lifecycle
//! ([`Database::open`], `flush`, dirty flag while open read-write, cleared
//! only by a graceful close, `allow_dirty` recovery) — see the README. The
//! live containers reside in process memory and are serialized into the
//! mapping on flush/close instead of living inside it via offset pointers, so
//! `shared_cow_string` and friends are plain `String`/`Vec` and objects are
//! `Clone` values encoded with `pulsevm_serialization`. Undo semantics,
//! session push/squash/undo behaviour, revision management and uniqueness
//! guarantees follow the original. One deliberate divergence: a `modify` that
//! violates a uniqueness constraint fails with an error and leaves the object
//! unchanged (strong guarantee), where C++ falls back to removing the object
//! when no in-session backup exists.

mod database;
mod error;
mod mapped_file;
mod object;
mod undo_index;

pub use database::{Database, OpenFlags, UndoSession};
pub use error::ChainbaseError;
pub use object::{ChainbaseObject, IndexedBy, KeyIndex, ObjectId, SecondaryIndex, key_index};
pub use undo_index::{IndexView, UndoIndex};
