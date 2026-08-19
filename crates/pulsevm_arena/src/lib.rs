//! A native Rust state store built to match EOS/Leap chainbase without the FFI.
//!
//! The design decision that makes this work — and makes persistence cheap
//! later — is that objects are addressed by **index, not pointer**. Each table
//! keeps its rows in one contiguous arena indexed by id (`Vec<Option<T>>`, the
//! slot number is the id), secondary indices map `key -> id`, and the undo
//! stack records values by id. Nothing holds an absolute address, so the state
//! is relocatable: it can be memory-mapped and read back regardless of where it
//! lands, the property chainbase gets from `offset_ptr` — but here for free,
//! because an index means the same thing everywhere.
//!
//! This crate is the engine core: [`Table`], its secondary indices, and the
//! full undo lifecycle. POD layout + mmap persistence and the multi-table
//! database layer build on top of it.

mod db;
mod object;
mod table;

pub use db::{
    Db,
    DbError,
};
pub use object::{
    ArenaObject,
    BlobRef,
    HashKeyIndex,
    IndexedBy,
    KeyIndex,
    ObjectId,
    SecondaryIndex,
    hash_index,
    key_index,
};
pub use table::{
    HashIndexView,
    IndexView,
    Table,
    TableError,
    UndoSessionChanges,
};

/// `#[derive(ArenaObject)]` — generates the trait impl and secondary-index
/// declarations. Re-exported so `use pulsevm_arena::ArenaObject` brings both the
/// trait and the derive into scope, as serde does.
pub use pulsevm_arena_derive::ArenaObject;
