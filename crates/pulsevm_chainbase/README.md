# pulsevm_chainbase

> [!WARNING]
> Work in progress — this crate is not used by the node yet. The chain still
> runs on the C++ chainbase via `pulsevm_ffi`; wiring this crate into
> `pulsevm_core` (porting the object types and swapping the FFI database) is
> still to be done, and APIs and the file format may change until then.

A pure-Rust recreation of EOS/Spring's [chainbase](../pulsevm_ffi/pulsevm/libraries/chainbase)
(the C++ original vendored under `pulsevm_ffi`): a transactional object
database where every object type gets a table with an auto-assigned primary id,
any number of ordered unique secondary indices, and an undo stack so groups of
changes (blocks / transactions / actions) can be reverted, squashed into the
enclosing session, or committed.

## Usage

```rust
use pulsevm_chainbase::*;
use pulsevm_proc_macros::{NumBytes, Read, Write};

#[derive(Clone, Default, NumBytes, Read, Write)]
struct AccountObject {
    id: ObjectId<AccountObject>,
    name: u64,
}

struct ByName;
impl IndexedBy<AccountObject> for ByName {
    type Key = u64;
    fn key(o: &AccountObject) -> u64 { o.name }
}

impl ChainbaseObject for AccountObject {
    const TYPE_ID: u16 = 1;
    fn id(&self) -> ObjectId<Self> { self.id }
    fn set_id(&mut self, id: ObjectId<Self>) { self.id = id; }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![key_index::<Self, ByName>()]
    }
}

// memory mapped and persistent; Database::new() gives a non-persistent one
let db = Database::open("state-dir", OpenFlags::ReadWrite, 1024 * 1024, false)?;
db.add_index::<AccountObject>()?; // loads the table if the file has one

let mut session = db.start_undo_session(true)?;
let account = db.create::<AccountObject>(|a| a.name = 42)?;
let found = db.get_by::<AccountObject, ByName>(&42)?;
db.modify(&found, |a| a.name = 43)?;
session.push(); // keep; dropping the session instead would revert everything
db.commit(db.revision())?;
```

`Database` is a cheap-to-clone, thread-safe handle (`Arc<RwLock<..>>`), so
sessions are owned values with C++-style RAII semantics: dropping an
unresolved `UndoSession` undoes its changes. Reads hand out clones; use
`Database::with_index` for by-reference iteration and range queries
(`lower_bound` / `upper_bound` / `range`).

## Persistence

`Database::open(dir, flags, size, allow_dirty)` memory-maps
`dir/shared_memory.bin` and follows chainbase's `pinnable_mapped_file`
lifecycle exactly:

- the file is **dirty** from the moment it is opened read-write until the
  last handle is dropped gracefully, which serializes the full state
  (rows, id counters, revisions and undo stacks) into the mapping and
  clears the flag;
- opening a dirty file (crash, or another process has it open) fails with
  `ChainbaseError::Dirty` unless `allow_dirty` is passed, which recovers
  the state from the last `flush()` or clean close — the same "discard and
  replay after a crash" model nodeos uses;
- `flush()` syncs the current state to disk without clearing the flag;
- `OpenFlags::ReadOnly` maps the file read-only and permanently rejects
  writes; registering a type the file does not contain is an error;
- tables present in the file but never re-registered with `add_index` are
  carried through unchanged, like unclaimed named objects in the C++
  segment.

Objects are serialized with the workspace's `pulsevm_serialization` binary
format (`#[derive(Read, Write, NumBytes)]` from `pulsevm_proc_macros`), which
`ChainbaseObject` requires.

## Divergences from the C++ original

- The live data structures reside in process memory and are serialized into
  the mapping on flush/close, rather than living inside the mapping via
  offset pointers. Crash-consistency semantics are identical (a crash leaves
  the file dirty either way); the differences are that open/close pay a
  serialize/deserialize pass and state must fit in RAM.
- The file grows automatically when the state outgrows it; the C++ segment
  is fixed-size and fails with `bad_alloc` until resized offline.
- `shared_cow_string` / `shared_cow_vector` are unnecessary — objects are
  plain `Clone` values.
- A `modify` that violates a uniqueness constraint returns an error and
  leaves the object unchanged (strong guarantee). C++ gives the basic
  guarantee: it reverts to an in-session backup if one exists, otherwise it
  *removes* the object.
- Errors are returned as `Result<_, ChainbaseError>` instead of thrown
  exceptions.

The test suite (`tests/undo_index_tests.rs`, `tests/database_tests.rs`) is a
port of the C++ `test/undo_index.cpp` and `test/test.cpp` behaviours;
`tests/persistence_tests.rs` covers the mapped-file lifecycle.

## Benchmarks

`cargo bench -p pulsevm_chainbase` runs a criterion suite
(`benches/chainbase.rs`) covering inserts, point lookups and range scans,
modifies (indexed and non-indexed fields), the per-transaction undo/squash
/push lifecycle, and persistence (`flush`, cold `open`). The insert and read
benches mirror `pulsevm_ffi/benches/{insert,read}.rs`, so the Rust and C++
FFI databases can be compared directly. HTML reports land in
`target/criterion/`.
