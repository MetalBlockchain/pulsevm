//! Native `pulsevm_arena` mirror carried inside [`crate::Database`], enabled by
//! the `arena-shadow` feature. Chainbase stays the source of truth; every
//! mutation that has been ported is replayed here so a per-block state root can
//! be pulled off the arena and compared as tables come online one at a time.
//!
//! The mirror lives in the `Database` wrapper (not in the controller) so that
//! every `Database` clone — and there is one per apply/transaction context —
//! shares the same arena through an `Arc`, and writes reach it with no change at
//! the call sites. The arena is single-threaded (`Db: !Sync`); the `Mutex`
//! serialises the mirror calls, which loses no concurrency because chainbase
//! access is already serialised by its own lock. Never hold the guard across an
//! `.await`.

use std::sync::{Arc, Mutex};

use pulsevm_arena::{ArenaObject, Db, DbError, ObjectId};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Arena mirror of chainbase `account_metadata_object` — the first table ported.
/// The trailing padding keeps the row free of implicit padding bytes so it
/// round-trips through the arena's zero-copy layout.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout, ArenaObject)]
#[arena(type_id = 1)]
struct AccountMetaRow {
    id: ObjectId<AccountMetaRow>,
    #[arena(index)]
    name: u64,
    privileged: u8,
    _pad: [u8; 7],
}

/// A cheaply cloned, `Send + Sync` handle to the shadow arena, held by
/// `Database` and shared across its clones.
#[derive(Clone)]
pub struct ArenaShadow {
    inner: Arc<Mutex<Db>>,
}

impl ArenaShadow {
    /// Registers every ported table. Grows as tables come online.
    pub fn new() -> Result<Self, DbError> {
        let mut db = Db::new();
        db.add_table::<AccountMetaRow>()?;
        Ok(ArenaShadow {
            inner: Arc::new(Mutex::new(db)),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Db> {
        self.inner.lock().expect("shadow arena mutex poisoned")
    }

    pub fn set_revision(&self, revision: i64) -> Result<(), DbError> {
        self.lock().set_revision(revision)
    }

    // Lifecycle, driven from the controller in lockstep with the chainbase
    // undo-session boundaries.
    pub fn start_undo_session(&self) {
        self.lock().start_undo_session();
    }
    pub fn squash(&self) {
        self.lock().squash();
    }
    pub fn undo(&self) {
        self.lock().undo();
    }
    pub fn commit(&self, revision: i64) {
        self.lock().commit(revision);
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.lock().state_root()
    }

    // ----- ported mutations -------------------------------------------------

    pub fn create_account_metadata(&self, name: u64, privileged: bool) -> Result<(), DbError> {
        self.lock().create::<AccountMetaRow>(|row| {
            row.name = name;
            row.privileged = privileged as u8;
        })?;
        Ok(())
    }
}
