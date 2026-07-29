//! Differential-testing seam between chainbase (via `pulsevm_ffi::Database`) and
//! the native `pulsevm_arena` store.
//!
//! Chainbase stays the source of truth. When the `arena-shadow` feature is on,
//! the same mutations are replayed into an arena `Db` so a per-block state root
//! can be pulled off the arena and checked against chainbase as tables are
//! ported over one at a time. With the feature off nothing here touches the
//! arena — the shadow field does not exist and every method is a plain forward.
//!
//! Two pieces live here:
//!   - [`ShadowDb`], the arena handle the controller holds to drive the shared
//!     undo/commit lifecycle and read the state root at the accept boundary.
//!   - [`ShadowState`], the forward-and-mirror adapter that write sites migrate
//!     onto. It owns the `Database` handle they already use and, when shadowing
//!     is on, mirrors each mutation into the same arena. Only a representative
//!     slice is wired so far (see the TODO at the bottom).

use pulsevm_error::ChainError;
use pulsevm_ffi::{AccountMetadataObject, Database};

#[cfg(feature = "arena-shadow")]
pub use arena::ShadowDb;

/// Owns the chainbase handle and, under `arena-shadow`, a clone of the arena
/// handle to mirror into. Write sites move here from talking to `Database`
/// directly; the chainbase call is unchanged and the arena mirror is a trailing
/// side effect, so behaviour with the feature off is identical to today.
pub struct ShadowState {
    db: Database,
    #[cfg(feature = "arena-shadow")]
    shadow: Option<ShadowDb>,
}

impl ShadowState {
    /// Wraps a handle with no arena mirror — the shape a non-shadow build always
    /// gets.
    pub fn new(db: Database) -> Self {
        ShadowState {
            db,
            #[cfg(feature = "arena-shadow")]
            shadow: None,
        }
    }

    /// Wraps a handle and mirrors every wired mutation into `shadow`.
    #[cfg(feature = "arena-shadow")]
    pub fn with_shadow(db: Database, shadow: ShadowDb) -> Self {
        ShadowState {
            db,
            shadow: Some(shadow),
        }
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    pub fn database_mut(&mut self) -> &mut Database {
        &mut self.db
    }

    /// State root of the mirrored subset, or `None` when shadowing is off. Only
    /// the tables that have been ported contribute; until every mutation is
    /// mirrored this is not yet comparable byte-for-byte against chainbase.
    pub fn arena_state_root(&self) -> Option<[u8; 32]> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(ShadowDb::state_root)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    // ----- lifecycle: driven in lockstep with the chainbase session boundaries

    pub fn commit(&mut self, revision: i64) -> Result<(), ChainError> {
        self.db.commit(revision)?;
        #[cfg(feature = "arena-shadow")]
        if let Some(shadow) = &self.shadow {
            shadow.commit(revision);
        }
        Ok(())
    }

    pub fn undo(&mut self) -> Result<(), ChainError> {
        self.db.undo()?;
        #[cfg(feature = "arena-shadow")]
        if let Some(shadow) = &self.shadow {
            shadow.undo();
        }
        Ok(())
    }

    pub fn set_revision(&mut self, revision: i64) -> Result<(), ChainError> {
        self.db.set_revision(revision)?;
        #[cfg(feature = "arena-shadow")]
        if let Some(shadow) = &self.shadow {
            shadow
                .set_revision(revision)
                .map_err(|e| ChainError::InternalError(format!("arena set_revision: {e:?}")))?;
        }
        Ok(())
    }

    // ----- mutations (one wired as the pattern; the rest are TODO below) ------

    /// First mirrored write path: proves the forward-then-mirror shape end to
    /// end. chainbase remains authoritative; the arena copy is best-effort and
    /// its failure must not fail the block, so it is logged rather than raised.
    pub fn create_account_metadata(
        &mut self,
        account_name: u64,
        is_privileged: bool,
    ) -> Result<*const AccountMetadataObject, ChainError> {
        let res = self.db.create_account_metadata(account_name, is_privileged)?;
        #[cfg(feature = "arena-shadow")]
        if let Some(shadow) = &self.shadow
            && let Err(e) = shadow.mirror_create_account_metadata(account_name, is_privileged)
        {
            spdlog::warn!("arena mirror of account metadata {account_name} diverged: {e:?}");
        }
        Ok(res)
    }
}

#[cfg(feature = "arena-shadow")]
mod arena {
    use std::sync::{Arc, Mutex};

    use pulsevm_arena::{ArenaObject, Db, DbError, ObjectId};
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

    /// Arena mirror of chainbase `account_metadata_object`. The first table
    /// ported; the padding keeps the row free of implicit padding bytes so it
    /// round-trips through the arena's zero-copy layout.
    #[repr(C)]
    #[derive(
        Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout, ArenaObject,
    )]
    #[arena(type_id = 1)]
    struct AccountMetaRow {
        id: ObjectId<AccountMetaRow>,
        #[arena(index)]
        name: u64,
        privileged: u8,
        _pad: [u8; 7],
    }

    /// A cheaply cloned, `Send + Sync` handle to the shadow arena. The arena is
    /// single-threaded (`Db: !Sync`); the `Mutex` serialises the mirror calls,
    /// which is correct — chainbase access is already serialised by its own lock
    /// so no concurrency is lost. Never hold the guard across an `.await`.
    #[derive(Clone)]
    pub struct ShadowDb {
        inner: Arc<Mutex<Db>>,
    }

    impl ShadowDb {
        /// Registers every ported table. Grows as tables come online.
        pub fn new() -> Result<Self, DbError> {
            let mut db = Db::new();
            db.add_table::<AccountMetaRow>()?;
            Ok(ShadowDb {
                inner: Arc::new(Mutex::new(db)),
            })
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, Db> {
            self.inner.lock().expect("shadow arena mutex poisoned")
        }

        pub fn revision(&self) -> i64 {
            self.lock().revision()
        }

        pub fn set_revision(&self, revision: i64) -> Result<(), DbError> {
            self.lock().set_revision(revision)
        }

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

        pub fn mirror_create_account_metadata(
            &self,
            account_name: u64,
            is_privileged: bool,
        ) -> Result<(), DbError> {
            self.lock().create::<AccountMetaRow>(|row| {
                row.name = account_name;
                row.privileged = is_privileged as u8;
            })?;
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "arena-shadow"))]
mod tests {
    use super::ShadowDb;

    #[test]
    fn mirrored_write_changes_root_and_survives_commit() {
        let shadow = ShadowDb::new().unwrap();
        let empty = shadow.state_root();

        shadow.start_undo_session();
        shadow
            .mirror_create_account_metadata(0x1122_3344, true)
            .unwrap();
        let populated = shadow.state_root();
        assert_ne!(empty, populated, "mirrored write did not move the root");

        // Committing the open session keeps the live rows, so the root is stable
        // across the session boundary the controller drives at accept.
        shadow.commit(shadow.revision());
        assert_eq!(populated, shadow.state_root());
    }

    #[test]
    fn undo_reverts_a_mirrored_write() {
        let shadow = ShadowDb::new().unwrap();
        let empty = shadow.state_root();

        shadow.start_undo_session();
        shadow
            .mirror_create_account_metadata(0x55, false)
            .unwrap();
        shadow.undo();
        assert_eq!(empty, shadow.state_root());
    }
}
