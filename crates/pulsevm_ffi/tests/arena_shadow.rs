//! End-to-end check that a ported write reaches the arena mirror through the
//! real `Database` wrapper: chainbase does the write, and the arena shadow —
//! carried inside `Database` and shared across clones — receives the same
//! mutation, so its state root moves, an undo reverts it, and a commit keeps it.
//!
//! This exercises the mirror seam itself (write path + arena session lifecycle),
//! not yet the controller's nested build/verify/accept session stack, which is
//! where the remaining integration work lives.

#![cfg(feature = "arena-shadow")]

use pulsevm_ffi::Database;
use tempfile::tempdir;

const DB_SIZE: u64 = 8 * 1024 * 1024 * 1024;

#[test]
fn account_metadata_writes_mirror_into_the_arena() {
    let dir = tempdir().unwrap();
    let mut db = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
    db.add_indices().unwrap();
    db.enable_shadow().unwrap();

    let empty = db.arena_state_root().expect("shadow enabled");

    // A ported write moves the arena root...
    db.arena_start_undo_session();
    db.create_account_metadata(0x1111, false).unwrap();
    let one = db.arena_state_root().unwrap();
    assert_ne!(empty, one, "first mirrored write did not move the root");

    db.create_account_metadata(0x2222, true).unwrap();
    let two = db.arena_state_root().unwrap();
    assert_ne!(one, two, "second mirrored write did not move the root");

    // ...and undoing the session reverts both mirrored rows.
    db.arena_undo();
    assert_eq!(empty, db.arena_state_root().unwrap(), "undo did not revert the mirror");

    // A committed session keeps its rows.
    db.arena_start_undo_session();
    db.create_account_metadata(0x3333, false).unwrap();
    let kept = db.arena_state_root().unwrap();
    assert_ne!(empty, kept);
    db.arena_commit(i64::MAX);
    assert_eq!(kept, db.arena_state_root().unwrap(), "commit did not keep the mirror");
}

#[test]
fn shadow_is_absent_until_enabled() {
    let dir = tempdir().unwrap();
    let db = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
    assert!(db.arena_state_root().is_none(), "no shadow before enable_shadow");
}
