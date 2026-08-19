//! End-to-end tests of the chain-database system objects (accounts, account
//! metadata, permissions, auth links, resource limits, RAM usage, transaction
//! dedup, sequences) exercised through the public `ChainDatabase` API — the
//! surface that, before this crate was split out of `pulsevm_database`, could only be
//! validated by the C++ differential harness. Here it is checked directly:
//! writes land, reads reflect them, and — crucially for consensus — `undo`
//! reverts and `commit` persists the whole set together.

use pulsevm_chaindb::ChainDatabase;

fn db() -> ChainDatabase {
    ChainDatabase::new().unwrap()
}

/// A minimal authority blob whose first four little-endian bytes are the
/// threshold, which is all `permission()` decodes back out.
fn auth(threshold: u32) -> Vec<u8> {
    let mut v = threshold.to_le_bytes().to_vec();
    v.extend_from_slice(&[0u8; 8]); // trailing bytes are ignored by the reader
    v
}

#[test]
fn accounts_and_metadata_create_and_read_back() {
    let s = db();
    assert!(!s.account_exists(1));
    s.create_account(1, 100).unwrap();
    s.create_account_metadata(1, false).unwrap();
    assert!(s.account_exists(1));
    assert_eq!(s.account_metadata_privileged(1), Some(false));

    s.set_privileged(1, true).unwrap();
    assert_eq!(s.account_metadata_privileged(1), Some(true));

    // An account that was never created reads back as absent.
    assert!(!s.account_exists(2));
    assert_eq!(s.account_metadata_privileged(2), None);
}

#[test]
fn permission_create_modify_remove() {
    let s = db();
    s.create_permission(5, -1, 1, 100, 0, &auth(1)).unwrap();
    // permission() -> (parent, threshold)
    assert_eq!(s.permission(1, 100), Some((-1, 1)));

    s.modify_permission(1, 100, &auth(3), 50).unwrap();
    assert_eq!(s.permission(1, 100), Some((-1, 3)), "threshold updated");

    s.remove_permission(1, 100).unwrap();
    assert_eq!(s.permission(1, 100), None);
}

#[test]
fn permission_satisfies_walks_parent_chain() {
    let s = db();
    // A tree for owner 1: a(id 1, root) -> b(id 2) -> c(id 3). Parent links are
    // chainbase ids; the root's parent is 0.
    let (a, b, c) = (100u64, 101u64, 102u64);
    s.create_permission(1, 0, 1, a, 0, &auth(1)).unwrap();
    s.create_permission(2, 1, 1, b, 0, &auth(1)).unwrap();
    s.create_permission(3, 2, 1, c, 0, &auth(1)).unwrap();

    // Self and immediate parent.
    assert_eq!(s.permission_satisfies(1, a, 1, a), Some(true));
    assert_eq!(s.permission_satisfies(1, b, 1, c), Some(true));
    // Ancestor two hops up (the walk).
    assert_eq!(s.permission_satisfies(1, a, 1, c), Some(true));
    // A descendant does not satisfy its ancestor.
    assert_eq!(s.permission_satisfies(1, c, 1, a), Some(false));
    assert_eq!(s.permission_satisfies(1, c, 1, b), Some(false));
    // A different owner never satisfies.
    assert_eq!(s.permission_satisfies(2, a, 1, c), None);
    // Absent permissions read back as None.
    assert_eq!(s.permission_satisfies(1, a, 1, 999), None);
}

#[test]
fn auth_links_link_and_unlink() {
    let s = db();
    // link_auth(account, code, message_type, required_permission)
    s.link_auth(1, 200, 300, 400).unwrap();
    s.link_auth(1, 100, 500, 300).unwrap();
    s.link_auth(2, 999, 999, 300).unwrap();
    assert_eq!(s.permission_link(1, 200, 300), Some(400));
    assert_eq!(
        s.permission_links_of(1),
        vec![(300, 100, 500), (400, 200, 300)]
    );

    s.unlink_auth(1, 200, 300).unwrap();
    assert_eq!(s.permission_link(1, 200, 300), None);
    assert_eq!(s.permission_links_of(1), vec![(300, 100, 500)]);
}

#[test]
fn resource_limits_pending_then_commit() {
    let s = db();
    s.initialize_account_resource_limits(1).unwrap();
    // Freshly initialized: committed row is "unlimited" (-1, -1, -1).
    assert_eq!(s.account_limits(1), Some((-1, -1, -1)));
    assert_eq!(s.account_ram_usage(1), Some(0));

    // set_account_limits stages a *pending* row; the effective read reflects it.
    s.set_account_limits(1, 1024, 10, 20).unwrap();
    assert_eq!(s.account_limits(1), Some((1024, 10, 20)));

    // Committing folds pending onto the committed row and drops the pending one;
    // the effective read is unchanged.
    s.process_account_limit_updates().unwrap();
    assert_eq!(s.account_limits(1), Some((1024, 10, 20)));
}

#[test]
fn ram_usage_accumulates_and_reverts_signed() {
    let s = db();
    s.initialize_account_resource_limits(1).unwrap();
    s.add_pending_ram_usage(1, 500).unwrap();
    assert_eq!(s.account_ram_usage(1), Some(500));
    s.add_pending_ram_usage(1, -200).unwrap();
    assert_eq!(s.account_ram_usage(1), Some(300));
    // A zero delta is a no-op.
    s.add_pending_ram_usage(1, 0).unwrap();
    assert_eq!(s.account_ram_usage(1), Some(300));
}

#[test]
fn transaction_dedup_and_expiry() {
    let s = db();
    let a = [1u8; 32];
    let b = [2u8; 32];
    assert!(!s.transaction_exists(a));
    s.record_transaction(a, 100).unwrap();
    s.record_transaction(b, 300).unwrap();
    assert!(s.transaction_exists(a));
    assert!(s.transaction_exists(b));

    // Clear everything expiring at or before 200: `a` (exp 100) goes, `b` stays.
    // clear_expired_input_transactions takes a microseconds cutoff; expirations
    // are seconds, so scale.
    s.clear_expired_input_transactions(200 * 1_000_000).unwrap();
    assert!(!s.transaction_exists(a));
    assert!(s.transaction_exists(b));
}

#[test]
fn global_action_sequence_roundtrips() {
    let s = db();
    s.set_global_action_sequence(42).unwrap();
    assert_eq!(s.global_action_sequence(), Some(42));
}

#[test]
fn undo_reverts_a_whole_session_across_tables() {
    let s = db();
    s.create_account(1, 100).unwrap();
    s.create_account_metadata(1, false).unwrap();
    let root_before = s.state_root();

    // A session that touches several tables.
    s.start_undo_session();
    s.create_account(2, 100).unwrap();
    s.create_permission(6, -1, 2, 100, 0, &auth(1)).unwrap();
    s.set_privileged(1, true).unwrap();
    assert!(s.account_exists(2));
    assert_eq!(s.permission(2, 100), Some((-1, 1)));
    assert_eq!(s.account_metadata_privileged(1), Some(true));
    assert_ne!(s.state_root(), root_before);

    // Undo rolls every table back together.
    s.undo();
    assert!(!s.account_exists(2));
    assert_eq!(s.permission(2, 100), None);
    assert_eq!(s.account_metadata_privileged(1), Some(false));
    assert_eq!(
        s.state_root(),
        root_before,
        "undo restores the exact prior state root"
    );
}

#[test]
fn commit_keeps_changes_and_drops_the_undo_history() {
    let s = db();
    s.start_undo_session();
    s.create_account(1, 100).unwrap();
    s.create_account_metadata(1, true).unwrap();
    let rev = s.state_root();
    // Commit at the current revision (1) discards the undo record but keeps state.
    s.commit(1);
    assert!(s.account_exists(1));
    assert_eq!(s.account_metadata_privileged(1), Some(true));
    assert_eq!(s.state_root(), rev);
}

#[test]
fn checkpoint_and_reload_preserve_state_root() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("pulsevm_chaindb_ckpt_{}.bin", std::process::id()));

    let s = db();
    s.create_account(1, 100).unwrap();
    s.create_account_metadata(1, false).unwrap();
    s.create_permission(7, -1, 1, 100, 0, &auth(2)).unwrap();
    s.initialize_account_resource_limits(1).unwrap();
    s.set_account_limits(1, 4096, 5, 6).unwrap();
    let root = s.state_root();

    s.checkpoint(&path).unwrap();

    // A fresh database loads the checkpoint to an identical logical state.
    let s2 = db();
    s2.load(&path).unwrap();
    assert_eq!(s2.state_root(), root);
    assert!(s2.account_exists(1));
    assert_eq!(s2.permission(1, 100), Some((-1, 2)));
    assert_eq!(s2.account_limits(1), Some((4096, 5, 6)));

    // reload_from restarts the same handle in place from disk.
    let s3 = db();
    s3.create_account(9, 1).unwrap(); // dirty it first
    s3.reload_from(&path).unwrap();
    assert_eq!(s3.state_root(), root);
    assert!(!s3.account_exists(9), "reload discards pre-reload state");

    let _ = std::fs::remove_file(&path);
}
