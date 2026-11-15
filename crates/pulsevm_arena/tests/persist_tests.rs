//! Durable incremental persistence: checkpoint + write-ahead delta log,
//! revision restore, and crash recovery from a torn final frame.

use std::io::Write;

use pulsevm_arena::{
    ArenaObject,
    Db,
    IndexedBy,
    ObjectId,
    SecondaryIndex,
    key_index,
};

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Default,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
struct Account {
    id: ObjectId<Account>,
    name: u64,
    value: u64,
}
struct ByName;
impl IndexedBy<Account> for ByName {
    type Key = u64;
    fn key(a: &Account) -> u64 {
        a.name
    }
}
impl ArenaObject for Account {
    const TYPE_ID: u16 = 1;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![key_index::<Self, ByName>()]
    }
}

fn new_db() -> Db {
    let mut db = Db::new();
    db.add_table::<Account>().unwrap();
    db
}

#[test]
fn checkpoint_plus_delta_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");

    let mut db = new_db();
    for i in 0..100 {
        db.create::<Account>(|a| a.name = i).unwrap();
    }
    db.checkpoint(&snap).unwrap(); // baseline

    // Changes after the checkpoint go only to the delta log.
    db.create::<Account>(|a| a.name = 100).unwrap();
    db.modify::<Account>(ObjectId::new(50), |a| a.value = 999)
        .unwrap();
    db.remove::<Account>(ObjectId::new(10)).unwrap();
    db.flush_delta(&wal).unwrap();

    let mut r = new_db();
    r.load(&snap).unwrap();
    r.replay_log(&wal).unwrap();

    assert_eq!(r.table::<Account>().unwrap().len(), 100); // 100 + 1 - 1
    assert!(r.find::<Account>(ObjectId::new(10)).unwrap().is_none());
    assert_eq!(r.get::<Account>(ObjectId::new(50)).unwrap().value, 999);
    assert_eq!(
        r.find_by::<Account, ByName>(&100)
            .unwrap()
            .unwrap()
            .id
            .raw(),
        100
    );
    // Next id continues past the tombstone.
    assert_eq!(
        r.create::<Account>(|a| a.name = 5000).unwrap().id.raw(),
        101
    );
}

#[test]
fn multiple_delta_frames_replay_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");

    let mut db = new_db();
    db.checkpoint(&snap).unwrap(); // empty baseline

    for round in 0..5u64 {
        for i in 0..10u64 {
            db.create::<Account>(|a| a.name = round * 10 + i).unwrap();
        }
        db.flush_delta(&wal).unwrap();
    }

    let mut r = new_db();
    r.load(&snap).unwrap();
    r.replay_log(&wal).unwrap();
    assert_eq!(r.table::<Account>().unwrap().len(), 50);
    assert_eq!(
        r.find_by::<Account, ByName>(&37).unwrap().unwrap().id.raw(),
        37
    );
}

#[test]
fn revision_survives_reload() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");

    let mut db = new_db();
    db.start_undo_session();
    db.create::<Account>(|a| a.name = 1).unwrap();
    db.start_undo_session();
    db.create::<Account>(|a| a.name = 2).unwrap();
    assert_eq!(db.revision(), 2);
    db.checkpoint(&snap).unwrap();

    let mut r = new_db();
    r.load(&snap).unwrap();
    assert_eq!(r.revision(), 2);
    assert_eq!(r.table::<Account>().unwrap().len(), 2);
}

#[test]
fn state_root_is_stable_across_reload_and_sensitive_to_change() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");

    let mut db = new_db();
    for i in 0..100 {
        db.create::<Account>(|a| a.name = i).unwrap();
    }
    db.checkpoint(&snap).unwrap();
    db.modify::<Account>(ObjectId::new(7), |a| a.value = 1)
        .unwrap();
    db.remove::<Account>(ObjectId::new(3)).unwrap();
    db.flush_delta(&wal).unwrap();
    let root = db.state_root();

    // Reloading from disk reproduces the exact state root.
    let mut r = new_db();
    r.load(&snap).unwrap();
    r.replay_log(&wal).unwrap();
    assert_eq!(r.state_root(), root);

    // Any change moves the root.
    r.modify::<Account>(ObjectId::new(7), |a| a.value = 2)
        .unwrap();
    assert_ne!(r.state_root(), root);
}

#[test]
fn torn_final_frame_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");

    let mut db = new_db();
    db.checkpoint(&snap).unwrap();
    db.create::<Account>(|a| a.name = 1).unwrap();
    db.flush_delta(&wal).unwrap(); // one complete frame

    // Simulate a crash mid-write: a length prefix promising more than follows.
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&wal).unwrap();
        f.write_all(&9999u64.to_le_bytes()).unwrap();
        f.write_all(b"partial").unwrap();
        f.sync_all().unwrap();
    }

    let mut r = new_db();
    r.load(&snap).unwrap();
    r.replay_log(&wal).unwrap(); // must not error, must ignore the torn frame
    assert_eq!(r.table::<Account>().unwrap().len(), 1);
    assert_eq!(
        r.find_by::<Account, ByName>(&1).unwrap().unwrap().id.raw(),
        0
    );
}

// A node killed after some blocks restarts from its last checkpoint and the log
// of the blocks since. Each frame is one revision; replay must apply exactly
// the ones the checkpoint does not already contain.

fn accepted(db: &mut Db, wal: &std::path::Path, revision: i64, name: u64) {
    db.create::<Account>(|a| a.name = name).unwrap();
    db.set_revision(revision).unwrap();
    db.flush_delta(wal).unwrap();
}

#[test]
fn replay_after_a_checkpoint_applies_only_the_frames_that_follow_it() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");

    let mut db = new_db();
    db.set_revision(1).unwrap();
    db.checkpoint(&snap).unwrap();
    accepted(&mut db, &wal, 2, 10);
    accepted(&mut db, &wal, 3, 20);
    accepted(&mut db, &wal, 4, 30);

    let mut recovered = new_db();
    recovered.load(&snap).unwrap();
    let outcome = recovered.replay_log_after(&wal, 1).unwrap();
    assert_eq!(outcome.frames_applied, 3);
    assert_eq!(outcome.frames_skipped, 0);
    assert!(!outcome.torn_tail);
    assert_eq!(recovered.revision(), 4);
    assert_eq!(recovered.state_root(), db.state_root());
}

#[test]
fn a_log_older_than_the_checkpoint_is_skipped_not_reapplied() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");

    let mut db = new_db();
    db.set_revision(1).unwrap();
    db.checkpoint(&snap).unwrap();
    accepted(&mut db, &wal, 2, 10);
    accepted(&mut db, &wal, 3, 20);
    // A newer checkpoint landed but the process died before it removed the log.
    db.checkpoint(&snap).unwrap();

    let mut recovered = new_db();
    recovered.load(&snap).unwrap();
    let outcome = recovered.replay_log_after(&wal, 3).unwrap();
    assert_eq!(outcome.frames_applied, 0);
    assert_eq!(outcome.frames_skipped, 2);
    assert_eq!(recovered.revision(), 3);
    assert_eq!(recovered.state_root(), db.state_root());

    // Frames that follow the new checkpoint still apply on top.
    accepted(&mut db, &wal, 4, 30);
    let mut again = new_db();
    again.load(&snap).unwrap();
    let outcome = again.replay_log_after(&wal, 3).unwrap();
    assert_eq!((outcome.frames_applied, outcome.frames_skipped), (1, 2));
    assert_eq!(again.state_root(), db.state_root());
}

#[test]
fn a_missing_frame_is_refused_rather_than_replayed_over() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");

    let mut db = new_db();
    db.set_revision(1).unwrap();
    db.checkpoint(&snap).unwrap();
    accepted(&mut db, &wal, 2, 10);
    // Revision 3 never reached the log.
    db.set_revision(3).unwrap();
    accepted(&mut db, &wal, 4, 30);

    let mut recovered = new_db();
    recovered.load(&snap).unwrap();
    let error = recovered.replay_log_after(&wal, 1).unwrap_err();
    assert!(
        format!("{error:?}").contains("jumps from revision 2 to 4"),
        "{error:?}"
    );

    // A log that starts after a gap from the checkpoint is refused the same way.
    let mut late = new_db();
    late.load(&snap).unwrap();
    let error = late.replay_log_after(&wal, 0).unwrap_err();
    assert!(format!("{error:?}").contains("jumps"), "{error:?}");
}

#[test]
fn a_torn_tail_is_reported_with_where_the_good_records_end() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");

    let mut db = new_db();
    db.set_revision(1).unwrap();
    db.checkpoint(&snap).unwrap();
    accepted(&mut db, &wal, 2, 10);
    let good_len = std::fs::metadata(&wal).unwrap().len();
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&wal).unwrap();
        f.write_all(&(1u64 << 40).to_le_bytes()).unwrap();
        f.write_all(b"cut short").unwrap();
    }

    let mut recovered = new_db();
    recovered.load(&snap).unwrap();
    let outcome = recovered.replay_log_after(&wal, 1).unwrap();
    assert!(outcome.torn_tail);
    assert_eq!(outcome.valid_len, good_len);
    assert_eq!(outcome.frames_applied, 1);
    assert_eq!(recovered.state_root(), db.state_root());
}

#[test]
fn replaying_a_log_that_does_not_exist_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = new_db();
    let outcome = db.replay_log_after(dir.path().join("absent"), 5).unwrap();
    assert_eq!(outcome.frames_applied + outcome.frames_skipped, 0);
    assert!(!outcome.torn_tail);
}
