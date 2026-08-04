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
