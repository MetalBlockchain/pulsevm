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
    fn blob_ref_offsets() -> &'static [usize] {
        &[]
    }
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

// What damage to the log looks like, and what is done about it. A crash cuts a
// record short or leaves its tail unwritten; neither may be mistaken for state,
// and a record that was altered with intact data after it must not be skipped.

/// A log of three accepted blocks on a base checkpoint, and where each record
/// starts and ends.
fn three_block_log() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    Db,
    Vec<usize>,
) {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");
    let mut db = new_db();
    db.set_revision(1).unwrap();
    db.checkpoint(&snap).unwrap();
    accepted(&mut db, &wal, 2, 10);
    accepted(&mut db, &wal, 3, 20);
    accepted(&mut db, &wal, 4, 30);
    let data = std::fs::read(&wal).unwrap();
    let mut ends = Vec::new();
    let mut at = 8; // past the header
    while at < data.len() {
        let len = u64::from_le_bytes(data[at..at + 8].try_into().unwrap()) as usize;
        at += 8 + len + 32;
        ends.push(at);
    }
    (dir, snap, wal, db, ends)
}

fn recover(
    snap: &std::path::Path,
    wal: &std::path::Path,
) -> Result<(Db, pulsevm_arena::WalReplay), pulsevm_arena::DbError> {
    let mut recovered = new_db();
    recovered.load(snap).unwrap();
    let outcome = recovered.replay_log_after(wal, 1)?;
    Ok((recovered, outcome))
}

#[test]
fn a_log_cut_inside_its_last_record_loses_only_that_record() {
    let (_dir, snap, wal, mut db, ends) = three_block_log();
    let cut = ends[2] - 5; // the last five bytes never reached the file
    std::fs::OpenOptions::new()
        .write(true)
        .open(&wal)
        .unwrap()
        .set_len(cut as u64)
        .unwrap();
    let (recovered, outcome) = recover(&snap, &wal).unwrap();
    assert!(outcome.torn_tail);
    assert_eq!(outcome.frames_applied, 2);
    assert_eq!(outcome.valid_len, ends[1] as u64);
    assert_eq!(recovered.revision(), 3);
    // It is the state after two blocks, not a partial third.
    db.undo_all();
    let mut two = new_db();
    two.set_revision(1).unwrap();
    assert_ne!(recovered.state_root(), two.state_root());
}

#[test]
fn a_byte_flipped_in_the_middle_of_the_log_is_refused_not_applied() {
    let (_dir, snap, wal, _db, ends) = three_block_log();
    let mut data = std::fs::read(&wal).unwrap();
    let middle = (ends[0] + ends[1]) / 2; // inside the second record's payload
    data[middle] ^= 0x40;
    std::fs::write(&wal, &data).unwrap();
    let error = recover(&snap, &wal)
        .err()
        .expect("a damaged record must not replay");
    let text = format!("{error:?}");
    assert!(
        text.contains("fails its checksum") && text.contains("altered, not cut short"),
        "{text}"
    );
}

#[test]
fn a_byte_flipped_in_the_last_record_is_a_torn_write() {
    // Nothing follows it, so it is what a crash mid-write leaves: dropped, and
    // the node's block log (one block ahead) is rewound to match.
    let (_dir, snap, wal, _db, ends) = three_block_log();
    let mut data = std::fs::read(&wal).unwrap();
    let inside_last = (ends[1] + ends[2]) / 2;
    data[inside_last] ^= 0x40;
    std::fs::write(&wal, &data).unwrap();
    let (recovered, outcome) = recover(&snap, &wal).unwrap();
    assert!(outcome.torn_tail);
    assert_eq!(outcome.frames_applied, 2);
    assert_eq!(recovered.revision(), 3);
}

#[test]
fn a_zero_length_record_header_at_the_end_is_trimmed_not_hung_on() {
    let (_dir, snap, wal, _db, ends) = three_block_log();
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&wal).unwrap();
        f.write_all(&0u64.to_le_bytes()).unwrap();
    }
    let (recovered, outcome) = recover(&snap, &wal).unwrap();
    assert!(outcome.torn_tail);
    assert_eq!(outcome.valid_len, ends[2] as u64);
    assert_eq!(recovered.revision(), 4);
}

#[test]
fn a_full_length_all_zero_record_is_discarded_and_not_left_behind() {
    let (_dir, snap, wal, _db, ends) = three_block_log();
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&wal).unwrap();
        // A zero length, its (empty) payload, and a 32-byte digest of zeros: the
        // right size for a record, with no checksum that matches.
        f.write_all(&[0u8; 8 + 32]).unwrap();
    }
    let (_, outcome) = recover(&snap, &wal).unwrap();
    assert!(outcome.torn_tail, "it was not silently skipped");
    assert_eq!(outcome.valid_len, ends[2] as u64, "and it is trimmed away");

    // The same record with intact data after it is not a crash.
    let (_dir2, snap2, wal2, mut db, _) = three_block_log();
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal2)
            .unwrap();
        f.write_all(&[0u8; 8 + 32]).unwrap();
    }
    accepted(&mut db, &wal2, 5, 40);
    assert!(recover(&snap2, &wal2).is_err());
}

#[test]
fn a_log_from_before_records_were_checksummed_is_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");
    let mut db = new_db();
    db.set_revision(1).unwrap();
    db.checkpoint(&snap).unwrap();
    // The old layout: [len][payload], no header, no digest.
    let mut old = Vec::new();
    old.extend_from_slice(&16u64.to_le_bytes());
    old.extend_from_slice(&[7u8; 16]);
    std::fs::write(&wal, old).unwrap();
    let error = recover(&snap, &wal)
        .err()
        .expect("an old-format log must not be misread");
    assert!(format!("{error:?}").contains("not in the checksummed format"));
}

#[test]
fn a_header_cut_short_is_trimmed_and_the_next_append_starts_a_clean_log() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");
    let mut db = new_db();
    db.set_revision(1).unwrap();
    db.checkpoint(&snap).unwrap();
    std::fs::write(&wal, b"PVMW").unwrap();
    let (_, outcome) = recover(&snap, &wal).unwrap();
    assert!(outcome.torn_tail);
    assert_eq!(outcome.valid_len, 0);

    // What the node does: trim to the last good byte, then keep appending.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&wal)
        .unwrap()
        .set_len(0)
        .unwrap();
    accepted(&mut db, &wal, 2, 10);
    let (recovered, outcome) = recover(&snap, &wal).unwrap();
    assert!(!outcome.torn_tail);
    assert_eq!(recovered.revision(), 2);
}

// Replay applies one row at a time, but a block can move a unique key from one
// row to another: the live table did it in a safe order, and replay must not
// trip over the row it has not reached yet.
#[test]
fn replaying_a_block_that_swaps_unique_keys_between_rows_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");

    let mut db = new_db();
    let a = db.create::<Account>(|a| a.name = 1).unwrap().id;
    let b = db.create::<Account>(|a| a.name = 2).unwrap().id;
    db.set_revision(1).unwrap();
    db.checkpoint(&snap).unwrap();

    // One block: a goes first (it is the first row touched), via a temporary
    // key, so the table is never in conflict while it does this.
    db.start_undo_session();
    db.modify::<Account>(a, |x| x.name = 3).unwrap();
    db.modify::<Account>(b, |x| x.name = 1).unwrap();
    db.modify::<Account>(a, |x| x.name = 2).unwrap();
    db.commit(2);
    db.flush_delta(&wal).unwrap();

    let mut recovered = new_db();
    recovered.load(&snap).unwrap();
    let outcome = recovered.replay_log_after(&wal, 1).unwrap();
    assert_eq!(outcome.frames_applied, 1);
    assert_eq!(recovered.state_root(), db.state_root());
    assert_eq!(
        recovered
            .find_by::<Account, ByName>(&2)
            .unwrap()
            .unwrap()
            .id,
        a
    );
    assert_eq!(
        recovered
            .find_by::<Account, ByName>(&1)
            .unwrap()
            .unwrap()
            .id,
        b
    );
}

// The same with a row removed and another taking its key in one block.
#[test]
fn replaying_a_block_that_removes_a_row_and_reuses_its_key_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");

    let mut db = new_db();
    let a = db.create::<Account>(|a| a.name = 1).unwrap().id;
    let b = db.create::<Account>(|a| a.name = 2).unwrap().id;
    db.set_revision(1).unwrap();
    db.checkpoint(&snap).unwrap();

    db.start_undo_session();
    // b is touched first, then a is removed and b takes a's key.
    db.modify::<Account>(b, |x| x.value = 9).unwrap();
    db.remove::<Account>(a).unwrap();
    db.modify::<Account>(b, |x| x.name = 1).unwrap();
    db.commit(2);
    db.flush_delta(&wal).unwrap();

    let mut recovered = new_db();
    recovered.load(&snap).unwrap();
    recovered.replay_log_after(&wal, 1).unwrap();
    assert_eq!(recovered.state_root(), db.state_root());
}
