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
    let mut at = 40; // past the header: 8 bytes of format and a 32-byte key
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
        text.contains("cannot be read") && text.contains("altered, not cut short"),
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

// Round 12. The checksum used to cover the payload but not the length in front of
// it, and "this record cannot be completed" was always read as "the log was cut
// short". A corrupted length in the middle of the file then made every valid
// record after it look like a torn tail, and they were deleted from the file.

/// Overwrite the length field of the record that starts at `start`.
fn corrupt_length_at(wal: &std::path::Path, start: usize, value: u64) {
    let mut data = std::fs::read(wal).unwrap();
    data[start..start + 8].copy_from_slice(&value.to_le_bytes());
    std::fs::write(wal, data).unwrap();
}

#[test]
fn a_corrupted_length_in_the_middle_refuses_and_leaves_the_file_alone() {
    let (_dir, snap, wal, _db, ends) = three_block_log();
    // The second record starts where the first ends. Make it claim to run far
    // past the end of the file, as a flipped high bit would.
    corrupt_length_at(&wal, ends[0], 1 << 40);
    let before = std::fs::read(&wal).unwrap();
    let error = recover(&snap, &wal)
        .err()
        .expect("valid records follow the damaged length, so this is not a torn tail");
    assert!(
        format!("{error:?}").contains("altered, not cut short"),
        "{error:?}"
    );
    assert_eq!(
        std::fs::read(&wal).unwrap(),
        before,
        "nothing is cut off while valid records follow"
    );

    // A smaller wrong length that still lands inside the file is the same.
    let (_dir2, snap2, wal2, _db2, ends2) = three_block_log();
    corrupt_length_at(&wal2, ends2[0], 3);
    assert!(recover(&snap2, &wal2).is_err());
}

#[test]
fn a_zero_filled_tail_of_any_length_is_trimmed() {
    // A filesystem that extends a file before the data lands leaves zeros. Paul
    // found that only exactly 40 bytes was handled; 41, 100 and 4096 stopped the
    // node as "altered".
    for zeros in [1usize, 7, 8, 39, 40, 41, 100, 4096, 70_000] {
        let (_dir, snap, wal, _db, ends) = three_block_log();
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(&wal).unwrap();
            f.write_all(&vec![0u8; zeros]).unwrap();
        }
        let (recovered, outcome) = recover(&snap, &wal)
            .unwrap_or_else(|error| panic!("{zeros} zero bytes must be trimmed: {error:?}"));
        assert!(outcome.torn_tail, "{zeros} zero bytes");
        assert_eq!(outcome.valid_len, ends[2] as u64, "{zeros} zero bytes");
        assert_eq!(recovered.revision(), 4, "{zeros} zero bytes");
    }
}

#[test]
fn a_record_cut_short_with_a_zero_filled_remainder_is_a_torn_tail() {
    // The shape a torn write usually has: the start of the next record, then
    // zeros where the rest was never written.
    let (_dir, snap, wal, mut db, ends) = three_block_log();
    accepted(&mut db, &wal, 5, 40);
    let data = std::fs::read(&wal).unwrap();
    let fifth_start = ends[2];
    let mut torn = data[..fifth_start + 20].to_vec(); // 20 bytes of the record
    torn.extend(vec![0u8; 500]);
    std::fs::write(&wal, torn).unwrap();
    let (recovered, outcome) = recover(&snap, &wal).unwrap();
    assert!(outcome.torn_tail);
    assert_eq!(outcome.valid_len, ends[2] as u64);
    assert_eq!(recovered.revision(), 4);
}

#[test]
fn garbage_after_the_last_good_record_is_trimmed_even_if_it_looks_like_a_length() {
    let (_dir, snap, wal, _db, ends) = three_block_log();
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&wal).unwrap();
        f.write_all(&(1u64 << 50).to_le_bytes()).unwrap();
        f.write_all(&[0xAB; 300]).unwrap();
    }
    let (_, outcome) = recover(&snap, &wal).unwrap();
    assert!(outcome.torn_tail);
    assert_eq!(outcome.valid_len, ends[2] as u64);
}

// Round 13. The checksum was a plain SHA-256 of the length and payload, and
// payloads carry contract row bytes verbatim, so anyone could store bytes that
// read as a valid record. Inside a torn final record that made the node refuse to
// start as "altered", one such row per block being enough to keep it from
// recovering without a manual fix. The checksum is now keyed with a random value
// kept in the file's header.

fn unkeyed_digest(len: u64, payload: &[u8]) -> [u8; 32] {
    use sha2::{
        Digest,
        Sha256,
    };
    let mut hasher = Sha256::new();
    hasher.update(len.to_le_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

#[test]
fn a_record_forged_inside_a_torn_one_does_not_make_the_tail_look_altered() {
    let (_dir, snap, wal, _db, ends) = three_block_log();
    // What an attacker can store in a row: a well-formed record as the old
    // checksum defined it (and as it would be if the key were guessed to be
    // empty).
    let inner_payload = [7u8; 16];
    let mut forged = Vec::new();
    forged.extend_from_slice(&(inner_payload.len() as u64).to_le_bytes());
    forged.extend_from_slice(&inner_payload);
    forged.extend_from_slice(&unkeyed_digest(16, &inner_payload));
    // A final record cut short: it claims far more than was written, and what was
    // written holds the forged record.
    let mut torn = Vec::new();
    torn.extend_from_slice(&(1u64 << 20).to_le_bytes());
    torn.extend_from_slice(&[0xCC; 33]);
    torn.extend_from_slice(&forged);
    torn.extend_from_slice(&[0xDD; 21]);
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&wal).unwrap();
        f.write_all(&torn).unwrap();
    }
    let (recovered, outcome) = recover(&snap, &wal)
        .unwrap_or_else(|error| panic!("a forged record must not block recovery: {error:?}"));
    assert!(outcome.torn_tail);
    assert_eq!(outcome.valid_len, ends[2] as u64);
    assert_eq!(recovered.revision(), 4);
}

#[test]
fn every_log_has_its_own_key() {
    let key_of = |wal: &std::path::Path| std::fs::read(wal).unwrap()[8..40].to_vec();
    let (_d1, _s1, wal1, _db1, _) = three_block_log();
    let (_d2, _s2, wal2, _db2, _) = three_block_log();
    assert_ne!(key_of(&wal1), key_of(&wal2), "keys are random per file");
    assert_ne!(key_of(&wal1), vec![0u8; 32]);
}

#[test]
fn a_record_copied_from_another_log_does_not_verify() {
    // The same blocks, written to two logs: the records differ because the keys do.
    let (_d1, snap, wal1, _db1, ends1) = three_block_log();
    let (_d2, _s2, wal2, _db2, ends2) = three_block_log();
    let donor = std::fs::read(&wal2).unwrap();
    let mut data = std::fs::read(&wal1).unwrap();
    // Overwrite the middle record with the donor's.
    data[ends1[0]..ends1[1]].copy_from_slice(&donor[ends2[0]..ends2[1]]);
    std::fs::write(&wal1, &data).unwrap();
    assert!(
        recover(&snap, &wal1).is_err(),
        "a record signed under a different key must not replay"
    );
}

#[test]
fn a_log_of_nothing_but_zeros_is_an_append_that_never_happened() {
    // The window opens once per fold: the log is removed and the next accept
    // creates it. A cut there left a file of zeros, refused as "written by an
    // earlier build".
    for zeros in [1usize, 7, 8, 39, 40, 41, 100, 4096] {
        let dir = tempfile::tempdir().unwrap();
        let snap = dir.path().join("state");
        let wal = dir.path().join("wal");
        let mut db = new_db();
        db.set_revision(1).unwrap();
        db.checkpoint(&snap).unwrap();
        std::fs::write(&wal, vec![0u8; zeros]).unwrap();
        let (recovered, outcome) = recover(&snap, &wal)
            .unwrap_or_else(|error| panic!("{zeros} zero bytes must be trimmed: {error:?}"));
        assert!(outcome.torn_tail, "{zeros}");
        assert_eq!(outcome.valid_len, 0, "{zeros}");
        assert_eq!(recovered.revision(), 1, "{zeros}");

        // What the node does: cut to the last good byte, then keep appending.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&wal)
            .unwrap()
            .set_len(outcome.valid_len)
            .unwrap();
        accepted(&mut db, &wal, 2, 10);
        let (recovered, outcome) = recover(&snap, &wal).unwrap();
        assert!(!outcome.torn_tail, "{zeros}");
        assert_eq!(recovered.revision(), 2, "{zeros}");
    }
}

#[test]
fn a_zero_header_followed_by_data_is_still_not_an_empty_log() {
    // Zeros are only "nothing happened" when nothing but zeros is there.
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");
    let mut db = new_db();
    db.set_revision(1).unwrap();
    db.checkpoint(&snap).unwrap();
    let mut data = vec![0u8; 48];
    data.extend_from_slice(&[1, 2, 3]);
    std::fs::write(&wal, data).unwrap();
    assert!(recover(&snap, &wal).is_err());
}

// The format name `getInfo` reports must be the one a log actually starts with,
// or a fleet check on it would be checking nothing.
#[test]
fn the_reported_wal_format_is_what_a_log_starts_with() {
    let (_dir, _snap, wal, _db, _ends) = three_block_log();
    let data = std::fs::read(&wal).unwrap();
    assert_eq!(&data[..8], pulsevm_arena::WAL_FORMAT.as_bytes());
}
