//! A node that restarts must not disagree with one that never stopped.
//!
//! Every other persistence test compares a database with its own copy. This one
//! runs the same random workload against a reference that never restarts and a
//! subject that is restarted at random points, cleanly (checkpoint, then load) or
//! as after a kill (older checkpoint plus the write-ahead log), and requires the
//! state root to match after every block. A root that depends on where blobs sit
//! in the arena, or on a free list a restart loses, fails here at the first
//! restart; it is what made five live nodes show five different roots.

use pulsevm_arena::{
    ArenaObject,
    BlobRef,
    Db,
    ObjectId,
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
    ArenaObject,
)]
#[arena(type_id = 11)]
struct Doc {
    id: ObjectId<Doc>,
    #[arena(index)]
    key: u64,
    counter: u32,
    _pad: u32,
    payload: BlobRef,
    note: BlobRef,
}

fn new_db() -> Db {
    let mut db = Db::new();
    db.add_table::<Doc>().unwrap();
    db
}

/// Deterministic xorshift, so a failing seed reproduces.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// One operation, described independent of any database so both get the same.
enum Op {
    Create {
        key: u64,
        payload: Vec<u8>,
        note: Vec<u8>,
    },
    Rewrite {
        slot: u64,
        payload: Vec<u8>,
        note: Option<Vec<u8>>,
    },
    Remove {
        slot: u64,
    },
}

fn apply(db: &mut Db, op: &Op) {
    match op {
        Op::Create { key, payload, note } => {
            let payload = db.alloc_blob::<Doc>(payload).unwrap();
            let note = db.alloc_blob::<Doc>(note).unwrap();
            db.create::<Doc>(|d| {
                d.key = *key;
                d.payload = payload;
                d.note = note;
            })
            .unwrap();
        }
        Op::Rewrite {
            slot,
            payload,
            note,
        } => {
            let Some(id) = pick(db, *slot) else { return };
            let row = *db.get::<Doc>(id).unwrap();
            let payload = db.realloc_blob::<Doc>(row.payload, payload).unwrap();
            let note = match note {
                Some(bytes) => db.realloc_blob::<Doc>(row.note, bytes).unwrap(),
                None => row.note,
            };
            db.modify::<Doc>(id, |d| {
                d.payload = payload;
                d.note = note;
                d.counter += 1;
            })
            .unwrap();
        }
        Op::Remove { slot } => {
            let Some(id) = pick(db, *slot) else { return };
            let row = *db.get::<Doc>(id).unwrap();
            db.free_blob::<Doc>(row.payload).unwrap();
            db.free_blob::<Doc>(row.note).unwrap();
            db.remove::<Doc>(id).unwrap();
        }
    }
}

/// The live row `slot` selects, by position among live ids, so the same slot
/// names the same row in two databases that hold the same logical rows.
fn pick(db: &Db, slot: u64) -> Option<ObjectId<Doc>> {
    let live: Vec<ObjectId<Doc>> = (0..512)
        .map(ObjectId::<Doc>::new)
        .filter(|id| db.get::<Doc>(*id).is_ok())
        .collect();
    if live.is_empty() {
        None
    } else {
        Some(live[(slot % live.len() as u64) as usize])
    }
}

fn random_ops(rng: &mut Rng, next_key: &mut u64) -> Vec<Op> {
    let mut ops = Vec::new();
    for _ in 0..1 + rng.below(5) {
        // Few distinct lengths, so freed spans are often reused exactly, which is
        // the case a lost free list changes.
        let payload_len = [0usize, 4, 8, 8, 16][rng.below(5) as usize];
        let payload = rng.bytes(payload_len);
        let note_len = [0usize, 4, 12][rng.below(3) as usize];
        let note = rng.bytes(note_len);
        let replace_note = rng.below(3) == 0;
        ops.push(match rng.below(10) {
            0..=3 => {
                *next_key += 1;
                Op::Create {
                    key: *next_key,
                    payload,
                    note,
                }
            }
            4..=8 => Op::Rewrite {
                slot: rng.next(),
                payload,
                note: replace_note.then_some(note),
            },
            _ => Op::Remove { slot: rng.next() },
        });
    }
    ops
}

/// Run one block on `db` the way a node does: a session, the operations, then
/// commit that session (it is not squashed away: the revision it opened is the
/// block's).
fn block(db: &mut Db, ops: &[Op], revision: i64) {
    let opened = db.start_undo_session();
    assert_eq!(opened, revision, "the session opens the block's revision");
    for op in ops {
        apply(db, op);
    }
    db.commit(revision);
}

struct Subject {
    dir: tempfile::TempDir,
    db: Db,
    checkpoint_revision: i64,
}

impl Subject {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut db = new_db();
        db.set_revision(1).unwrap();
        db.checkpoint(dir.path().join("state")).unwrap();
        Subject {
            dir,
            db,
            checkpoint_revision: 1,
        }
    }

    fn state(&self) -> std::path::PathBuf {
        self.dir.path().join("state")
    }

    fn wal(&self) -> std::path::PathBuf {
        self.dir.path().join("wal")
    }

    /// Accepting a block makes it durable in the log, as the node does.
    fn accepted(&mut self) {
        self.db.flush_delta(self.wal()).unwrap();
    }

    /// A clean stop and start: fold the log into a new checkpoint, then load it.
    fn clean_restart(&mut self) {
        self.db.checkpoint(self.state()).unwrap();
        let _ = std::fs::remove_file(self.wal());
        self.checkpoint_revision = self.db.revision();
        let mut fresh = new_db();
        fresh.load(self.state()).unwrap();
        self.db = fresh;
    }

    /// A kill: nothing is folded. The process comes back from the checkpoint it
    /// last wrote plus whatever reached the log.
    fn crash_restart(&mut self) {
        let mut fresh = new_db();
        fresh.load(self.state()).unwrap();
        let replay = fresh
            .replay_log_after(self.wal(), self.checkpoint_revision)
            .unwrap();
        assert!(!replay.torn_tail);
        self.db = fresh;
    }
}

#[test]
fn a_restarted_database_keeps_the_root_of_one_that_never_stopped() {
    for seed in 1..=12u64 {
        let mut rng = Rng(0x9e3779b97f4a7c15 ^ seed.wrapping_mul(0x2545f4914f6cdd1d));
        let mut reference = new_db();
        reference.set_revision(1).unwrap();
        let mut subject = Subject::new();
        let mut next_key = 0u64;

        for round in 0..80i64 {
            let revision = 2 + round;
            // Sometimes a block is built and thrown away first (a rejected or
            // failed block): it opens a session, writes, and is undone. Row ids
            // it used are handed out again and its rows were marked dirty, which
            // is where a stale mark or a reused id would show in the log.
            if rng.below(5) == 0 {
                let mut scratch_key = next_key;
                let aborted = random_ops(&mut rng, &mut scratch_key);
                for db in [&mut reference, &mut subject.db] {
                    assert_eq!(db.start_undo_session(), revision);
                    for op in &aborted {
                        apply(db, op);
                    }
                    db.undo();
                }
            }
            let ops = random_ops(&mut rng, &mut next_key);
            block(&mut reference, &ops, revision);
            block(&mut subject.db, &ops, revision);
            subject.accepted();
            assert_eq!(
                subject.db.state_root(),
                reference.state_root(),
                "seed {seed}, block {revision}: root diverged"
            );

            match rng.below(10) {
                0 => subject.clean_restart(),
                1 | 2 => subject.crash_restart(),
                _ => {}
            }
            assert_eq!(
                subject.db.state_root(),
                reference.state_root(),
                "seed {seed}, after block {revision}'s restart: root diverged"
            );
        }
    }
}

// The reverse direction: two nodes that reach the same rows by different
// allocation histories hold the same state, so they must have the same root.
#[test]
fn the_root_does_not_depend_on_where_the_blobs_sit() {
    let mut direct = new_db();
    direct.set_revision(1).unwrap();
    let a = direct.alloc_blob::<Doc>(b"final-payload").unwrap();
    direct
        .create::<Doc>(|d| {
            d.key = 7;
            d.payload = a;
        })
        .unwrap();

    let mut roundabout = new_db();
    roundabout.set_revision(1).unwrap();
    // Leave junk first, free it, and rewrite the row, so its blob lands elsewhere
    // and a dead span sits in the arena with different bytes.
    let junk = roundabout
        .alloc_blob::<Doc>(b"xxxxxxxxxxxxxxxxxxxx")
        .unwrap();
    roundabout.free_blob::<Doc>(junk).unwrap();
    let first = roundabout.alloc_blob::<Doc>(b"first-attempt").unwrap();
    let id = roundabout
        .create::<Doc>(|d| {
            d.key = 7;
            d.payload = first;
        })
        .unwrap()
        .id;
    let moved = roundabout
        .realloc_blob::<Doc>(first, b"final-payload")
        .unwrap();
    roundabout.modify::<Doc>(id, |d| d.payload = moved).unwrap();

    assert_eq!(direct.state_root(), roundabout.state_root());

    // And a different payload is a different root.
    let other = roundabout
        .realloc_blob::<Doc>(moved, b"final-payloaD")
        .unwrap();
    roundabout.modify::<Doc>(id, |d| d.payload = other).unwrap();
    assert_ne!(direct.state_root(), roundabout.state_root());
}

// Paul stopped five nodes cleanly at one height: the roots agreed, but the five
// checkpoint files differed in size and hash. A checkpoint is a dump of the arena
// as it is laid out, dead blob spans included, so two nodes with the same state
// and different histories write different bytes. That is fine for a node's own
// file, which must match its own layout, but anything that hashes an *exported*
// snapshot (state sync serves one and commits to its hash) would then differ
// between nodes that agree on the state. An export is therefore written
// canonically: same state, same bytes.

fn export_bytes(db: &Db) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("export");
    db.checkpoint_unmarked(&path).unwrap();
    std::fs::read(&path).unwrap()
}

#[test]
fn an_export_is_the_same_bytes_for_the_same_state_whatever_the_history() {
    let mut direct = new_db();
    direct.set_revision(1).unwrap();
    for (key, payload) in [(7u64, &b"final-payload"[..]), (9, b"nine"), (11, b"")] {
        let blob = direct.alloc_blob::<Doc>(payload).unwrap();
        direct
            .create::<Doc>(|d| {
                d.key = key;
                d.payload = blob;
            })
            .unwrap();
    }

    let mut roundabout = new_db();
    roundabout.set_revision(1).unwrap();
    // Junk first, freed; each row first written wrong and then rewritten, so the
    // blobs land in different places and dead spans with other bytes are left.
    let junk = roundabout
        .alloc_blob::<Doc>(b"xxxxxxxxxxxxxxxxxxxx")
        .unwrap();
    roundabout.free_blob::<Doc>(junk).unwrap();
    for (key, wrong, payload) in [
        (7u64, &b"first-attempt"[..], &b"final-payload"[..]),
        (9, b"zzzzzz", b"nine"),
        (11, b"qq", b""),
    ] {
        let first = roundabout.alloc_blob::<Doc>(wrong).unwrap();
        let id = roundabout
            .create::<Doc>(|d| {
                d.key = key;
                d.payload = first;
            })
            .unwrap()
            .id;
        let moved = roundabout.realloc_blob::<Doc>(first, payload).unwrap();
        roundabout.modify::<Doc>(id, |d| d.payload = moved).unwrap();
    }

    assert_eq!(direct.state_root(), roundabout.state_root());
    assert_eq!(
        export_bytes(&direct),
        export_bytes(&roundabout),
        "same state, same exported bytes"
    );

    // And the export loads back to the same state.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("export");
    roundabout.checkpoint_unmarked(&path).unwrap();
    let mut loaded = new_db();
    loaded.load(&path).unwrap();
    assert_eq!(loaded.state_root(), direct.state_root());
}

#[test]
fn a_node_that_restarted_exports_the_bytes_of_one_that_did_not() {
    for seed in 1..=6u64 {
        let mut rng = Rng(0x2545f4914f6cdd1d ^ seed.wrapping_mul(0x9e3779b97f4a7c15));
        let mut reference = new_db();
        reference.set_revision(1).unwrap();
        let mut subject = Subject::new();
        let mut next_key = 0u64;
        for round in 0..40i64 {
            let revision = 2 + round;
            let ops = random_ops(&mut rng, &mut next_key);
            block(&mut reference, &ops, revision);
            block(&mut subject.db, &ops, revision);
            subject.accepted();
            if rng.below(6) == 0 {
                subject.crash_restart();
            }
            assert_eq!(
                export_bytes(&subject.db),
                export_bytes(&reference),
                "seed {seed}, block {revision}: exported bytes differ"
            );
        }
    }
}

// A node's own checkpoint, by contrast, keeps its live layout: the log that
// follows it is written in terms of that layout.
#[test]
fn a_nodes_own_checkpoint_still_matches_its_live_layout() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("state");
    let wal = dir.path().join("wal");
    let mut db = new_db();
    db.set_revision(1).unwrap();
    let mut rng = Rng(77);
    let mut next_key = 0;
    for round in 0..10i64 {
        let ops = random_ops(&mut rng, &mut next_key);
        block(&mut db, &ops, 2 + round);
    }
    db.checkpoint(&snap).unwrap();
    for round in 10..20i64 {
        let ops = random_ops(&mut rng, &mut next_key);
        block(&mut db, &ops, 2 + round);
        db.flush_delta(&wal).unwrap();
    }
    let mut recovered = new_db();
    recovered.load(&snap).unwrap();
    recovered.replay_log_after(&wal, 11).unwrap();
    assert_eq!(recovered.state_root(), db.state_root());
}

// The export used to hold the whole database for as long as it took to repack and
// hash every byte (seconds at mainnet size). It now copies out what it reads, and
// repacks the copy afterwards. The copy has to give exactly the bytes the file
// export gives, and has to be unaffected by what the database does next.
#[test]
fn a_frozen_copy_exports_the_same_bytes_as_the_database_and_is_unaffected_by_later_writes() {
    let mut db = new_db();
    db.set_revision(1).unwrap();
    // Blob churn: rows rewritten at different sizes, a freed span, an empty blob.
    let junk = db.alloc_blob::<Doc>(b"xxxxxxxxxxxxxxxxxxxx").unwrap();
    db.free_blob::<Doc>(junk).unwrap();
    for (key, wrong, payload) in [
        (7u64, &b"first-attempt"[..], &b"final-payload"[..]),
        (9, b"zzzzzz", b"nine"),
        (11, b"qq", b""),
        (13, b"a-longer-first-attempt-here", b"short"),
    ] {
        let first = db.alloc_blob::<Doc>(wrong).unwrap();
        let id = db
            .create::<Doc>(|d| {
                d.key = key;
                d.payload = first;
            })
            .unwrap()
            .id;
        let moved = db.realloc_blob::<Doc>(first, payload).unwrap();
        db.modify::<Doc>(id, |d| d.payload = moved).unwrap();
    }

    let before = export_bytes(&db);
    let frozen = db.freeze();
    assert_eq!(frozen.revision(), db.revision());
    assert_eq!(
        frozen.canonical_bytes().unwrap(),
        before,
        "the frozen copy exports the bytes the file export writes"
    );

    // The database moves on after the copy was taken: new rows, a rewrite.
    let blob = db.alloc_blob::<Doc>(b"written-after-the-freeze").unwrap();
    db.create::<Doc>(|d| {
        d.key = 99;
        d.payload = blob;
    })
    .unwrap();
    db.set_revision(2).unwrap();
    assert_ne!(export_bytes(&db), before, "the live state did change");
    assert_eq!(
        frozen.canonical_bytes().unwrap(),
        before,
        "and the copy still exports the state it was taken at"
    );

    // A copy builds the same bytes whichever thread does it.
    let from_a_thread = std::thread::spawn(move || frozen.canonical_bytes().unwrap())
        .join()
        .unwrap();
    assert_eq!(from_a_thread, before);
}

#[test]
fn a_frozen_copy_of_a_corrupt_database_still_refuses_to_export() {
    // Same refusal as the file export (dangling blob reference), now off the lock.
    let mut db = new_db();
    db.set_revision(1).unwrap();
    db.create::<Doc>(|d| {
        d.key = 1;
        d.payload = BlobRef {
            off: 1_000_000,
            len: 64,
        };
    })
    .unwrap();
    let error = db.freeze().canonical_bytes().expect_err("must refuse");
    assert!(
        format!("{error:?}").contains("outside its arena"),
        "{error:?}"
    );
}
