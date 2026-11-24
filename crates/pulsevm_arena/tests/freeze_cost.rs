//! How long the part of a state-summary export that needs the database takes,
//! next to the whole export. Not a pass/fail test (timings depend on the host); run
//! it to see the figures:
//!
//!   cargo test -p pulsevm_arena --release --test freeze_cost -- --ignored --nocapture
//!
//! The export used to hold the database for all of `export`; it now holds it for
//! `freeze` only, and `export` runs afterwards on a copy.

use std::time::Instant;

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

#[test]
#[ignore = "a measurement, not a check"]
fn how_long_the_database_is_held_against_the_whole_export() {
    let rows: u64 = std::env::var("FREEZE_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3_000_000);
    let mut db = Db::new();
    db.add_table::<Doc>().unwrap();
    db.set_revision(1).unwrap();
    let payload = vec![0xA5u8; 160];
    for key in 0..rows {
        let blob = db.alloc_blob::<Doc>(&payload).unwrap();
        db.create::<Doc>(|d| {
            d.key = key;
            d.payload = blob;
        })
        .unwrap();
    }

    let held = Instant::now();
    let frozen = db.freeze();
    let held = held.elapsed();

    let exported = Instant::now();
    let bytes = frozen.canonical_bytes().unwrap();
    let exported = exported.elapsed();

    // What it cost before: the whole export under the database, via a file.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("export");
    let old = Instant::now();
    db.checkpoint_unmarked(&path).unwrap();
    let old = old.elapsed();

    println!(
        "{rows} rows, {:.0} MB canonical: database held {held:?} now, {old:?} before (file route); the build itself {exported:?} off the lock",
        bytes.len() as f64 / 1e6
    );
}
