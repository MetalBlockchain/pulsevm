//! A faithful model of EOS/PulseVM `account_object` — fixed-size fields plus a
//! variable-length `abi` in the blob arena — exercised through create, read,
//! undo, and snapshot. This is the shape the ~40 real tables take.

use pulsevm_arena::{ArenaObject, BlobRef, Db, ObjectId};

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
#[arena(type_id = 10)]
struct AccountObject {
    id: ObjectId<AccountObject>,
    #[arena(index)]
    name: u64,
    creation_date: u32,
    _pad: u32,
    abi: BlobRef,
}

fn new_db() -> Db {
    let mut db = Db::new();
    db.add_table::<AccountObject>().unwrap();
    db
}

fn create_account(db: &mut Db, name: u64, abi: &[u8]) -> ObjectId<AccountObject> {
    let abi_ref = db.alloc_blob::<AccountObject>(abi).unwrap();
    db.create::<AccountObject>(|a| {
        a.name = name;
        a.creation_date = 1;
        a.abi = abi_ref;
    })
    .unwrap()
    .id
}

#[test]
fn stores_and_reads_variable_length_abi() {
    let mut db = new_db();
    let id = create_account(&mut db, 42, b"the-abi-bytes");
    let acct = *db.get::<AccountObject>(id).unwrap();
    assert_eq!(db.blob::<AccountObject>(acct.abi).unwrap(), b"the-abi-bytes");
    // An account created with no abi reads back as an empty slice.
    let empty = create_account(&mut db, 43, b"");
    let acct = *db.get::<AccountObject>(empty).unwrap();
    assert_eq!(db.blob::<AccountObject>(acct.abi).unwrap(), b"");
}

#[test]
fn undo_drops_blobs_appended_in_the_session() {
    let mut db = new_db();
    create_account(&mut db, 1, b"kept");

    db.start_undo_session();
    create_account(&mut db, 2, b"discarded-abi");
    db.undo();

    // The rejected account and its abi are gone; the next allocation reuses the
    // space, so the arena did not leak the discarded blob.
    assert!(db.find_by::<AccountObject, AccountObjectByName>(&2).unwrap().is_none());
    let reused = db.alloc_blob::<AccountObject>(b"x").unwrap();
    assert_eq!(reused.off, 4); // right after "kept" (4 bytes), not after the discarded blob
}

#[test]
fn snapshot_round_trips_blobs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap.bin");

    let mut db = new_db();
    let a = create_account(&mut db, 1, b"first-abi");
    let b = create_account(&mut db, 2, b"second-longer-abi");
    db.save(&path).unwrap();

    let mut restored = new_db();
    restored.load(&path).unwrap();
    let ra = *restored.get::<AccountObject>(a).unwrap();
    let rb = *restored.get::<AccountObject>(b).unwrap();
    assert_eq!(restored.blob::<AccountObject>(ra.abi).unwrap(), b"first-abi");
    assert_eq!(restored.blob::<AccountObject>(rb.abi).unwrap(), b"second-longer-abi");
    assert_eq!(restored.find_by::<AccountObject, AccountObjectByName>(&2).unwrap().unwrap().id, b);
}
