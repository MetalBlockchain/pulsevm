//! A checkpoint is read from a file a peer chose (state sync) as well as from the
//! node's own disk. Every number in it is a claim: none may size an allocation or
//! change state without being checked, and nothing may be accepted twice or left
//! over. Each test alters one thing in a real checkpoint and requires a refusal
//! (or, for the state root, a different root) rather than a panic, a huge
//! allocation, or a silent install.

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
#[arena(type_id = 10)]
struct Account {
    id: ObjectId<Account>,
    #[arena(index)]
    name: u64,
    created: u32,
    _pad: u32,
    abi: BlobRef,
}

fn db_with(names: &[u64]) -> Db {
    let mut db = Db::new();
    db.add_table::<Account>().unwrap();
    for &name in names {
        let abi = db.alloc_blob::<Account>(b"some-abi").unwrap();
        db.create::<Account>(|a| {
            a.name = name;
            a.created = 1;
            a.abi = abi;
        })
        .unwrap();
    }
    db.set_revision(1).unwrap();
    db
}

/// A real checkpoint's bytes: [revision i64][sections u64] then per section
/// [type_id u16][len u64][next_id u64][live u64]...
fn checkpoint_bytes(db: &mut Db) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cp");
    db.checkpoint(&path).unwrap();
    std::fs::read(path).unwrap()
}

const NEXT_ID_AT: usize = 16 + 2 + 8;
const LIVE_AT: usize = NEXT_ID_AT + 8;

fn load(bytes: &[u8]) -> Result<Db, pulsevm_arena::DbError> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cp");
    std::fs::write(&path, bytes).unwrap();
    let mut db = Db::new();
    db.add_table::<Account>().unwrap();
    db.load(&path)?;
    Ok(db)
}

fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn a_real_checkpoint_loads() {
    let mut db = db_with(&[1, 2, 3]);
    let bytes = checkpoint_bytes(&mut db);
    let loaded = load(&bytes).unwrap();
    assert_eq!(loaded.state_root(), db.state_root());
}

#[test]
fn a_next_id_beyond_any_real_table_is_refused_not_allocated() {
    let mut db = db_with(&[1, 2, 3]);
    let mut bytes = checkpoint_bytes(&mut db);
    put_u64(&mut bytes, NEXT_ID_AT, 1 << 40);
    let error = load(&bytes).err().expect("a forged counter must not load");
    assert!(
        format!("{error:?}").contains("beyond any real table"),
        "{error:?}"
    );
}

#[test]
fn a_live_count_larger_than_the_bytes_present_is_refused_before_any_allocation() {
    let mut db = db_with(&[1, 2, 3]);
    let mut bytes = checkpoint_bytes(&mut db);
    // 2^45 rows claimed, three present. Sizing a vector from it would abort.
    put_u64(&mut bytes, LIVE_AT, 1 << 35);
    let error = load(&bytes).err().expect("must be refused");
    assert!(format!("{error:?}").contains("live row count"), "{error:?}");
    // And more live rows than ids ever minted cannot be true.
    let mut bytes = checkpoint_bytes(&mut db);
    put_u64(&mut bytes, LIVE_AT, 4);
    assert!(load(&bytes).is_err());
}

// The state root covers the id counter: two nodes with the same rows and
// different counters mint different ids from the next block, so they are not in
// the same state. It was not hashed, so a snapshot with a forged counter passed
// the root check.
#[test]
fn the_state_root_covers_the_id_counter() {
    let mut honest = db_with(&[1, 2, 3]);
    let mut bytes = checkpoint_bytes(&mut honest);
    let next_id = u64::from_le_bytes(bytes[NEXT_ID_AT..NEXT_ID_AT + 8].try_into().unwrap());
    put_u64(&mut bytes, NEXT_ID_AT, next_id + 5);
    let forged = load(&bytes).expect("a larger counter is a valid table, only a different one");
    assert_ne!(
        forged.state_root(),
        honest.state_root(),
        "the same rows with another counter must not share a root"
    );
}

#[test]
fn two_sections_for_one_table_are_refused() {
    let mut db = db_with(&[1, 2, 3]);
    let bytes = checkpoint_bytes(&mut db);
    // [revision][2 sections][section][section]: the same section twice.
    let section = &bytes[16..];
    let mut doubled = Vec::new();
    doubled.extend_from_slice(&bytes[..8]);
    doubled.extend_from_slice(&2u64.to_le_bytes());
    doubled.extend_from_slice(section);
    doubled.extend_from_slice(section);
    let error = load(&doubled)
        .err()
        .expect("a table loaded twice must be refused");
    assert!(format!("{error:?}").contains("two sections"), "{error:?}");
}

#[test]
fn bytes_after_the_last_section_are_refused() {
    let mut db = db_with(&[1, 2, 3]);
    let mut bytes = checkpoint_bytes(&mut db);
    bytes.extend_from_slice(&[0xAB; 7]);
    let error = load(&bytes).err().expect("trailing bytes must be refused");
    assert!(format!("{error:?}").contains("trailing"), "{error:?}");
}
