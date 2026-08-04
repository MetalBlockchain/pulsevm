//! With the derive, a table type is a declaration: no hand-written trait impl,
//! no separate tag structs. This is what makes the ~40 PulseVM tables cheap.

use pulsevm_arena::{
    ArenaObject,
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
#[arena(type_id = 7)]
struct Account {
    id: ObjectId<Account>,
    #[arena(index)]
    name: u64,
    #[arena(index)]
    alias: u64,
    balance: i64,
}

#[test]
fn derived_object_has_both_indices() {
    let mut db = Db::new();
    db.add_table::<Account>().unwrap();

    let id = db
        .create::<Account>(|a| {
            a.name = 100;
            a.alias = 200;
            a.balance = 5;
        })
        .unwrap()
        .id;

    // The derive named the tags AccountByName / AccountByAlias.
    assert_eq!(
        db.find_by::<Account, AccountByName>(&100)
            .unwrap()
            .unwrap()
            .id,
        id
    );
    assert_eq!(
        db.find_by::<Account, AccountByAlias>(&200)
            .unwrap()
            .unwrap()
            .balance,
        5
    );
    assert!(
        db.find_by::<Account, AccountByName>(&999)
            .unwrap()
            .is_none()
    );

    // Both indices are maintained on modify.
    db.modify::<Account>(id, |a| a.name = 101).unwrap();
    assert!(
        db.find_by::<Account, AccountByName>(&100)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.find_by::<Account, AccountByName>(&101)
            .unwrap()
            .unwrap()
            .id,
        id
    );
    assert_eq!(
        db.find_by::<Account, AccountByAlias>(&200)
            .unwrap()
            .unwrap()
            .id,
        id
    );
}

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
#[arena(type_id = 8)]
struct HashedRow {
    id: ObjectId<HashedRow>,
    #[arena(hash_index)]
    key: u64,
    payload: u64,
}

/// A `#[arena(hash_index)]` field is queried through `find_by_hash`, stays in
/// step across modify/remove, and survives a checkpoint round-trip (whose open
/// path bulk-builds the hash index).
#[test]
fn hash_index_point_lookups_and_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap.bin");

    let mut db = Db::new();
    db.add_table::<HashedRow>().unwrap();
    for k in [10u64, 20, 30] {
        db.create::<HashedRow>(|r| {
            r.key = k;
            r.payload = k * 2;
        })
        .unwrap();
    }

    assert_eq!(
        db.find_by_hash::<HashedRow, HashedRowByKey>(&20)
            .unwrap()
            .unwrap()
            .payload,
        40
    );
    assert!(
        db.find_by_hash::<HashedRow, HashedRowByKey>(&99)
            .unwrap()
            .is_none()
    );

    // Rekey and remove keep the hash index consistent.
    let id20 = db
        .find_by_hash::<HashedRow, HashedRowByKey>(&20)
        .unwrap()
        .unwrap()
        .id;
    db.modify::<HashedRow>(id20, |r| r.key = 25).unwrap();
    assert!(
        db.find_by_hash::<HashedRow, HashedRowByKey>(&20)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.find_by_hash::<HashedRow, HashedRowByKey>(&25)
            .unwrap()
            .unwrap()
            .id,
        id20
    );

    db.save(&path).unwrap();
    let mut fresh = Db::new();
    fresh.add_table::<HashedRow>().unwrap();
    fresh.load(&path).unwrap();
    // The hash index was bulk-rebuilt on open and answers the same.
    assert_eq!(
        fresh
            .find_by_hash::<HashedRow, HashedRowByKey>(&30)
            .unwrap()
            .unwrap()
            .payload,
        60
    );
    assert_eq!(
        fresh
            .find_by_hash::<HashedRow, HashedRowByKey>(&25)
            .unwrap()
            .unwrap()
            .id,
        id20
    );
    assert!(
        fresh
            .find_by_hash::<HashedRow, HashedRowByKey>(&10)
            .unwrap()
            .is_some()
    );
}
