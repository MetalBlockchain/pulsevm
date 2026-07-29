//! With the derive, a table type is a declaration: no hand-written trait impl,
//! no separate tag structs. This is what makes the ~40 PulseVM tables cheap.

use pulsevm_arena::{ArenaObject, Db, ObjectId};

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
    assert_eq!(db.find_by::<Account, AccountByName>(&100).unwrap().unwrap().id, id);
    assert_eq!(db.find_by::<Account, AccountByAlias>(&200).unwrap().unwrap().balance, 5);
    assert!(db.find_by::<Account, AccountByName>(&999).unwrap().is_none());

    // Both indices are maintained on modify.
    db.modify::<Account>(id, |a| a.name = 101).unwrap();
    assert!(db.find_by::<Account, AccountByName>(&100).unwrap().is_none());
    assert_eq!(db.find_by::<Account, AccountByName>(&101).unwrap().unwrap().id, id);
    assert_eq!(db.find_by::<Account, AccountByAlias>(&200).unwrap().unwrap().id, id);
}
