use pulsevm_arena::{
    ArenaObject,
    Db,
    DbError,
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
    Debug,
    PartialEq,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
struct Account {
    id: ObjectId<Account>,
    name: u64,
}
struct AccountByName;
impl IndexedBy<Account> for AccountByName {
    type Key = u64;
    fn key(o: &Account) -> u64 {
        o.name
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
        vec![key_index::<Self, AccountByName>()]
    }
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Default,
    Debug,
    PartialEq,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
struct Resource {
    id: ObjectId<Resource>,
    owner: u64,
    ram: i64,
}
impl ArenaObject for Resource {
    const TYPE_ID: u16 = 2;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
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
)]
struct AccountTypeIdCollision {
    id: ObjectId<AccountTypeIdCollision>,
}
impl ArenaObject for AccountTypeIdCollision {
    const TYPE_ID: u16 = Account::TYPE_ID;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
}

fn new_db() -> Db {
    let mut db = Db::new();
    db.add_table::<Account>().unwrap();
    db.add_table::<Resource>().unwrap();
    db
}

#[test]
fn cross_table_operations() {
    let mut db = new_db();
    let a = db.create::<Account>(|a| a.name = 5).unwrap().id;
    db.create::<Resource>(|r| {
        r.owner = 5;
        r.ram = 100;
    })
    .unwrap();
    assert_eq!(db.get::<Account>(a).unwrap().name, 5);
    assert_eq!(
        db.find_by::<Account, AccountByName>(&5)
            .unwrap()
            .unwrap()
            .id,
        a
    );
    assert_eq!(db.table::<Resource>().unwrap().len(), 1);
}

#[test]
fn duplicate_type_id_rejected() {
    let mut db = Db::new();
    db.add_table::<Account>().unwrap();
    let err = db.add_table::<AccountTypeIdCollision>().unwrap_err();
    assert!(matches!(err, DbError::TypeIdInUse { .. }));

    // Direct TYPE_ID indexing must not turn a colliding, unregistered Rust type
    // into a downcast panic at lookup time.
    let err = db.table::<AccountTypeIdCollision>().err().unwrap();
    assert!(matches!(err, DbError::NotRegistered { .. }));
}

#[test]
fn unregistered_table_errors() {
    let db = Db::new();
    let err = db.find::<Account>(ObjectId::new(0)).unwrap_err();
    assert!(matches!(err, DbError::NotRegistered { .. }));
}

#[test]
fn undo_session_spans_all_tables() {
    let mut db = new_db();
    db.create::<Account>(|a| a.name = 1).unwrap();
    db.create::<Resource>(|r| r.owner = 1).unwrap();

    let rev = db.start_undo_session();
    assert_eq!(rev, 1);
    db.create::<Account>(|a| a.name = 2).unwrap();
    db.modify::<Resource>(ObjectId::new(0), |r| r.ram = 999)
        .unwrap();
    assert_eq!(db.table::<Account>().unwrap().len(), 2);
    assert_eq!(db.get::<Resource>(ObjectId::new(0)).unwrap().ram, 999);

    db.undo();
    // Both tables reverted together.
    assert_eq!(db.table::<Account>().unwrap().len(), 1);
    assert_eq!(db.get::<Resource>(ObjectId::new(0)).unwrap().ram, 0);
    assert!(db.find_by::<Account, AccountByName>(&2).unwrap().is_none());
}

#[test]
fn shared_revision_and_commit() {
    let mut db = new_db();
    assert_eq!(db.revision(), 0);
    db.start_undo_session();
    db.create::<Account>(|a| a.name = 1).unwrap();
    db.start_undo_session();
    db.create::<Resource>(|r| r.owner = 1).unwrap();
    assert_eq!(db.revision(), 2);

    // Both tables sit at the same revision.
    assert_eq!(
        db.table::<Account>().unwrap().revision(),
        db.table::<Resource>().unwrap().revision()
    );

    db.commit(db.revision());
    db.undo(); // nothing left to revert
    assert_eq!(db.table::<Account>().unwrap().len(), 1);
    assert_eq!(db.table::<Resource>().unwrap().len(), 1);
}

#[test]
fn snapshot_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snapshot.bin");

    let mut db = new_db();
    for i in 0..1000u64 {
        db.create::<Account>(|a| a.name = i).unwrap();
    }
    db.create::<Resource>(|r| {
        r.owner = 42;
        r.ram = -7;
    })
    .unwrap();
    // A tombstone in the middle must survive the round trip as an absent id.
    db.remove::<Account>(ObjectId::new(500)).unwrap();
    db.save(&path).unwrap();

    let mut restored = new_db();
    restored.load(&path).unwrap();
    assert_eq!(restored.table::<Account>().unwrap().len(), 999);
    assert!(
        restored
            .find::<Account>(ObjectId::new(500))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        restored.get::<Account>(ObjectId::new(499)).unwrap().name,
        499
    );
    // Secondary index was rebuilt.
    assert_eq!(
        restored
            .find_by::<Account, AccountByName>(&777)
            .unwrap()
            .unwrap()
            .id
            .raw(),
        777
    );
    assert_eq!(restored.get::<Resource>(ObjectId::new(0)).unwrap().ram, -7);
    // Next id continues past the tombstone, not reusing 500 or 1000.
    let next = restored
        .create::<Account>(|a| a.name = 9999)
        .unwrap()
        .id
        .raw();
    assert_eq!(next, 1000);
}

#[test]
fn load_rejects_unregistered_table() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snapshot.bin");
    let mut full = new_db();
    full.create::<Account>(|a| a.name = 1).unwrap();
    full.save(&path).unwrap();

    let mut partial = Db::new();
    partial.add_table::<Account>().unwrap();
    let err = partial.load(&path).unwrap_err();
    assert!(matches!(err, DbError::Corrupted(_)));
}

#[test]
fn table_added_after_sessions_matches_revision() {
    let mut db = Db::new();
    db.add_table::<Account>().unwrap();
    db.start_undo_session();
    db.start_undo_session();
    // A table registered now must line up with the existing undo depth.
    db.add_table::<Resource>().unwrap();
    assert_eq!(
        db.table::<Account>().unwrap().revision(),
        db.table::<Resource>().unwrap().revision()
    );
    // And undo still works consistently across both.
    db.create::<Resource>(|r| r.owner = 7).unwrap();
    db.undo();
    assert_eq!(db.table::<Resource>().unwrap().len(), 0);
}
