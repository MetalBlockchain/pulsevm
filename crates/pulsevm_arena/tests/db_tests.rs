use pulsevm_arena::{ArenaObject, Db, DbError, IndexedBy, ObjectId, SecondaryIndex, key_index};

#[derive(Clone, Default, Debug, PartialEq)]
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

#[derive(Clone, Default, Debug, PartialEq)]
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

fn db() -> Db {
    let mut db = Db::new();
    db.add_table::<Account>().unwrap();
    db.add_table::<Resource>().unwrap();
    db
}

#[test]
fn cross_table_operations() {
    let mut db = db();
    let a = db.create::<Account>(|a| a.name = 5).unwrap().id;
    db.create::<Resource>(|r| {
        r.owner = 5;
        r.ram = 100;
    })
    .unwrap();
    assert_eq!(db.get::<Account>(a).unwrap().name, 5);
    assert_eq!(db.find_by::<Account, AccountByName>(&5).unwrap().unwrap().id, a);
    assert_eq!(db.table::<Resource>().unwrap().len(), 1);
}

#[test]
fn duplicate_type_id_rejected() {
    let mut db = Db::new();
    db.add_table::<Account>().unwrap();
    let err = db.add_table::<Account>().unwrap_err();
    assert!(matches!(err, DbError::TypeIdInUse { .. }));
}

#[test]
fn unregistered_table_errors() {
    let db = Db::new();
    let err = db.find::<Account>(ObjectId::new(0)).unwrap_err();
    assert!(matches!(err, DbError::NotRegistered { .. }));
}

#[test]
fn undo_session_spans_all_tables() {
    let mut db = db();
    db.create::<Account>(|a| a.name = 1).unwrap();
    db.create::<Resource>(|r| r.owner = 1).unwrap();

    let rev = db.start_undo_session();
    assert_eq!(rev, 1);
    db.create::<Account>(|a| a.name = 2).unwrap();
    db.modify::<Resource>(ObjectId::new(0), |r| r.ram = 999).unwrap();
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
    let mut db = db();
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
