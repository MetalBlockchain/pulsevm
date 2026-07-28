//! Port of the database-level behaviour exercised by `chainbase/test/test.cpp`
//! (the `book` object) plus the session patterns pulsevm's controller uses
//! (root session with squashed/undone children, push on success).

use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_chainbase::{
    ChainbaseError, ChainbaseObject, Database, IndexedBy, ObjectId, SecondaryIndex, key_index,
};

#[derive(Clone, Default, Debug, PartialEq, NumBytes, Read, Write)]
struct Book {
    id: ObjectId<Book>,
    a: i32,
    b: i32,
}

struct ByA;
impl IndexedBy<Book> for ByA {
    type Key = i32;
    fn key(obj: &Book) -> i32 {
        obj.a
    }
}

impl ChainbaseObject for Book {
    const TYPE_ID: u16 = 0;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![key_index::<Self, ByA>()]
    }
}

#[derive(Clone, Default, Debug, PartialEq, NumBytes, Read, Write)]
struct Page {
    id: ObjectId<Page>,
    number: u32,
}

impl ChainbaseObject for Page {
    const TYPE_ID: u16 = 1;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
}

fn new_db() -> Database {
    let db = Database::new();
    db.add_index::<Book>().unwrap();
    db
}

#[test]
fn open_and_create() {
    let db = new_db();
    // duplicate registration is rejected
    assert!(matches!(
        db.add_index::<Book>(),
        Err(ChainbaseError::TypeIdInUse { .. })
    ));

    let new_book = db
        .create::<Book>(|b| {
            b.a = 3;
            b.b = 4;
        })
        .unwrap();
    let copy_new_book = db.get::<Book>(new_book.id).unwrap();
    assert_eq!(new_book.a, copy_new_book.a);
    assert_eq!(new_book.b, copy_new_book.b);

    let by_a = db.get_by::<Book, ByA>(&3).unwrap();
    assert_eq!(by_a.id, new_book.id);
    assert!(db.find_by::<Book, ByA>(&99).unwrap().is_none());
    assert!(matches!(
        db.get_by::<Book, ByA>(&99),
        Err(ChainbaseError::UnknownKey { .. })
    ));

    db.modify(&new_book, |b| b.a = 5).unwrap();
    let modified = db.get::<Book>(new_book.id).unwrap();
    assert_eq!(modified.a, 5);
    assert!(db.find_by::<Book, ByA>(&3).unwrap().is_none());
    assert_eq!(db.find_by::<Book, ByA>(&5).unwrap().unwrap().id, new_book.id);

    db.remove(&modified).unwrap();
    assert!(db.find::<Book>(new_book.id).unwrap().is_none());
    assert!(matches!(
        db.get::<Book>(new_book.id),
        Err(ChainbaseError::NotFound { .. })
    ));
}

#[test]
fn unregistered_type_errors() {
    let db = new_db();
    assert!(matches!(
        db.create::<Page>(|_| {}),
        Err(ChainbaseError::IndexNotRegistered { .. })
    ));
    assert!(matches!(
        db.find::<Page>(ObjectId::new(0)),
        Err(ChainbaseError::IndexNotRegistered { .. })
    ));
}

#[test]
fn session_undo_on_drop() {
    let db = new_db();
    let book = db.create::<Book>(|b| b.a = 1).unwrap();
    {
        let _session = db.start_undo_session(true).unwrap();
        db.modify(&book, |b| b.a = 2).unwrap();
        db.create::<Book>(|b| b.a = 50).unwrap();
        assert_eq!(db.get::<Book>(book.id).unwrap().a, 2);
        // dropped without push: everything reverts
    }
    assert_eq!(db.get::<Book>(book.id).unwrap().a, 1);
    assert_eq!(db.with_index::<Book, _>(|idx| idx.len()).unwrap(), 1);
    assert_eq!(db.revision(), 0);
}

#[test]
fn session_push_keeps_changes() {
    let db = new_db();
    let book = db.create::<Book>(|b| b.a = 1).unwrap();
    {
        let mut session = db.start_undo_session(true).unwrap();
        db.modify(&book, |b| b.a = 2).unwrap();
        session.push();
    }
    assert_eq!(db.get::<Book>(book.id).unwrap().a, 2);
    assert_eq!(db.revision(), 1);
    // the undo state is still on the stack until commit
    assert!(db.with_index::<Book, _>(|idx| idx.has_undo_session()).unwrap());
    db.commit(db.revision()).unwrap();
    assert!(!db.with_index::<Book, _>(|idx| idx.has_undo_session()).unwrap());
    // a pushed and committed change can no longer be undone
    db.undo_all().unwrap();
    assert_eq!(db.get::<Book>(book.id).unwrap().a, 2);
}

#[test]
fn disabled_session_is_noop() {
    let db = new_db();
    let book = db.create::<Book>(|b| b.a = 1).unwrap();
    {
        let _session = db.start_undo_session(false).unwrap();
        db.modify(&book, |b| b.a = 2).unwrap();
    }
    assert_eq!(db.get::<Book>(book.id).unwrap().a, 2);
    assert_eq!(db.revision(), 0);
}

/// The controller's block-building pattern: a root session wraps per
/// transaction child sessions which are squashed on success or undone on
/// failure; the root is pushed when the block is accepted.
#[test]
fn nested_sessions_controller_pattern() {
    let db = new_db();
    let book = db.create::<Book>(|b| b.a = 1).unwrap();

    let mut root = db.start_undo_session(true).unwrap();

    {
        // transaction 1 succeeds -> squash into root
        let mut child = db.start_undo_session(true).unwrap();
        db.modify(&book, |b| b.a = 2).unwrap();
        child.squash();
    }
    {
        // transaction 2 fails -> undo
        let mut child = db.start_undo_session(true).unwrap();
        db.modify(&book, |b| b.a = 99).unwrap();
        child.undo();
    }
    assert_eq!(db.get::<Book>(book.id).unwrap().a, 2);

    root.push();
    assert_eq!(db.get::<Book>(book.id).unwrap().a, 2);
    assert_eq!(db.revision(), 1);

    // undoing the pushed-but-uncommitted revision reverts the block
    db.undo().unwrap();
    assert_eq!(db.get::<Book>(book.id).unwrap().a, 1);
    assert_eq!(db.revision(), 0);
}

#[test]
fn database_undo_all() {
    let db = new_db();
    let book = db.create::<Book>(|b| b.a = 1).unwrap();
    let mut s1 = db.start_undo_session(true).unwrap();
    db.modify(&book, |b| b.a = 2).unwrap();
    let mut s2 = db.start_undo_session(true).unwrap();
    db.modify(&book, |b| b.a = 3).unwrap();
    s2.push();
    s1.push();
    assert_eq!(db.revision(), 2);
    db.undo_all().unwrap();
    assert_eq!(db.get::<Book>(book.id).unwrap().a, 1);
    assert_eq!(db.revision(), 0);
}

#[test]
fn set_revision_and_range() {
    let db = new_db();
    assert_eq!(db.revision(), 0);
    db.set_revision(10).unwrap();
    assert_eq!(db.revision(), 10);
    let mut session = db.start_undo_session(true).unwrap();
    assert_eq!(db.revision(), 11);
    assert!(matches!(
        db.set_revision(20),
        Err(ChainbaseError::Revision(_))
    ));
    session.undo();
    assert_eq!(db.revision(), 10);
}

/// C++ `add_index` syncs a late-added index with the revision range of the
/// existing indices.
#[test]
fn add_index_syncs_revision() {
    let db = new_db();
    db.set_revision(5).unwrap();
    let mut s1 = db.start_undo_session(true).unwrap();
    let _s2 = db.start_undo_session(true).unwrap();

    db.add_index::<Page>().unwrap();
    let range = db
        .with_index::<Page, _>(|idx| idx.undo_stack_revision_range())
        .unwrap();
    assert_eq!(range, (5, 7));
    let book_range = db
        .with_index::<Book, _>(|idx| idx.undo_stack_revision_range())
        .unwrap();
    assert_eq!(range, book_range);
    drop(_s2);
    s1.undo();
}

#[test]
fn read_only_mode_blocks_writes() {
    let db = new_db();
    let book = db.create::<Book>(|b| b.a = 1).unwrap();
    db.set_read_only_mode();
    assert!(matches!(
        db.create::<Book>(|b| b.a = 2),
        Err(ChainbaseError::ReadOnly { .. })
    ));
    assert!(matches!(
        db.modify(&book, |b| b.a = 2),
        Err(ChainbaseError::ReadOnly { .. })
    ));
    assert!(matches!(
        db.remove(&book),
        Err(ChainbaseError::ReadOnly { .. })
    ));
    assert!(matches!(
        db.start_undo_session(true),
        Err(ChainbaseError::ReadOnly { .. })
    ));
    // reads still work
    assert_eq!(db.get::<Book>(book.id).unwrap().a, 1);
    db.unset_read_only_mode().unwrap();
    db.modify(&book, |b| b.a = 2).unwrap();
    assert_eq!(db.get::<Book>(book.id).unwrap().a, 2);
}

#[test]
fn with_index_range_queries() {
    let db = new_db();
    for v in [5, 1, 3, 4, 2] {
        db.create::<Book>(|b| b.a = v).unwrap();
    }
    let keys: Vec<i32> = db
        .with_index::<Book, _>(|idx| {
            idx.get_index::<ByA>()
                .lower_bound(&2)
                .map(|(k, _)| *k)
                .collect()
        })
        .unwrap();
    assert_eq!(keys, vec![2, 3, 4, 5]);
    let row_counts = db.row_count_per_index();
    assert_eq!(row_counts.len(), 1);
    assert_eq!(row_counts[0].0, 5);
}

#[test]
fn shared_handle_across_threads() {
    let db = new_db();
    let db2 = db.clone();
    let handle = std::thread::spawn(move || {
        db2.create::<Book>(|b| b.a = 7).unwrap();
    });
    handle.join().unwrap();
    assert_eq!(db.get_by::<Book, ByA>(&7).unwrap().a, 7);
}
