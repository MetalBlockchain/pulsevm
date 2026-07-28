//! Tests for the memory mapped persistence layer: the chainbase lifecycle of
//! open / flush / dirty flag / clean close, reload of rows, undo stacks and
//! revisions, read-only opens, file growth and preservation of tables whose
//! type is not re-registered.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use pulsevm_chainbase::{
    ChainbaseError, ChainbaseObject, Database, IndexedBy, ObjectId, OpenFlags, SecondaryIndex,
    key_index,
};
use pulsevm_proc_macros::{NumBytes, Read, Write};

#[derive(Clone, Default, Debug, PartialEq, NumBytes, Read, Write)]
struct Book {
    id: ObjectId<Book>,
    a: i32,
    blob: Vec<u8>,
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

/// Unique temp dir per test, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "pulsevm_chainbase_{}_{}_{}",
            name,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const MB: u64 = 1024 * 1024;

fn open_rw(dir: &TempDir) -> Database {
    let db = Database::open(&dir.0, OpenFlags::ReadWrite, MB, false).unwrap();
    db.add_index::<Book>().unwrap();
    db
}

#[test]
fn reopen_restores_state() {
    let dir = TempDir::new("reopen");
    let book_id;
    {
        let db = open_rw(&dir);
        let book = db
            .create::<Book>(|b| {
                b.a = 3;
                b.blob = vec![1, 2, 3];
            })
            .unwrap();
        db.create::<Book>(|b| b.a = 7).unwrap();
        book_id = book.id;
        db.set_revision(42).unwrap();
        // graceful close on drop
    }
    {
        let db = open_rw(&dir);
        assert_eq!(db.revision(), 42);
        let book = db.get::<Book>(book_id).unwrap();
        assert_eq!(book.a, 3);
        assert_eq!(book.blob, vec![1, 2, 3]);
        // secondary indices are rebuilt on load
        assert_eq!(db.get_by::<Book, ByA>(&7).unwrap().id.raw(), 1);
        // the id counter continues where it left off
        let next = db.create::<Book>(|b| b.a = 9).unwrap();
        assert_eq!(next.id.raw(), 2);
    }
}

#[test]
fn reopen_restores_undo_stack() {
    let dir = TempDir::new("undo_stack");
    {
        let db = open_rw(&dir);
        let book = db.create::<Book>(|b| b.a = 1).unwrap();
        let mut session = db.start_undo_session(true).unwrap();
        db.modify(&book, |b| b.a = 2).unwrap();
        session.push();
        // closed with a live undo stack at revision 1
    }
    {
        let db = open_rw(&dir);
        assert_eq!(db.revision(), 1);
        assert_eq!(
            db.with_index::<Book, _>(|idx| idx.undo_stack_revision_range())
                .unwrap(),
            (0, 1)
        );
        assert_eq!(db.get_by::<Book, ByA>(&2).unwrap().a, 2);
        // the persisted undo state is still undoable
        db.undo().unwrap();
        assert_eq!(db.get_by::<Book, ByA>(&1).unwrap().a, 1);
        assert_eq!(db.revision(), 0);
    }
}

#[test]
fn crash_leaves_dirty_and_is_refused() {
    let dir = TempDir::new("dirty");
    {
        let db = open_rw(&dir);
        db.create::<Book>(|b| b.a = 1).unwrap();
        db.flush().unwrap();
        db.create::<Book>(|b| b.a = 2).unwrap();
        db.simulate_crash();
    }
    // a dirty database is refused...
    assert!(matches!(
        Database::open(&dir.0, OpenFlags::ReadWrite, MB, false),
        Err(ChainbaseError::Dirty { .. })
    ));
    // ...unless allow_dirty is passed, which recovers the last flushed state
    let db = Database::open(&dir.0, OpenFlags::ReadWrite, MB, true).unwrap();
    db.add_index::<Book>().unwrap();
    assert_eq!(db.with_index::<Book, _>(|idx| idx.len()).unwrap(), 1);
    assert!(db.find_by::<Book, ByA>(&2).unwrap().is_none());
}

#[test]
fn open_while_already_open_is_dirty() {
    let dir = TempDir::new("concurrent");
    let _db = open_rw(&dir);
    // the file is dirty from open until close, so a second open is refused
    assert!(matches!(
        Database::open(&dir.0, OpenFlags::ReadWrite, MB, false),
        Err(ChainbaseError::Dirty { .. })
    ));
}

#[test]
fn read_only_open() {
    let dir = TempDir::new("read_only");
    {
        let db = open_rw(&dir);
        db.create::<Book>(|b| b.a = 5).unwrap();
    }
    let db = Database::open(&dir.0, OpenFlags::ReadOnly, MB, false).unwrap();
    db.add_index::<Book>().unwrap();
    assert!(db.is_read_only());
    assert_eq!(db.get_by::<Book, ByA>(&5).unwrap().a, 5);
    assert!(matches!(
        db.create::<Book>(|b| b.a = 6),
        Err(ChainbaseError::ReadOnly { .. })
    ));
    assert!(matches!(
        db.unset_read_only_mode(),
        Err(ChainbaseError::ReadOnly { .. })
    ));
    // registering a type the file does not contain fails, as in C++
    assert!(matches!(
        db.add_index::<Page>(),
        Err(ChainbaseError::Corrupted(_))
    ));
    drop(db);
    // the read-only open left the file clean
    Database::open(&dir.0, OpenFlags::ReadWrite, MB, false).unwrap();
}

#[test]
fn file_grows_beyond_initial_size() {
    let dir = TempDir::new("grow");
    let initial_size = 4096u64;
    {
        let db = Database::open(&dir.0, OpenFlags::ReadWrite, initial_size, false).unwrap();
        db.add_index::<Book>().unwrap();
        for i in 0..100 {
            db.create::<Book>(|b| {
                b.a = i;
                b.blob = vec![0xAB; 1024];
            })
            .unwrap();
        }
    }
    let file_len = std::fs::metadata(dir.0.join("shared_memory.bin"))
        .unwrap()
        .len();
    assert!(file_len > initial_size);
    let db = open_rw(&dir);
    assert_eq!(db.with_index::<Book, _>(|idx| idx.len()).unwrap(), 100);
    assert_eq!(db.get_by::<Book, ByA>(&99).unwrap().blob.len(), 1024);
}

#[test]
fn unregistered_table_survives_rewrite() {
    let dir = TempDir::new("unclaimed");
    {
        let db = open_rw(&dir);
        db.add_index::<Page>().unwrap();
        db.create::<Book>(|b| b.a = 1).unwrap();
        db.create::<Page>(|p| p.number = 7).unwrap();
    }
    {
        // reopen registering only Book; Page's table must be carried through
        let db = open_rw(&dir);
        db.create::<Book>(|b| b.a = 2).unwrap();
    }
    {
        let db = open_rw(&dir);
        db.add_index::<Page>().unwrap();
        let page = db.get::<Page>(ObjectId::new(0)).unwrap();
        assert_eq!(page.number, 7);
        assert_eq!(db.with_index::<Book, _>(|idx| idx.len()).unwrap(), 2);
    }
}

#[test]
fn flush_persists_without_clearing_dirty() {
    let dir = TempDir::new("flush");
    let db = open_rw(&dir);
    db.create::<Book>(|b| b.a = 1).unwrap();
    db.flush().unwrap();
    // still open => still dirty on disk
    let file = std::fs::read(dir.0.join("shared_memory.bin")).unwrap();
    assert_eq!(file[12], 1, "dirty flag should be set while open");
    drop(db);
    let file = std::fs::read(dir.0.join("shared_memory.bin")).unwrap();
    assert_eq!(file[12], 0, "dirty flag should be cleared by a clean close");
}

#[test]
fn corrupted_file_is_refused() {
    let dir = TempDir::new("corrupted");
    {
        open_rw(&dir);
    }
    let path = dir.0.join("shared_memory.bin");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] = b'X'; // break the magic
    std::fs::write(&path, bytes).unwrap();
    assert!(matches!(
        Database::open(&dir.0, OpenFlags::ReadWrite, MB, false),
        Err(ChainbaseError::Corrupted(_))
    ));
}

#[test]
fn empty_database_reopens() {
    let dir = TempDir::new("empty");
    {
        open_rw(&dir);
    }
    let db = open_rw(&dir);
    assert_eq!(db.revision(), 0);
    assert_eq!(db.with_index::<Book, _>(|idx| idx.len()).unwrap(), 0);
}
