//! Port of `chainbase/test/undo_index.cpp` to the Rust `UndoIndex`.
//!
//! The C++ tests use RAII sessions whose scope-exit runs `undo()`; here the
//! equivalent calls are explicit. The allocator failure-injection machinery
//! (`test_exceptions`) has no equivalent because the Rust implementation does
//! not allocate through a failable segment allocator.

use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_chainbase::{
    ChainbaseError, ChainbaseObject, IndexedBy, ObjectId, SecondaryIndex, UndoIndex, key_index,
};

#[derive(Clone, Default, Debug, PartialEq, NumBytes, Read, Write)]
struct BasicElement {
    id: ObjectId<BasicElement>,
}

impl ChainbaseObject for BasicElement {
    const TYPE_ID: u16 = 0;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
}

#[derive(Clone, Default, Debug, PartialEq, NumBytes, Read, Write)]
struct TestElement {
    id: ObjectId<TestElement>,
    secondary: i32,
}

struct BySecondary;
impl IndexedBy<TestElement> for BySecondary {
    type Key = i32;
    fn key(obj: &TestElement) -> i32 {
        obj.secondary
    }
}

impl ChainbaseObject for TestElement {
    const TYPE_ID: u16 = 1;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![key_index::<Self, BySecondary>()]
    }
}

fn find_secondary(index: &UndoIndex<TestElement>, id: i64) -> Option<i32> {
    index.find(ObjectId::new(id)).map(|e| e.secondary)
}

/// Equivalent of the C++ `capture_state` scope guard: checks that the table
/// matches `expected` `(id, secondary)` pairs and that both indices agree.
fn assert_state(index: &UndoIndex<TestElement>, expected: &[(i64, i32)]) {
    assert_eq!(index.len(), expected.len());
    let by_secondary = index.get_index::<BySecondary>();
    assert_eq!(by_secondary.len(), expected.len());
    for &(id, secondary) in expected {
        let actual = index.find(ObjectId::new(id)).expect("missing element");
        assert_eq!(actual.id.raw(), id);
        assert_eq!(actual.secondary, secondary);
        let through_secondary = by_secondary.find(&secondary).expect("missing in secondary");
        assert_eq!(through_secondary.id.raw(), id);
    }
}

#[test]
fn test_simple() {
    let mut i0 = UndoIndex::<BasicElement>::new();
    i0.emplace(|_| {}).unwrap();
    let element = i0.find(ObjectId::new(0));
    assert!(matches!(element, Some(e) if e.id.raw() == 0));
    assert!(i0.find(ObjectId::new(1)).is_none());
    i0.emplace(|_| {}).unwrap();
    let e2 = i0.find(ObjectId::new(1));
    assert!(matches!(e2, Some(e) if e.id.raw() == 1));

    i0.modify(ObjectId::new(0), |_| {}).unwrap();
    i0.remove(ObjectId::new(0)).unwrap();
    assert!(i0.find(ObjectId::new(0)).is_none());
}

#[test]
fn test_insert_undo() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    assert_eq!(find_secondary(&i0, 0), Some(42));
    i0.start_undo_session();
    i0.emplace(|e| e.secondary = 12).unwrap();
    assert_eq!(find_secondary(&i0, 1), Some(12));
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
    assert!(i0.find(ObjectId::new(1)).is_none());
}

#[test]
fn test_insert_squash() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.start_undo_session();
    i0.emplace(|e| e.secondary = 12).unwrap();
    assert_eq!(find_secondary(&i0, 1), Some(12));
    i0.squash();
    assert_eq!(find_secondary(&i0, 1), Some(12));
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
    assert!(i0.find(ObjectId::new(1)).is_none());
}

#[test]
fn test_insert_push() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.emplace(|e| e.secondary = 12).unwrap();
    // session.push(): keep the changes, then make them permanent.
    i0.commit(i0.revision());
    assert!(!i0.has_undo_session());
    assert_state(&i0, &[(0, 42), (1, 12)]);
}

#[test]
fn test_modify_undo() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.modify(ObjectId::new(0), |e| e.secondary = 18).unwrap();
    assert_eq!(find_secondary(&i0, 0), Some(18));
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
}

#[test]
fn test_modify_squash() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.start_undo_session();
    i0.modify(ObjectId::new(0), |e| e.secondary = 18).unwrap();
    i0.squash();
    assert_eq!(find_secondary(&i0, 0), Some(18));
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
}

#[test]
fn test_modify_push() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.modify(ObjectId::new(0), |e| e.secondary = 18).unwrap();
    i0.commit(i0.revision());
    assert!(!i0.has_undo_session());
    assert_state(&i0, &[(0, 18)]);
}

#[test]
fn test_remove_undo() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.remove(ObjectId::new(0)).unwrap();
    assert!(i0.find(ObjectId::new(0)).is_none());
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
}

#[test]
fn test_remove_squash() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.start_undo_session();
    i0.remove(ObjectId::new(0)).unwrap();
    i0.squash();
    assert!(i0.find(ObjectId::new(0)).is_none());
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
}

#[test]
fn test_remove_push() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.remove(ObjectId::new(0)).unwrap();
    i0.commit(i0.revision());
    assert!(!i0.has_undo_session());
    assert!(i0.find(ObjectId::new(0)).is_none());
}

#[test]
fn test_insert_modify() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.emplace(|e| e.secondary = 12).unwrap();
    assert_eq!(find_secondary(&i0, 1), Some(12));
    i0.modify(ObjectId::new(1), |e| e.secondary = 24).unwrap();
    assert_state(&i0, &[(0, 42), (1, 24)]);
}

#[test]
fn test_insert_modify_undo() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.emplace(|e| e.secondary = 12).unwrap();
    i0.modify(ObjectId::new(1), |e| e.secondary = 24).unwrap();
    assert_eq!(find_secondary(&i0, 1), Some(24));
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
    assert!(i0.find(ObjectId::new(1)).is_none());
}

#[test]
fn test_insert_modify_squash() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.emplace(|e| e.secondary = 12).unwrap();
    i0.start_undo_session();
    i0.modify(ObjectId::new(1), |e| e.secondary = 24).unwrap();
    i0.squash();
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
    assert!(i0.find(ObjectId::new(1)).is_none());
}

#[test]
fn test_insert_remove_undo() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.emplace(|e| e.secondary = 12).unwrap();
    i0.remove(ObjectId::new(1)).unwrap();
    assert!(i0.find(ObjectId::new(1)).is_none());
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
    assert!(i0.find(ObjectId::new(1)).is_none());
}

#[test]
fn test_insert_remove_squash() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.emplace(|e| e.secondary = 12).unwrap();
    i0.start_undo_session();
    i0.remove(ObjectId::new(1)).unwrap();
    i0.squash();
    assert!(i0.find(ObjectId::new(1)).is_none());
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
    assert!(i0.find(ObjectId::new(1)).is_none());
}

#[test]
fn test_modify_modify_undo() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.modify(ObjectId::new(0), |e| e.secondary = 18).unwrap();
    i0.modify(ObjectId::new(0), |e| e.secondary = 24).unwrap();
    assert_eq!(find_secondary(&i0, 0), Some(24));
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
}

#[test]
fn test_modify_modify_squash() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.modify(ObjectId::new(0), |e| e.secondary = 18).unwrap();
    i0.start_undo_session();
    i0.modify(ObjectId::new(0), |e| e.secondary = 24).unwrap();
    i0.squash();
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
}

#[test]
fn test_modify_remove_undo() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.modify(ObjectId::new(0), |e| e.secondary = 18).unwrap();
    i0.remove(ObjectId::new(0)).unwrap();
    assert!(i0.find(ObjectId::new(0)).is_none());
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
}

#[test]
fn test_modify_remove_squash() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.start_undo_session();
    i0.modify(ObjectId::new(0), |e| e.secondary = 18).unwrap();
    i0.start_undo_session();
    i0.remove(ObjectId::new(0)).unwrap();
    i0.squash();
    assert!(i0.find(ObjectId::new(0)).is_none());
    i0.undo();
    assert_state(&i0, &[(0, 42)]);
}

#[test]
fn test_squash_one() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    i0.modify(ObjectId::new(0), |e| e.secondary = 18).unwrap();
    i0.start_undo_session();
    i0.remove(ObjectId::new(0)).unwrap();
    assert!(i0.find(ObjectId::new(0)).is_none());
    // Squashing the only session makes the removal permanent.
    i0.squash();
    assert!(!i0.has_undo_session());
    assert!(i0.find(ObjectId::new(0)).is_none());
}

#[test]
fn test_insert_non_unique() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 42).unwrap();
    let result = i0.emplace(|e| e.secondary = 42);
    assert!(matches!(
        result,
        Err(ChainbaseError::UniquenessViolation { .. })
    ));
    assert_state(&i0, &[(0, 42)]);
}

#[derive(Clone, Default, Debug, PartialEq, NumBytes, Read, Write)]
struct ConflictElement {
    id: ObjectId<ConflictElement>,
    x0: i32,
    x1: i32,
    x2: i32,
}

struct ByX0;
struct ByX1;
struct ByX2;
impl IndexedBy<ConflictElement> for ByX0 {
    type Key = i32;
    fn key(obj: &ConflictElement) -> i32 {
        obj.x0
    }
}
impl IndexedBy<ConflictElement> for ByX1 {
    type Key = i32;
    fn key(obj: &ConflictElement) -> i32 {
        obj.x1
    }
}
impl IndexedBy<ConflictElement> for ByX2 {
    type Key = i32;
    fn key(obj: &ConflictElement) -> i32 {
        obj.x2
    }
}

impl ChainbaseObject for ConflictElement {
    const TYPE_ID: u16 = 2;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![
            key_index::<Self, ByX0>(),
            key_index::<Self, ByX1>(),
            key_index::<Self, ByX2>(),
        ]
    }
}

#[test]
fn test_modify_conflict() {
    let mut i0 = UndoIndex::<ConflictElement>::new();
    // insert 3 elements
    i0.emplace(|e| {
        e.x0 = 0;
        e.x1 = 10;
        e.x2 = 10;
    })
    .unwrap();
    i0.emplace(|e| {
        e.x0 = 11;
        e.x1 = 1;
        e.x2 = 11;
    })
    .unwrap();
    i0.emplace(|e| {
        e.x0 = 12;
        e.x1 = 12;
        e.x2 = 2;
    })
    .unwrap();
    i0.start_undo_session();
    // set them to a different value
    i0.modify(ObjectId::new(0), |e| {
        e.x0 = 10;
        e.x1 = 10;
        e.x2 = 10;
    })
    .unwrap();
    i0.modify(ObjectId::new(1), |e| {
        e.x0 = 11;
        e.x1 = 11;
        e.x2 = 11;
    })
    .unwrap();
    i0.modify(ObjectId::new(2), |e| {
        e.x0 = 12;
        e.x1 = 12;
        e.x2 = 12;
    })
    .unwrap();
    // create a circular conflict with the original values
    i0.modify(ObjectId::new(0), |e| {
        e.x0 = 10;
        e.x1 = 1;
        e.x2 = 10;
    })
    .unwrap();
    i0.modify(ObjectId::new(1), |e| {
        e.x0 = 11;
        e.x1 = 11;
        e.x2 = 2;
    })
    .unwrap();
    i0.modify(ObjectId::new(2), |e| {
        e.x0 = 0;
        e.x1 = 12;
        e.x2 = 12;
    })
    .unwrap();
    // undoing must resolve the circular restore without transient conflicts
    i0.undo();
    assert_eq!(i0.find(ObjectId::new(0)).unwrap().x0, 0);
    assert_eq!(i0.find(ObjectId::new(1)).unwrap().x1, 1);
    assert_eq!(i0.find(ObjectId::new(2)).unwrap().x2, 2);
    // Check lookup in the other indices
    assert_eq!(i0.get_index::<ByX0>().find(&0).unwrap().x0, 0);
    assert_eq!(i0.get_index::<ByX0>().find(&11).unwrap().x0, 11);
    assert_eq!(i0.get_index::<ByX0>().find(&12).unwrap().x0, 12);
    assert_eq!(i0.get_index::<ByX1>().find(&10).unwrap().x1, 10);
    assert_eq!(i0.get_index::<ByX1>().find(&1).unwrap().x1, 1);
    assert_eq!(i0.get_index::<ByX1>().find(&12).unwrap().x1, 12);
    assert_eq!(i0.get_index::<ByX2>().find(&10).unwrap().x2, 10);
    assert_eq!(i0.get_index::<ByX2>().find(&11).unwrap().x2, 11);
    assert_eq!(i0.get_index::<ByX2>().find(&2).unwrap().x2, 2);
}

fn insert_fail_check(i0: &UndoIndex<ConflictElement>) {
    assert_eq!(i0.find(ObjectId::new(0)).unwrap().x0, 10);
    assert_eq!(i0.find(ObjectId::new(1)).unwrap().x1, 11);
    assert_eq!(i0.find(ObjectId::new(2)).unwrap().x2, 12);
    for key in [10, 11, 12] {
        assert_eq!(i0.get_index::<ByX0>().find(&key).unwrap().x0, key);
        assert_eq!(i0.get_index::<ByX1>().find(&key).unwrap().x1, key);
        assert_eq!(i0.get_index::<ByX2>().find(&key).unwrap().x2, key);
    }
}

#[test]
fn test_insert_fail() {
    for use_undo in [true, false] {
        let mut i0 = UndoIndex::<ConflictElement>::new();
        for v in [10, 11, 12] {
            i0.emplace(|e| {
                e.x0 = v;
                e.x1 = v;
                e.x2 = v;
            })
            .unwrap();
        }
        if use_undo {
            i0.start_undo_session();
        }
        // Insert a value with a duplicate
        let result = i0.emplace(|e| {
            e.x0 = 81;
            e.x1 = 11;
            e.x2 = 91;
        });
        assert!(matches!(
            result,
            Err(ChainbaseError::UniquenessViolation { .. })
        ));
        if use_undo {
            i0.undo();
        }
        assert_eq!(i0.len(), 3);
        insert_fail_check(&i0);
    }
}

#[test]
fn test_modify_fail() {
    let mut i0 = UndoIndex::<ConflictElement>::new();
    for v in [10, 11, 12] {
        i0.emplace(|e| {
            e.x0 = v;
            e.x1 = v;
            e.x2 = v;
        })
        .unwrap();
    }
    i0.start_undo_session();
    i0.emplace(|e| {
        e.x0 = 71;
        e.x1 = 81;
        e.x2 = 91;
    })
    .unwrap();
    // Modify to a value with a duplicate
    let result = i0.modify(ObjectId::new(3), |e| {
        e.x0 = 71;
        e.x1 = 10;
        e.x2 = 91;
    });
    assert!(matches!(
        result,
        Err(ChainbaseError::UniquenessViolation { .. })
    ));
    // Strong guarantee: the failed modify left the object unchanged.
    assert_eq!(i0.find(ObjectId::new(3)).unwrap().x1, 81);
    i0.undo();
    assert_eq!(i0.len(), 3);
    assert_eq!(i0.get_index::<ByX0>().len(), 3);
    assert_eq!(i0.get_index::<ByX1>().len(), 3);
    assert_eq!(i0.get_index::<ByX2>().len(), 3);
    insert_fail_check(&i0);
}

#[test]
fn test_commit_partial() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 1).unwrap();
    i0.start_undo_session(); // revision 1
    i0.modify(ObjectId::new(0), |e| e.secondary = 2).unwrap();
    i0.start_undo_session(); // revision 2
    i0.modify(ObjectId::new(0), |e| e.secondary = 3).unwrap();
    i0.start_undo_session(); // revision 3
    i0.modify(ObjectId::new(0), |e| e.secondary = 4).unwrap();
    assert_eq!(i0.undo_stack_revision_range(), (0, 3));

    i0.commit(2); // revisions 1 and 2 become permanent
    assert_eq!(i0.undo_stack_revision_range(), (2, 3));
    i0.undo_all();
    assert_eq!(i0.revision(), 2);
    // Only the change of revision 3 was undone.
    assert_eq!(find_secondary(&i0, 0), Some(3));
}

#[test]
fn test_set_revision() {
    let mut i0 = UndoIndex::<TestElement>::new();
    assert_eq!(i0.revision(), 0);
    i0.set_revision(42).unwrap();
    assert_eq!(i0.revision(), 42);
    // decreasing is an error
    assert!(i0.set_revision(41).is_err());
    // setting with an active undo stack is an error
    i0.start_undo_session();
    assert!(i0.set_revision(50).is_err());
}

#[test]
fn test_id_reuse_after_undo() {
    let mut i0 = UndoIndex::<TestElement>::new();
    i0.emplace(|e| e.secondary = 1).unwrap();
    i0.start_undo_session();
    i0.emplace(|e| e.secondary = 2).unwrap();
    assert_eq!(i0.next_id(), 2);
    i0.undo();
    // an id is reused only if its insertion is undone
    assert_eq!(i0.next_id(), 1);
    let created = i0.emplace(|e| e.secondary = 3).unwrap();
    assert_eq!(created.id.raw(), 1);
}

#[test]
fn test_secondary_iteration() {
    let mut i0 = UndoIndex::<TestElement>::new();
    for v in [30, 10, 20] {
        i0.emplace(|e| e.secondary = v).unwrap();
    }
    let by_secondary = i0.get_index::<BySecondary>();
    let keys: Vec<i32> = by_secondary.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, vec![10, 20, 30]);
    let lower: Vec<i32> = by_secondary.lower_bound(&20).map(|(k, _)| *k).collect();
    assert_eq!(lower, vec![20, 30]);
    let upper: Vec<i32> = by_secondary.upper_bound(&20).map(|(k, _)| *k).collect();
    assert_eq!(upper, vec![30]);
    let reversed: Vec<i32> = by_secondary.iter().rev().map(|(k, _)| *k).collect();
    assert_eq!(reversed, vec![30, 20, 10]);
}
