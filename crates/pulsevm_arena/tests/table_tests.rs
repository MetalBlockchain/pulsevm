use pulsevm_arena::{
    ArenaObject,
    IndexedBy,
    ObjectId,
    SecondaryIndex,
    Table,
    TableError,
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
    value: u64,
}

struct ByName;
impl IndexedBy<Account> for ByName {
    type Key = u64;
    fn key(obj: &Account) -> u64 {
        obj.name
    }
}

impl ArenaObject for Account {
    const TYPE_ID: u16 = 0;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![key_index::<Self, ByName>()]
    }
}

fn mk() -> Table<Account> {
    Table::new()
}

#[test]
fn create_assigns_sequential_ids_and_finds() {
    let mut t = mk();
    let a = *t.emplace(|a| a.name = 10).unwrap();
    let b = *t.emplace(|a| a.name = 20).unwrap();
    assert_eq!(a.id.raw(), 0);
    assert_eq!(b.id.raw(), 1);
    assert_eq!(t.find(ObjectId::new(0)).unwrap().name, 10);
    assert_eq!(t.get_index::<ByName>().find(&20).unwrap().id.raw(), 1);
    assert_eq!(t.len(), 2);
}

#[test]
fn uniqueness_violation_leaves_table_unchanged() {
    let mut t = mk();
    t.emplace(|a| a.name = 10).unwrap();
    let err = t.emplace(|a| a.name = 10).unwrap_err();
    assert!(matches!(err, TableError::UniquenessViolation { .. }));
    // The failed insert consumed no id and left one row.
    assert_eq!(t.len(), 1);
    let c = t.emplace(|a| a.name = 30).unwrap();
    assert_eq!(c.id.raw(), 1);
}

#[test]
fn modify_non_key_field() {
    let mut t = mk();
    t.emplace(|a| a.name = 10).unwrap();
    t.modify(ObjectId::new(0), |a| a.value = 99).unwrap();
    assert_eq!(t.find(ObjectId::new(0)).unwrap().value, 99);
    // by_name still resolves.
    assert_eq!(t.get_index::<ByName>().find(&10).unwrap().value, 99);
}

#[test]
fn modify_secondary_key_moves_index_entry() {
    let mut t = mk();
    t.emplace(|a| a.name = 10).unwrap();
    t.modify(ObjectId::new(0), |a| a.name = 11).unwrap();
    assert!(t.get_index::<ByName>().find(&10).is_none());
    assert_eq!(t.get_index::<ByName>().find(&11).unwrap().id.raw(), 0);
}

#[test]
fn remove_tombstones_and_frees_key() {
    let mut t = mk();
    t.emplace(|a| a.name = 10).unwrap();
    t.emplace(|a| a.name = 20).unwrap();
    t.remove(ObjectId::new(0)).unwrap();
    assert!(t.find(ObjectId::new(0)).is_none());
    assert!(t.get_index::<ByName>().find(&10).is_none());
    assert_eq!(t.len(), 1);
    // Id is not reused: next create takes id 2, not the freed 0.
    let c = t.emplace(|a| a.name = 30).unwrap();
    assert_eq!(c.id.raw(), 2);
}

#[test]
fn undo_reverts_creates() {
    let mut t = mk();
    t.emplace(|a| a.name = 1).unwrap();
    let rev = t.start_undo_session();
    assert_eq!(rev, 1);
    t.emplace(|a| a.name = 2).unwrap();
    t.emplace(|a| a.name = 3).unwrap();
    assert_eq!(t.len(), 3);
    t.undo();
    assert_eq!(t.len(), 1);
    assert!(t.get_index::<ByName>().find(&2).is_none());
    // Ids created in the session are released; next id is 1 again.
    let c = t.emplace(|a| a.name = 9).unwrap();
    assert_eq!(c.id.raw(), 1);
}

#[test]
fn undo_reverts_modifies_to_oldest_value() {
    let mut t = mk();
    t.emplace(|a| a.name = 10).unwrap();
    t.start_undo_session();
    t.modify(ObjectId::new(0), |a| a.value = 1).unwrap();
    t.modify(ObjectId::new(0), |a| a.value = 2).unwrap();
    t.undo();
    assert_eq!(t.find(ObjectId::new(0)).unwrap().value, 0);
}

#[test]
fn undo_restores_removed_rows_and_keys() {
    let mut t = mk();
    t.emplace(|a| a.name = 10).unwrap();
    t.emplace(|a| a.name = 20).unwrap();
    t.start_undo_session();
    t.remove(ObjectId::new(1)).unwrap();
    assert_eq!(t.len(), 1);
    t.undo();
    assert_eq!(t.len(), 2);
    assert_eq!(t.find(ObjectId::new(1)).unwrap().name, 20);
    assert_eq!(t.get_index::<ByName>().find(&20).unwrap().id.raw(), 1);
}

#[test]
fn undo_handles_two_rows_swapping_keys() {
    // A modify that trades a unique key between two live rows must undo without
    // a transient collision.
    let mut t = mk();
    t.emplace(|a| a.name = 1).unwrap();
    t.emplace(|a| a.name = 2).unwrap();
    t.start_undo_session();
    // Move row 0 out of the way, give its key to row 1, then reuse it.
    t.modify(ObjectId::new(0), |a| a.name = 99).unwrap();
    t.modify(ObjectId::new(1), |a| a.name = 1).unwrap();
    t.modify(ObjectId::new(0), |a| a.name = 2).unwrap();
    t.undo();
    assert_eq!(t.find(ObjectId::new(0)).unwrap().name, 1);
    assert_eq!(t.find(ObjectId::new(1)).unwrap().name, 2);
    assert_eq!(t.get_index::<ByName>().find(&1).unwrap().id.raw(), 0);
    assert_eq!(t.get_index::<ByName>().find(&2).unwrap().id.raw(), 1);
}

#[test]
fn squash_merges_into_previous_session() {
    let mut t = mk();
    t.emplace(|a| a.name = 10).unwrap();
    t.start_undo_session();
    t.modify(ObjectId::new(0), |a| a.value = 1).unwrap();
    t.start_undo_session();
    t.modify(ObjectId::new(0), |a| a.value = 2).unwrap();
    t.squash();
    assert_eq!(t.revision(), 1);
    // Squash kept the change; undoing the merged session restores the original.
    t.undo();
    assert_eq!(t.find(ObjectId::new(0)).unwrap().value, 0);
}

#[test]
fn undo_changes_match_chainbase_push_front_order() {
    let mut t = mk();
    for name in [10, 20, 30, 40] {
        t.emplace(|a| a.name = name).unwrap();
    }

    t.start_undo_session();
    t.modify(ObjectId::new(0), |a| a.value = 1).unwrap();
    t.modify(ObjectId::new(2), |a| a.value = 2).unwrap();
    // A repeated modification keeps the oldest value and its original touch
    // position, just as chainbase's compressed undo list does.
    t.modify(ObjectId::new(0), |a| a.value = 3).unwrap();
    t.remove(ObjectId::new(1)).unwrap();
    t.remove(ObjectId::new(3)).unwrap();

    let changes = t.last_undo_session_changes().unwrap();
    let modified: Vec<i64> = changes.old_values.iter().map(|(id, _)| *id).collect();
    let removed: Vec<i64> = changes.removed_values.iter().map(|(id, _)| *id).collect();
    assert_eq!(modified, vec![2, 0]);
    assert_eq!(removed, vec![3, 1]);
    assert_eq!(changes.old_values[1].1.value, 0);
}

#[test]
fn squashed_undo_changes_keep_reverse_timeline_order() {
    let mut t = mk();
    for name in [10, 20, 30] {
        t.emplace(|a| a.name = name).unwrap();
    }

    t.start_undo_session();
    t.modify(ObjectId::new(0), |a| a.value = 1).unwrap();
    t.start_undo_session();
    t.modify(ObjectId::new(1), |a| a.value = 1).unwrap();
    t.modify(ObjectId::new(0), |a| a.value = 2).unwrap();
    t.modify(ObjectId::new(2), |a| a.value = 1).unwrap();
    t.squash();

    let changes = t.last_undo_session_changes().unwrap();
    let modified: Vec<i64> = changes.old_values.iter().map(|(id, _)| *id).collect();
    assert_eq!(modified, vec![2, 1, 0]);
    // The parent session's pre-change value wins when both sessions touched it.
    assert_eq!(changes.old_values[2].1.value, 0);
}

#[test]
fn commit_drops_undo_history() {
    let mut t = mk();
    let r0 = t.start_undo_session();
    t.emplace(|a| a.name = 10).unwrap();
    let r1 = t.start_undo_session();
    t.emplace(|a| a.name = 20).unwrap();
    assert_eq!((r0, r1), (1, 2));
    t.commit(t.revision());
    // Nothing left to undo; state persists.
    t.undo();
    assert_eq!(t.len(), 2);
}

#[test]
fn lower_bound_scans_in_key_order() {
    let mut t = mk();
    for n in [5u64, 1, 9, 3, 7] {
        t.emplace(|a| a.name = n).unwrap();
    }
    let got: Vec<u64> = t
        .get_index::<ByName>()
        .lower_bound(&3)
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(got, vec![3, 5, 7, 9]);
}
