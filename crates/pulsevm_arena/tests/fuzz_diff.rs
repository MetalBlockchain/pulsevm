//! Differential fuzzing of the undo engine.
//!
//! This is the shape of the verification that closes the consensus tail: drive
//! a random sequence of operations against the real store and an obviously
//! correct reference, and assert they agree after *every* step. proptest
//! generates the sequences and shrinks any failure to a minimal reproducer.
//!
//! The reference here is a full-snapshot model — session start clones the whole
//! state and undo restores the clone — which is trivially correct but slow.

use std::collections::BTreeMap;

use proptest::{
    collection::vec,
    prelude::*,
};
use pulsevm_arena::{
    ArenaObject,
    ObjectId,
    Table,
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
)]
struct Row {
    id: ObjectId<Row>,
    value: u64,
}
impl ArenaObject for Row {
    const TYPE_ID: u16 = 0;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
}

/// The obviously-correct reference: state plus a stack of full snapshots.
struct Model {
    rows: BTreeMap<i64, u64>,
    next_id: i64,
    snaps: Vec<(BTreeMap<i64, u64>, i64)>,
    revision: i64,
}

impl Model {
    fn new() -> Self {
        Model {
            rows: BTreeMap::new(),
            next_id: 0,
            snaps: Vec::new(),
            revision: 0,
        }
    }
    fn live_ids(&self) -> Vec<i64> {
        self.rows.keys().copied().collect()
    }
    fn create(&mut self, v: u64) {
        self.rows.insert(self.next_id, v);
        self.next_id += 1;
    }
    fn modify(&mut self, id: i64, v: u64) {
        self.rows.insert(id, v);
    }
    fn remove(&mut self, id: i64) {
        self.rows.remove(&id);
    }
    fn session(&mut self) {
        self.snaps.push((self.rows.clone(), self.next_id));
        self.revision += 1;
    }
    fn undo(&mut self) {
        if let Some((r, n)) = self.snaps.pop() {
            self.rows = r;
            self.next_id = n;
            self.revision -= 1;
        }
    }
    fn squash(&mut self) {
        // Merge the top session into the one below: drop the top snapshot, so a
        // later undo reverts to the earlier baseline (which predates both).
        if self.snaps.pop().is_some() {
            self.revision -= 1;
        }
    }
    fn commit(&mut self, rev: i64) {
        let rev = rev.min(self.revision);
        let keep = (self.revision - rev).max(0) as usize;
        while self.snaps.len() > keep {
            self.snaps.remove(0);
        }
    }
    fn snapshot(&self) -> Vec<(i64, u64)> {
        self.rows.iter().map(|(&k, &v)| (k, v)).collect()
    }
}

#[derive(Debug, Clone)]
enum Op {
    Create(u64),
    Modify(usize, u64),
    Remove(usize),
    Session,
    Undo,
    Squash,
    Commit(u8),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        any::<u64>().prop_map(Op::Create),
        (any::<usize>(), any::<u64>()).prop_map(|(i, v)| Op::Modify(i, v)),
        any::<usize>().prop_map(Op::Remove),
        Just(Op::Session),
        Just(Op::Undo),
        Just(Op::Squash),
        any::<u8>().prop_map(Op::Commit),
    ]
}

fn arena_snapshot(t: &Table<Row>) -> Vec<(i64, u64)> {
    t.iter().map(|r| (r.id().raw(), r.value)).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn arena_matches_reference(ops in vec(op_strategy(), 0..300)) {
        let mut table = Table::<Row>::new();
        let mut model = Model::new();

        for op in ops {
            match op {
                Op::Create(v) => {
                    table.emplace(|r| r.value = v).unwrap();
                    model.create(v);
                }
                Op::Modify(sel, v) => {
                    let ids = model.live_ids();
                    if !ids.is_empty() {
                        let id = ids[sel % ids.len()];
                        table.modify(ObjectId::new(id), |r| r.value = v).unwrap();
                        model.modify(id, v);
                    }
                }
                Op::Remove(sel) => {
                    let ids = model.live_ids();
                    if !ids.is_empty() {
                        let id = ids[sel % ids.len()];
                        table.remove(ObjectId::new(id)).unwrap();
                        model.remove(id);
                    }
                }
                Op::Session => { table.start_undo_session(); model.session(); }
                Op::Undo => { table.undo(); model.undo(); }
                Op::Squash => { table.squash(); model.squash(); }
                Op::Commit(depth) => {
                    let rev = model.revision - (depth as i64);
                    table.commit(rev);
                    model.commit(rev);
                }
            }
            // The invariant: identical live state and revision after every op.
            prop_assert_eq!(arena_snapshot(&table), model.snapshot());
            prop_assert_eq!(table.revision(), model.revision);
        }
    }
}
