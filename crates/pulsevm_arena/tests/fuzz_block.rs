//! Block-level differential fuzzing of the undo structure block creation uses.
//!
//! A block is an undo session; each transaction is a nested session that is
//! *squashed* into the block on success or *undone* on failure; accepting the
//! block squashes it into the base. This is the exact shape the controller
//! drives, and it is where consensus divergences hide (a failed tx must leave
//! no trace, a succeeded one must be exactly its own effect).
//!
//! proptest generates random blocks of random transactions with random
//! success/failure, runs them against the engine and an obviously-correct
//! full-snapshot reference, and asserts identical state after every tx and
//! every block.

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
}
impl Model {
    fn new() -> Self {
        Model {
            rows: BTreeMap::new(),
            next_id: 0,
            snaps: Vec::new(),
        }
    }
    fn ids(&self) -> Vec<i64> {
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
    }
    fn undo(&mut self) {
        if let Some((r, n)) = self.snaps.pop() {
            self.rows = r;
            self.next_id = n;
        }
    }
    fn squash(&mut self) {
        self.snaps.pop();
    }
    fn state(&self) -> Vec<(i64, u64)> {
        self.rows.iter().map(|(&k, &v)| (k, v)).collect()
    }
}

#[derive(Debug, Clone)]
enum Op {
    Create(u64),
    Modify(usize, u64),
    Remove(usize),
}

#[derive(Debug, Clone)]
struct Tx {
    ops: Vec<Op>,
    commit: bool,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        any::<u64>().prop_map(Op::Create),
        (any::<usize>(), any::<u64>()).prop_map(|(i, v)| Op::Modify(i, v)),
        any::<usize>().prop_map(Op::Remove),
    ]
}

fn tx() -> impl Strategy<Value = Tx> {
    (vec(op(), 0..8), any::<bool>()).prop_map(|(ops, commit)| Tx { ops, commit })
}

fn apply_op(table: &mut Table<Row>, model: &mut Model, op: &Op) {
    match op {
        Op::Create(v) => {
            table.emplace(|r| r.value = *v).unwrap();
            model.create(*v);
        }
        Op::Modify(sel, v) => {
            let ids = model.ids();
            if !ids.is_empty() {
                let id = ids[sel % ids.len()];
                table.modify(ObjectId::new(id), |r| r.value = *v).unwrap();
                model.modify(id, *v);
            }
        }
        Op::Remove(sel) => {
            let ids = model.ids();
            if !ids.is_empty() {
                let id = ids[sel % ids.len()];
                table.remove(ObjectId::new(id)).unwrap();
                model.remove(id);
            }
        }
    }
}

fn state(t: &Table<Row>) -> Vec<(i64, u64)> {
    t.iter().map(|r| (r.id().raw(), r.value)).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(600))]

    #[test]
    fn blocks_of_transactions_match_reference(blocks in vec(vec(tx(), 0..6), 0..15)) {
        let mut table = Table::<Row>::new();
        let mut model = Model::new();

        for block in blocks {
            table.start_undo_session();   // block session
            model.session();
            for t in block {
                table.start_undo_session(); // transaction session
                model.session();
                for op in &t.ops {
                    apply_op(&mut table, &mut model, op);
                }
                if t.commit {
                    table.squash(); // fold the tx into the block
                    model.squash();
                } else {
                    table.undo(); // a failed tx leaves no trace
                    model.undo();
                }
                prop_assert_eq!(state(&table), model.state());
            }
            table.squash(); // accept the block
            model.squash();
            prop_assert_eq!(state(&table), model.state());
        }
    }
}
