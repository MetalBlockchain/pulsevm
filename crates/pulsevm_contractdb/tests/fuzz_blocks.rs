//! Block-level differential fuzzing of the contract state machine.
//!
//! Random blocks of transactions run against the real ContractDb and an
//! obviously-correct reference; each transaction commits (squash) or fails
//! (undo). After every block, the full logical state — rows *and* per-account
//! RAM — must match. This is the consensus invariant for block creation: a
//! failed transaction leaves no trace in either rows or RAM, a successful one
//! is exactly its own effect. Point the reference at C++ and it is the
//! Rust-vs-chainbase block check.

use std::collections::{
    BTreeMap,
    BTreeSet,
};

use proptest::{
    collection::vec,
    prelude::*,
};
use pulsevm_contractdb::ContractDb;

const CODE: u64 = 10;
const TABLE: u64 = 20;
const KV_OVERHEAD: i64 = 112;
const TABLE_OVERHEAD: i64 = 112;

type Rows = BTreeMap<(u64, u64, u64, u64), (u64, Vec<u8>)>;
type Tables = BTreeSet<(u64, u64, u64)>;
type Ram = BTreeMap<u64, i64>;
type Snapshot = (Rows, Tables, Ram);
type Dump = (Vec<(u64, u64, u64, u64, u64, Vec<u8>)>, Vec<(u64, i64)>);

/// Obviously-correct reference with full-snapshot undo.
#[derive(Clone, Default)]
struct Model {
    rows: Rows,
    tables: Tables,
    ram: Ram,
    snaps: Vec<Snapshot>,
}

impl Model {
    fn bill(&mut self, account: u64, delta: i64) {
        *self.ram.entry(account).or_insert(0) += delta;
    }
    fn store(&mut self, scope: u64, payer: u64, pk: u64, value: Vec<u8>) {
        if self.tables.insert((CODE, scope, TABLE)) {
            self.bill(payer, TABLE_OVERHEAD);
        }
        self.bill(payer, KV_OVERHEAD + value.len() as i64);
        self.rows.insert((CODE, scope, TABLE, pk), (payer, value));
    }
    fn update(&mut self, key: (u64, u64, u64, u64), payer: u64, value: Vec<u8>) {
        let (old_payer, old_value) = self.rows[&key].clone();
        let old_bytes = old_value.len() as i64 + KV_OVERHEAD;
        let new_bytes = value.len() as i64 + KV_OVERHEAD;
        if old_payer == payer {
            self.bill(payer, new_bytes - old_bytes);
        } else {
            self.bill(old_payer, -old_bytes);
            self.bill(payer, new_bytes);
        }
        self.rows.insert(key, (payer, value));
    }
    fn remove(&mut self, key: (u64, u64, u64, u64)) {
        let (payer, value) = self.rows.remove(&key).unwrap();
        self.bill(payer, -(value.len() as i64 + KV_OVERHEAD));
    }
    fn nth_key(&self, sel: usize) -> Option<(u64, u64, u64, u64)> {
        if self.rows.is_empty() {
            None
        } else {
            Some(*self.rows.keys().nth(sel % self.rows.len()).unwrap())
        }
    }
    fn session(&mut self) {
        self.snaps
            .push((self.rows.clone(), self.tables.clone(), self.ram.clone()));
    }
    fn undo(&mut self) {
        if let Some((r, t, m)) = self.snaps.pop() {
            self.rows = r;
            self.tables = t;
            self.ram = m;
        }
    }
    fn squash(&mut self) {
        self.snaps.pop();
    }
    fn dump(&self) -> Dump {
        let rows = self
            .rows
            .iter()
            .map(|(&(c, s, t, p), (payer, v))| (c, s, t, p, *payer, v.clone()))
            .collect();
        let ram = self
            .ram
            .iter()
            .filter(|(_, b)| **b != 0)
            .map(|(a, b)| (*a, *b))
            .collect();
        (rows, ram)
    }
}

#[derive(Debug, Clone)]
enum Op {
    Store {
        scope: u8,
        payer: u8,
        value: Vec<u8>,
    },
    Update {
        sel: usize,
        payer: u8,
        value: Vec<u8>,
    },
    Remove {
        sel: usize,
    },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u8..3, 0u8..4, vec(any::<u8>(), 0..12))
            .prop_map(|(scope, payer, value)| Op::Store { scope, payer, value }),
        2 => (any::<usize>(), 0u8..4, vec(any::<u8>(), 0..12))
            .prop_map(|(sel, payer, value)| Op::Update { sel, payer, value }),
        1 => any::<usize>().prop_map(|sel| Op::Remove { sel }),
    ]
}

#[derive(Debug, Clone)]
struct Tx {
    ops: Vec<Op>,
    commit: bool,
}
fn tx() -> impl Strategy<Value = Tx> {
    (vec(op(), 0..6), any::<bool>()).prop_map(|(ops, commit)| Tx { ops, commit })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn blocks_produce_identical_state(blocks in vec(vec(tx(), 0..5), 0..12)) {
        let mut cdb = ContractDb::new();
        let mut model = Model::default();
        let mut next_pk = 0u64;

        for block in blocks {
            cdb.start_undo_session();
            model.session();
            for t in block {
                cdb.reset_iterators();
                cdb.start_undo_session();
                model.session();
                for op in &t.ops {
                    match op {
                        Op::Store { scope, payer, value } => {
                            let (scope, payer) = (*scope as u64, *payer as u64);
                            cdb.db_store_i64(CODE, scope, TABLE, payer, next_pk, value);
                            model.store(scope, payer, next_pk, value.clone());
                            next_pk += 1;
                        }
                        Op::Update { sel, payer, value } => {
                            if let Some(key) = model.nth_key(*sel) {
                                let it = cdb.db_find_i64(key.0, key.1, key.2, key.3);
                                cdb.db_update_i64(it, *payer as u64, value);
                                model.update(key, *payer as u64, value.clone());
                            }
                        }
                        Op::Remove { sel } => {
                            if let Some(key) = model.nth_key(*sel) {
                                let it = cdb.db_find_i64(key.0, key.1, key.2, key.3);
                                cdb.db_remove_i64(it);
                                model.remove(key);
                            }
                        }
                    }
                }
                if t.commit {
                    cdb.squash();
                    model.squash();
                } else {
                    cdb.undo();
                    model.undo();
                }
            }
            cdb.squash(); // accept the block
            model.squash();
            prop_assert_eq!(cdb.dump(), model.dump());
        }
    }
}
