//! Differential fuzzing of persistence: apply random operations, flush the WAL
//! at random points, then reopen from disk and assert the reloaded state equals
//! the live state. This is what makes the incremental delta log trustworthy —
//! any mismatch between "in memory" and "reloaded" shrinks to a minimal case.

use proptest::collection::vec;
use proptest::prelude::*;
use pulsevm_arena::{ArenaObject, Db, IndexedBy, ObjectId, SecondaryIndex, key_index};

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
struct Account {
    id: ObjectId<Account>,
    name: u64,
    value: u64,
}
struct ByName;
impl IndexedBy<Account> for ByName {
    type Key = u64;
    fn key(a: &Account) -> u64 {
        a.name
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
        vec![key_index::<Self, ByName>()]
    }
}

fn new_db() -> Db {
    let mut db = Db::new();
    db.add_table::<Account>().unwrap();
    db
}

// A monotonically increasing name avoids secondary-key collisions so ops never
// fail for reasons unrelated to persistence.
#[derive(Debug, Clone)]
enum Op {
    Create,
    ModifyValue(usize, u64),
    Remove(usize),
    Flush,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => Just(Op::Create),
        2 => (any::<usize>(), any::<u64>()).prop_map(|(i, v)| Op::ModifyValue(i, v)),
        1 => any::<usize>().prop_map(Op::Remove),
        2 => Just(Op::Flush),
    ]
}

fn state(db: &Db) -> Vec<(i64, u64, u64)> {
    db.table::<Account>()
        .unwrap()
        .iter()
        .map(|a| (a.id().raw(), a.name, a.value))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(80))]

    #[test]
    fn reload_equals_live_state(ops in vec(op(), 0..120)) {
        let dir = tempfile::tempdir().unwrap();
        let snap = dir.path().join("state");
        let wal = dir.path().join("wal");

        let mut db = new_db();
        db.checkpoint(&snap).unwrap(); // empty baseline; all changes go to the WAL
        let mut next_name = 0u64;

        for op in ops {
            match op {
                Op::Create => {
                    db.create::<Account>(|a| a.name = next_name).unwrap();
                    next_name += 1;
                }
                Op::ModifyValue(sel, v) => {
                    let ids: Vec<i64> = db.table::<Account>().unwrap().iter().map(|a| a.id().raw()).collect();
                    if !ids.is_empty() {
                        let id = ids[sel % ids.len()];
                        db.modify::<Account>(ObjectId::new(id), |a| a.value = v).unwrap();
                    }
                }
                Op::Remove(sel) => {
                    let ids: Vec<i64> = db.table::<Account>().unwrap().iter().map(|a| a.id().raw()).collect();
                    if !ids.is_empty() {
                        let id = ids[sel % ids.len()];
                        db.remove::<Account>(ObjectId::new(id)).unwrap();
                    }
                }
                Op::Flush => { db.flush_delta(&wal).unwrap(); }
            }
        }
        db.flush_delta(&wal).unwrap(); // capture anything since the last flush

        let mut reloaded = new_db();
        reloaded.load(&snap).unwrap();
        reloaded.replay_log(&wal).unwrap();

        prop_assert_eq!(state(&reloaded), state(&db));
    }
}
