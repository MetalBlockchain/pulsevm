//! Benchmarks for the Rust chainbase, mirroring the operations that
//! `pulsevm_ffi/benches/{insert,read}.rs` run against the C++ FFI database so
//! the two implementations can be compared, plus the undo machinery and the
//! persistence layer.
//!
//! Run with `cargo bench -p pulsevm_chainbase`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pulsevm_chainbase::{
    ChainbaseObject, Database, IndexedBy, ObjectId, OpenFlags, SecondaryIndex, UndoIndex,
    key_index,
};
use pulsevm_proc_macros::{NumBytes, Read, Write};

#[derive(Clone, Default, Debug, NumBytes, Read, Write)]
struct Account {
    id: ObjectId<Account>,
    name: u64,
    data: Vec<u8>,
}

struct ByName;
impl IndexedBy<Account> for ByName {
    type Key = u64;
    fn key(obj: &Account) -> u64 {
        obj.name
    }
}

impl ChainbaseObject for Account {
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

const DATA_LEN: usize = 64;
const SIZES: [u64; 2] = [1_000, 100_000];

fn populated_db(rows: u64) -> Database {
    let db = Database::new();
    db.add_index::<Account>().unwrap();
    for i in 0..rows {
        db.create::<Account>(|a| {
            a.name = i;
            a.data = vec![0xAB; DATA_LEN];
        })
        .unwrap();
    }
    db
}

/// Counterpart of the FFI `insert` bench (`db.create_account(n)`).
fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert");

    let db = populated_db(0);
    let mut n = 0u64;
    group.bench_function("database_create", |b| {
        b.iter(|| {
            db.create::<Account>(|a| a.name = black_box(n)).unwrap();
            n += 1;
        })
    });

    // The same insert without the handle lock and clone-out, to isolate their cost.
    let mut index = UndoIndex::<Account>::new();
    let mut m = 0u64;
    group.bench_function("undo_index_emplace", |b| {
        b.iter(|| {
            index.emplace(|a| a.name = black_box(m)).unwrap();
            m += 1;
        })
    });

    group.finish();
}

/// Counterpart of the FFI `read` bench (`find_account(name)`).
fn bench_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("read");
    for rows in SIZES {
        let db = populated_db(rows);
        let mut n = 0u64;
        group.bench_with_input(BenchmarkId::new("find_by_name", rows), &rows, |b, rows| {
            b.iter(|| {
                let account = db.find_by::<Account, ByName>(black_box(&(n % rows))).unwrap();
                n += 1;
                black_box(account)
            })
        });

        let mut m = 0i64;
        group.bench_with_input(BenchmarkId::new("find_by_id", rows), &rows, |b, rows| {
            b.iter(|| {
                let account = db.find::<Account>(ObjectId::new(black_box(m % *rows as i64))).unwrap();
                m += 1;
                black_box(account)
            })
        });

        // By-reference lookup under the lock, no clone-out.
        let mut k = 0u64;
        group.bench_with_input(
            BenchmarkId::new("find_by_name_no_clone", rows),
            &rows,
            |b, rows| {
                b.iter(|| {
                    let name = db
                        .with_index::<Account, _>(|idx| {
                            idx.get_index::<ByName>().find(black_box(&(k % rows))).map(|a| a.name)
                        })
                        .unwrap();
                    k += 1;
                    black_box(name)
                })
            },
        );
    }

    // Walk 100 consecutive entries through the secondary index.
    let db = populated_db(100_000);
    let mut start = 0u64;
    group.bench_function("lower_bound_scan_100", |b| {
        b.iter(|| {
            let sum = db
                .with_index::<Account, _>(|idx| {
                    idx.get_index::<ByName>()
                        .lower_bound(black_box(&(start % 99_000)))
                        .take(100)
                        .map(|(_, a)| a.name)
                        .sum::<u64>()
                })
                .unwrap();
            start += 137;
            black_box(sum)
        })
    });
    group.finish();
}

fn bench_modify(c: &mut Criterion) {
    let mut group = c.benchmark_group("modify");
    let rows = 100_000;
    let db = populated_db(rows);

    // Touch a non-indexed field: no reindexing needed.
    let mut n = 0i64;
    group.bench_function("non_key_field", |b| {
        b.iter(|| {
            let account = db.get::<Account>(ObjectId::new(n % rows as i64)).unwrap();
            db.modify(&account, |a| a.data[0] = a.data[0].wrapping_add(1))
                .unwrap();
            n += 1;
        })
    });

    // Change the secondary key: erase + reinsert in the name index.
    let mut m = 0i64;
    let mut next_name = rows;
    group.bench_function("secondary_key", |b| {
        b.iter(|| {
            let account = db.get::<Account>(ObjectId::new(m % rows as i64)).unwrap();
            db.modify(&account, |a| a.name = black_box(next_name)).unwrap();
            m += 1;
            next_name += 1;
        })
    });
    group.finish();
}

/// The undo lifecycle the controller exercises per transaction/block:
/// session + changes + undo (failed transaction), squash (successful
/// transaction into block) and push+commit (accepted block).
fn bench_undo(c: &mut Criterion) {
    let mut group = c.benchmark_group("undo");
    let rows = 100_000;
    const CHANGES: i64 = 100;

    let db = populated_db(rows);
    let mut n = 0i64;
    group.bench_function("session_100_modifies_undo", |b| {
        b.iter(|| {
            let session = db.start_undo_session(true).unwrap();
            for i in 0..CHANGES {
                let id = ObjectId::new((n + i) % rows as i64);
                let account = db.get::<Account>(id).unwrap();
                db.modify(&account, |a| a.data[0] = a.data[0].wrapping_add(1))
                    .unwrap();
            }
            n += CHANGES;
            drop(session); // undo
        })
    });

    let mut m = 0i64;
    group.bench_function("session_100_modifies_squash", |b| {
        b.iter(|| {
            let mut outer = db.start_undo_session(true).unwrap();
            {
                let mut inner = db.start_undo_session(true).unwrap();
                for i in 0..CHANGES {
                    let id = ObjectId::new((m + i) % rows as i64);
                    let account = db.get::<Account>(id).unwrap();
                    db.modify(&account, |a| a.data[0] = a.data[0].wrapping_add(1))
                        .unwrap();
                }
                m += CHANGES;
                inner.squash();
            }
            outer.undo(); // restore the baseline for the next iteration
        })
    });

    let mut k = 0i64;
    group.bench_function("session_100_creates_push_commit", |b| {
        b.iter(|| {
            let mut session = db.start_undo_session(true).unwrap();
            for i in 0..CHANGES {
                db.create::<Account>(|a| a.name = rows + (k + i) as u64).unwrap();
            }
            k += CHANGES;
            session.push();
            db.commit(db.revision()).unwrap();
        })
    });
    group.finish();
}

/// Serialization into the mapped file (`flush`) and loading a database from
/// disk (read-only open, so the close writes nothing back).
fn bench_persistence(c: &mut Criterion) {
    let mut group = c.benchmark_group("persistence");
    group.sample_size(10);
    let rows = 100_000;

    let flush_dir = tempfile::tempdir().unwrap();
    let db = Database::open(flush_dir.path(), OpenFlags::ReadWrite, 64 * 1024 * 1024, false)
        .unwrap();
    db.add_index::<Account>().unwrap();
    for i in 0..rows {
        db.create::<Account>(|a| {
            a.name = i;
            a.data = vec![0xAB; DATA_LEN];
        })
        .unwrap();
    }
    group.bench_function(BenchmarkId::new("flush", rows), |b| b.iter(|| db.flush().unwrap()));
    drop(db);

    group.bench_function(BenchmarkId::new("open_load", rows), |b| {
        b.iter(|| {
            let db = Database::open(flush_dir.path(), OpenFlags::ReadOnly, 0, false).unwrap();
            db.add_index::<Account>().unwrap();
            black_box(db.revision());
        })
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1);
    targets = bench_insert, bench_read, bench_modify, bench_undo, bench_persistence
}
criterion_main!(benches);
