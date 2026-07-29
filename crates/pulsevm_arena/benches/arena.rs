//! Performance check for the arena store: the hot-path operations plus the raw
//! snapshot save/load. Run with `cargo bench -p pulsevm_arena`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pulsevm_arena::{ArenaObject, Db, IndexedBy, ObjectId, SecondaryIndex, Table, key_index};

#[repr(C)]
#[derive(Clone, Copy, Default, zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
struct Account {
    id: ObjectId<Account>,
    name: u64,
    creation_date: u32,
    _pad: u32,
}

struct ByName;
impl IndexedBy<Account> for ByName {
    type Key = u64;
    fn key(o: &Account) -> u64 {
        o.name
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

fn table(rows: u64) -> Table<Account> {
    let mut t = Table::<Account>::new();
    for i in 0..rows {
        t.emplace(|a| a.name = i).unwrap();
    }
    t
}

fn bench_hot_path(c: &mut Criterion) {
    let mut insert = c.benchmark_group("insert");
    let mut t = Table::<Account>::new();
    let mut n = 0u64;
    insert.bench_function("emplace", |b| {
        b.iter(|| {
            t.emplace(|a| a.name = black_box(n)).unwrap();
            n += 1;
        })
    });
    insert.finish();

    let mut find = c.benchmark_group("find");
    for rows in [1_000u64, 100_000] {
        let t = table(rows);
        let mut k = 0u64;
        find.bench_with_input(BenchmarkId::new("by_name", rows), &rows, |b, rows| {
            b.iter(|| {
                let name = t.get_index::<ByName>().find(black_box(&(k % rows))).map(|a| a.name);
                k += 1;
                black_box(name)
            })
        });
        let mut m = 0i64;
        find.bench_with_input(BenchmarkId::new("by_id", rows), &rows, |b, rows| {
            b.iter(|| {
                let v = t.find(ObjectId::new(black_box(m % *rows as i64))).map(|a| a.name);
                m += 1;
                black_box(v)
            })
        });
    }
    find.finish();

    let mut undo = c.benchmark_group("undo");
    let mut t = table(100_000);
    let mut base = 100_000u64;
    undo.bench_function("session_100_creates_commit", |b| {
        b.iter(|| {
            t.start_undo_session();
            for i in 0..100 {
                t.emplace(|a| a.name = base + i).unwrap();
            }
            base += 100;
            t.commit(t.revision());
        })
    });
    undo.finish();
}

fn bench_persistence(c: &mut Criterion) {
    let mut group = c.benchmark_group("persistence");
    group.sample_size(20);
    let rows = 100_000u64;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snapshot.bin");
    let mut db = Db::new();
    db.add_table::<Account>().unwrap();
    for i in 0..rows {
        db.create::<Account>(|a| a.name = i).unwrap();
    }

    group.bench_function(BenchmarkId::new("save", rows), |b| {
        b.iter(|| db.save(&path).unwrap())
    });

    db.save(&path).unwrap();
    group.bench_function(BenchmarkId::new("load", rows), |b| {
        b.iter(|| {
            let mut fresh = Db::new();
            fresh.add_table::<Account>().unwrap();
            fresh.load(&path).unwrap();
            black_box(fresh.table::<Account>().unwrap().len());
        })
    });

    // O(dirty): flush the WAL after touching 10 rows of the 100k-row DB. Cost
    // tracks the change, not the total size — unlike the full checkpoint above.
    let wal = dir.path().join("wal");
    db.checkpoint(&path).unwrap();
    let mut n = 0u64;
    group.bench_function(BenchmarkId::new("flush_delta_after_10", rows), |b| {
        b.iter(|| {
            for i in 0..10u64 {
                db.modify::<Account>(ObjectId::new(i as i64), |a| a.name = rows + n + i).unwrap();
            }
            n += 10;
            db.flush_delta(&wal).unwrap();
        })
    });
    group.finish();
}

criterion_group!(benches, bench_hot_path, bench_persistence);
criterion_main!(benches);
