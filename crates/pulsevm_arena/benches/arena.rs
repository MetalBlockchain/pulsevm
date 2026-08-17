//! Performance check for the arena store: the hot-path operations plus the raw
//! snapshot save/load. Run with `cargo bench -p pulsevm_arena`.

use std::hint::black_box;

use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
use pulsevm_arena::{
    ArenaObject,
    Db,
    IndexedBy,
    ObjectId,
    SecondaryIndex,
    Table,
    hash_index,
    key_index,
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

/// Identical to `Account` but with a hash-backed name index, to compare
/// point-lookup latency in isolation (kept off `Account` so the insert/undo
/// benches maintain a single realistic index, as chainbase's account does).
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
struct HashAccount {
    id: ObjectId<HashAccount>,
    name: u64,
    creation_date: u32,
    _pad: u32,
}

struct HashByName;
impl IndexedBy<HashAccount> for HashByName {
    type Key = u64;
    fn key(o: &HashAccount) -> u64 {
        o.name
    }
}

impl ArenaObject for HashAccount {
    const TYPE_ID: u16 = 1;
    fn id(&self) -> ObjectId<Self> {
        self.id
    }
    fn set_id(&mut self, id: ObjectId<Self>) {
        self.id = id;
    }
    fn secondary_indices() -> Vec<Box<dyn SecondaryIndex<Self>>> {
        vec![hash_index::<Self, HashByName>()]
    }
}

fn hash_table(rows: u64) -> Table<HashAccount> {
    let mut t = Table::<HashAccount>::new();
    for i in 0..rows {
        t.emplace(|a| a.name = i).unwrap();
    }
    t
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
        let ht = hash_table(rows);
        let mut k = 0u64;
        find.bench_with_input(BenchmarkId::new("by_name", rows), &rows, |b, rows| {
            b.iter(|| {
                let name = t
                    .get_index::<ByName>()
                    .find(black_box(&(k % rows)))
                    .map(|a| a.name);
                k += 1;
                black_box(name)
            })
        });
        let mut h = 0u64;
        find.bench_with_input(BenchmarkId::new("by_name_hash", rows), &rows, |b, rows| {
            b.iter(|| {
                let name = ht
                    .get_hash_index::<HashByName>()
                    .find(black_box(&(h % rows)))
                    .map(|a| a.name);
                h += 1;
                black_box(name)
            })
        });
        let mut m = 0i64;
        find.bench_with_input(BenchmarkId::new("by_id", rows), &rows, |b, rows| {
            b.iter(|| {
                let v = t
                    .find(ObjectId::new(black_box(m % *rows as i64)))
                    .map(|a| a.name);
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
                db.modify::<Account>(ObjectId::new(i as i64), |a| a.name = rows + n + i)
                    .unwrap();
            }
            n += 10;
            db.flush_delta(&wal).unwrap();
        })
    });
    group.finish();
}

/// Where does `load` actually spend its time? An mmap-backed open would make the
/// raw row bytes zero-copy (removing `raw_row_copy`), but the ordered secondary
/// index is heap-only and must be rebuilt on every open (`index_rebuild`) no
/// matter how the rows arrive. This isolates the two so we know the real ceiling
/// on what mmap can save.
fn bench_open_breakdown(c: &mut Criterion) {
    use std::collections::BTreeMap;
    let rows = 100_000u64;
    let mut group = c.benchmark_group("open_breakdown");
    group.sample_size(20);

    // The part mmap removes: materialize the raw row slab (a bulk copy).
    let slab: Vec<Account> = (0..rows)
        .map(|i| Account {
            name: i,
            ..Account::default()
        })
        .collect();
    group.bench_function(BenchmarkId::new("raw_row_copy", rows), |b| {
        b.iter(|| black_box(slab.clone()))
    });

    // The part mmap cannot remove: rebuild the ordered secondary index. Insert in
    // id order (as load does) — the friendly case for a BTree.
    group.bench_function(BenchmarkId::new("index_rebuild", rows), |b| {
        b.iter(|| {
            let mut idx: BTreeMap<u64, i64> = BTreeMap::new();
            for a in &slab {
                idx.insert(a.name, a.id.raw());
            }
            black_box(idx.len());
        })
    });

    // If the index were persisted key-sorted, open could bulk-build it:
    // BTreeMap::from_iter sorts + builds bottom-up instead of N inserts.
    let sorted: Vec<(u64, i64)> = {
        let mut v: Vec<(u64, i64)> = slab.iter().map(|a| (a.name, a.id.raw())).collect();
        v.sort_by_key(|&(k, _)| k);
        v
    };
    group.bench_function(BenchmarkId::new("index_bulk_build_sorted", rows), |b| {
        b.iter(|| {
            let idx: BTreeMap<u64, i64> = sorted.iter().copied().collect();
            black_box(idx.len());
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_hot_path,
    bench_persistence,
    bench_open_breakdown
);
criterion_main!(benches);
