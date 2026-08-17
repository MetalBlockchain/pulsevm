use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
use pulsevm_database::Database;
use std::hint::black_box;
use tempfile::{
    TempDir,
    tempdir,
};

const DB_SIZE: u64 = 8 * 1024 * 1024 * 1024;

fn populated() -> (TempDir, Database, u64) {
    let dir = tempdir().unwrap();
    let mut db = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
    db.add_indices().unwrap();
    for n in 0..100_000u64 {
        db.create_account(n, 0).unwrap();
    }
    (dir, db, 100_000)
}

// Matches pulsevm_arena's `undo/session_100_creates_commit`: open an undo
// session, create 100 accounts against a ~100k-row table, then commit.
fn bench_session(c: &mut Criterion) {
    let (mut _dir, mut db, mut next) = populated();
    let mut since_recycle = 0u64;
    c.bench_function("session_100_creates_commit", |b| {
        b.iter(|| {
            if since_recycle >= 300_000 {
                let p = populated();
                _dir = p.0;
                db = p.1;
                next = p.2;
                since_recycle = 0;
            }
            db.arena_start_undo_session();
            for _ in 0..100 {
                db.create_account(black_box(next), 0).unwrap();
                next += 1;
            }
            db.arena_squash();
            since_recycle += 100;
        })
    });
}

// Reopen a populated, closed database and measure checkpoint restoration.
fn bench_reopen(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let path = dir.path().to_str().unwrap().to_string();
    {
        let mut db = Database::new(&path, DB_SIZE).unwrap();
        db.add_indices().unwrap();
        for n in 0..100_000u64 {
            db.create_account(n, 0).unwrap();
        }
        db.close().unwrap();
    }
    let mut group = c.benchmark_group("reopen");
    group.sample_size(50);
    group.bench_function(BenchmarkId::new("checkpoint_open", 100_000), |b| {
        b.iter(|| {
            let db = Database::new(&path, DB_SIZE).unwrap();
            black_box(&db);
        })
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(200);
    targets = bench_session, bench_reopen
}
criterion_main!(benches);
