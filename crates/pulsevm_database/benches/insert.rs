use criterion::{
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

const DB_SIZE: u64 = 1024 * 1024 * 1024;
// Recycle the store before the fixed-size mmap fills; amortized over this many
// inserts the recreation cost is negligible, and inserts still land in a
// non-trivially populated table.
const RECYCLE_EVERY: u64 = 200_000;

fn fresh() -> (TempDir, Database) {
    let dir = tempdir().unwrap();
    let mut db = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
    db.add_indices().unwrap();
    (dir, db)
}

fn criterion_benchmark(c: &mut Criterion) {
    let (mut _dir, mut db) = fresh();
    let mut val = 0u64;
    c.bench_function("insert", |b| {
        b.iter(|| {
            if val >= RECYCLE_EVERY {
                let (d, fresh_db) = fresh();
                _dir = d;
                db = fresh_db;
                val = 0;
            }
            db.create_account(black_box(val), 0).unwrap();
            val += 1;
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(500);
    targets = criterion_benchmark
}
criterion_main!(benches);
