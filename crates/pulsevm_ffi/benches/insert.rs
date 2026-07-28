use criterion::{Criterion, criterion_group, criterion_main};
use pulsevm_ffi::Database;
use std::hint::black_box;
use tempfile::tempdir;

const DB_SIZE: u64 = 8 * 1024 * 1024 * 1024;

// Raw chainbase account-insert throughput. The account index grows as the
// benchmark runs, so later inserts are slightly slower than earlier ones; read
// this as an order-of-magnitude cost, not a precise steady-state figure.
fn criterion_benchmark(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let mut db = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
    db.add_indices().unwrap();
    let mut n = 0u64;
    c.bench_function("db_insert_account", |b| {
        b.iter(|| {
            db.create_account(black_box(n), 0).unwrap();
            n += 1;
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(200);
    targets = criterion_benchmark
}
criterion_main!(benches);
