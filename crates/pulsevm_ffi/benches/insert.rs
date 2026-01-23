use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pulsevm_ffi::{Database, Name, string_to_name};
use std::hint::black_box;
use tempfile::{env::temp_dir, tempdir, tempfile};

fn bench(db: &mut Database, n: &mut u64) {
    db.create_account(black_box(*n), 0).unwrap();
    *n += 1;
}

fn criterion_benchmark(c: &mut Criterion) {
    let temp_dir = tempdir().unwrap();
    let mut db = Database::new(temp_dir.path().to_str().unwrap()).unwrap();
    let mut val = 0u64;
    db.add_indices().unwrap();
    c.bench_function("insert", |b| b.iter(|| bench(&mut db, &mut val)));
}

criterion_group! {
    name = benches;
    // This can be any expression that returns a `Criterion` object.
    config = Criterion::default().significance_level(0.1).sample_size(500);
    targets = criterion_benchmark
}
criterion_main!(benches);
