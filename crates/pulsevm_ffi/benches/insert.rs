use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pulsevm_ffi::Database;
use tempfile::{env::temp_dir, tempdir, tempfile};
use std::hint::black_box;

fn bench(db: &mut Database) {
    db.add_account();
}

fn criterion_benchmark(c: &mut Criterion) {
    let temp_dir = tempdir().unwrap();
    println!("Temp dir path: {:?}", temp_dir.path().to_str().unwrap());
    let mut db = Database::new(temp_dir.path().to_str().unwrap()).unwrap();
    db.add_indices();
    c.bench_function("insert", |b| b.iter(|| bench(&mut db)));
}

criterion_group!{
    name = benches;
    // This can be any expression that returns a `Criterion` object.
    config = Criterion::default().significance_level(0.1).sample_size(500);
    targets = criterion_benchmark
}
criterion_main!(benches);
