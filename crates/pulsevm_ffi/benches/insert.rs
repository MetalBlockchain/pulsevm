use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pulsevm_ffi::{Database, string_to_name};
use std::hint::black_box;
use tempfile::{env::temp_dir, tempdir, tempfile};

fn bench(db: &mut Database, name: &pulsevm_ffi::Name) {
    db.add_account(black_box(name));
}

fn criterion_benchmark(c: &mut Criterion) {
    let temp_dir = tempdir().unwrap();
    let mut db = Database::new(temp_dir.path().to_str().unwrap()).unwrap();
    let name = string_to_name("testaccount").unwrap();
    db.add_indices();
    c.bench_function("insert", |b| b.iter(|| bench(&mut db, &name)));
}

criterion_group! {
    name = benches;
    // This can be any expression that returns a `Criterion` object.
    config = Criterion::default().significance_level(0.1).sample_size(500);
    targets = criterion_benchmark
}
criterion_main!(benches);
