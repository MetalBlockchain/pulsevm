use criterion::{Criterion, criterion_group, criterion_main};
use pulsevm_ffi::{Database, Name};
use tempfile::{env::temp_dir, tempdir};

fn bench(db: &mut Database, name: &Name) {
    db.get_account(name).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let temp_dir = tempdir().unwrap();
    let mut db = Database::new(temp_dir.path().to_str().unwrap()).unwrap();
    db.add_indices();
    let n = Name::new(123);
    db.create_account(n.to_uint64_t(), 0).unwrap();
    c.bench_function("read", |b| b.iter(|| bench(&mut db, &n)));
}

criterion_group! {
    name = benches;
    // This can be any expression that returns a `Criterion` object.
    config = Criterion::default().significance_level(0.1).sample_size(500);
    targets = criterion_benchmark
}
criterion_main!(benches);
