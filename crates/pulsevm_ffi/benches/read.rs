use criterion::{Criterion, criterion_group, criterion_main};
use pulsevm_ffi::Database;
use std::hint::black_box;
use tempfile::tempdir;

const DB_SIZE: u64 = 1024 * 1024 * 1024;

fn criterion_benchmark(c: &mut Criterion) {
    let temp_dir = tempdir().unwrap();
    let mut db = Database::new(temp_dir.path().to_str().unwrap(), DB_SIZE).unwrap();
    db.add_indices().unwrap();
    let name = 123u64;
    db.create_account(name, 0).unwrap();
    c.bench_function("read", |b| {
        b.iter(|| {
            black_box(db.get_account(black_box(name)).unwrap());
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(500);
    targets = criterion_benchmark
}
criterion_main!(benches);
