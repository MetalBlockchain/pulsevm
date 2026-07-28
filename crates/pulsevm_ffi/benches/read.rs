use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pulsevm_ffi::Database;
use std::hint::black_box;
use tempfile::tempdir;

const DB_SIZE: u64 = 8 * 1024 * 1024 * 1024;

// How raw chainbase `find_account` scales with the size of the account index.
// This is the "does state lookup cost grow with state" question in isolation,
// without WASM or signature-recovery noise.
fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("db_find_account");
    for &n in &[1_000u64, 100_000, 1_000_000] {
        let dir = tempdir().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
        db.add_indices().unwrap();
        for i in 0..n {
            db.create_account(i, 0).unwrap();
        }
        let probe = n / 2; // an existing account roughly in the middle of the index
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| {
                db.find_account(black_box(probe)).unwrap();
            })
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(200);
    targets = criterion_benchmark
}
criterion_main!(benches);
