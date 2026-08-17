use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
use pulsevm_database::Database;
use std::hint::black_box;
use tempfile::tempdir;

const DB_SIZE: u64 = 4 * 1024 * 1024 * 1024;

// Find an account in a populated database at the same row counts as the
// pulsevm_arena `find` benchmark.
fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("read");
    for rows in [1_000u64, 100_000] {
        let dir = tempdir().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
        db.add_indices().unwrap();
        for n in 0..rows {
            db.create_account(n, 0).unwrap();
        }
        let mut k = 0u64;
        group.bench_with_input(BenchmarkId::new("get_account", rows), &rows, |b, rows| {
            b.iter(|| {
                let a = db.arena_account_exists(black_box(k % rows));
                k += 1;
                black_box(a);
            })
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(500);
    targets = criterion_benchmark
}
criterion_main!(benches);
