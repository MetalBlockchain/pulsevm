use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pulsevm_ffi::Database;
use std::hint::black_box;
use tempfile::tempdir;

const DB_SIZE: u64 = 4 * 1024 * 1024 * 1024;

// Find an account against a populated chainbase, at the same row counts the
// pulsevm_arena `find` bench uses, so the two are comparable. get_account is a
// by-name lookup through the FFI (RwLock read guard + cxx boundary + boost
// multi_index), which is the cost the arena's index-addressed find replaces.
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
                let a = db.get_account(black_box(k % rows)).unwrap();
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
