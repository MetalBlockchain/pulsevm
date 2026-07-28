use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use pulsevm_ffi::{Database, KeyValueIteratorCache, TableObject};
use std::hint::black_box;
use tempfile::tempdir;

const DB_SIZE: u64 = 8 * 1024 * 1024 * 1024;

// The "DB iteration heavy" case in isolation: insert N rows into one chainbase
// table, then walk them all with db_lowerbound + repeated db_next. Reports
// throughput (rows/s), so per-row iteration cost across sizes shows whether the
// FFI/state boundary becomes expensive when a contract actually iterates a lot.
fn criterion_benchmark(c: &mut Criterion) {
    let (code, scope, table, payer) = (1u64, 2u64, 3u64, 1u64);
    let mut group = c.benchmark_group("db_iterate_rows");
    group.sample_size(20);

    // 1M rows is available but slow (~minutes); 1k/100k already shows the trend.
    for &n in &[1_000u64, 100_000] {
        let dir = tempdir().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
        db.add_indices().unwrap();

        let table_ptr = db.create_table(code, scope, table, payer).unwrap();
        let table_ref: &TableObject = unsafe { &*table_ptr };
        let buf = [0u8; 8];
        for i in 0..n {
            db.create_key_value_object(table_ref, payer, i, &buf).unwrap();
        }

        group.throughput(Throughput::Elements(n));
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| {
                let mut cache = KeyValueIteratorCache::new();
                cache.cache_table(table_ref).unwrap();
                let mut it = db.db_lowerbound_i64(&mut cache, code, scope, table, 0).unwrap();
                let mut primary = 0u64;
                let mut rows = 0u64;
                // Negative iterator == end-of-table sentinel.
                while it >= 0 {
                    it = db.db_next_i64(&mut cache, it, &mut primary).unwrap();
                    rows += 1;
                }
                black_box(rows);
            })
        });
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
