use criterion::{Criterion, criterion_group, criterion_main};
use heed::{Database, EnvOpenOptions, RwTxn, types::Bytes};
use std::{hint::black_box, path::Path};
use tempfile::tempdir;

fn bench(params: (&Database<Bytes, Bytes>, &mut RwTxn<'_>)) {
    let (db, txn) = params;
    db.get(txn, b"hello").unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    // Use a temporary directory for the env
    let dir = tempdir().unwrap();
    let path = dir.path();

    // Open heed environment
    let env = unsafe {
        EnvOpenOptions::new()
            .map_size(1024 * 1024 * 100) // 100 MB
            .max_dbs(10)
            .open(path)
            .unwrap()
    };

    // Create/open a DB with raw byte keys/values
    // Start a single write txn like in your lmdb example
    let mut wtxn = env.write_txn().unwrap();
    let db: Database<Bytes, Bytes> = env.create_database(&mut wtxn, Some("example")).unwrap();
    db.put(&mut wtxn, b"hello", b"world").unwrap();

    c.bench_function("heed", |b| b.iter(|| bench(black_box((&db, &mut wtxn)))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
