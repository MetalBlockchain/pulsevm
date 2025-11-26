use criterion::{Criterion, criterion_group, criterion_main};
use fjall::{Config, PartitionCreateOptions, PartitionHandle};
use lmdb::{Database, Environment, RwTransaction, WriteFlags};
use pulsevm_serialization::{Read, Write};
use std::{fs, hint::black_box, path::Path};

fn bench(params: (&Database, &mut RwTransaction)) {
    let (db, txn) = params;
    txn.put(*db, &b"hello", &b"world", WriteFlags::empty())
        .unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let path = Path::new("./mydb");

    // Create directory if it doesn't exist
    if !path.exists() {
        fs::create_dir(path).unwrap();
    }

    // Create environment (max 10 DBs, 100 MB map size)
    let env = Environment::new()
        .set_max_dbs(10)
        .set_map_size(1024 * 1024 * 100)
        .open(path)
        .unwrap();

    let db = env
        .create_db(Some("example"), lmdb::DatabaseFlags::empty())
        .unwrap();
    let mut txn = env.begin_rw_txn().unwrap();

    c.bench_function("lmdb", |b| b.iter(|| bench(black_box((&db, &mut txn)))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
