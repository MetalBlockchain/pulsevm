use criterion::{Criterion, criterion_group, criterion_main};
use feoxdb::FeoxStore;
use fjall::{Config, PartitionCreateOptions, PartitionHandle};
use pulsevm_serialization::{Read, Write};
use std::hint::black_box;

fn bench(store: &FeoxStore) {
    store.insert(b"config:app", b"production").unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let store = FeoxStore::builder()
        .device_path("myapp.feox")
        .file_size(10 * 1024 * 1024 * 1024) // 10GB initial file size
        .max_memory(2_000_000_000) // 2GB limit
        .enable_caching(true) // Enable CLOCK cache
        .hash_bits(20) // 1M hash buckets
        .build()
        .unwrap();
    c.bench_function("feoxdb", |b| b.iter(|| bench(black_box(&store))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
