use criterion::{Criterion, criterion_group, criterion_main};
use fjall::{Config, PartitionCreateOptions, PartitionHandle};
use pulsevm_serialization::{Read, Write};
use std::hint::black_box;

fn bench(items: &PartitionHandle) {
    items.insert("a", "hello").unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let keyspace = Config::new("db").fsync_ms(Some(500)).open().unwrap();
    let items = keyspace
        .open_partition("my_items", PartitionCreateOptions::default())
        .unwrap();
    c.bench_function("fjall", |b| b.iter(|| bench(black_box(&items))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
