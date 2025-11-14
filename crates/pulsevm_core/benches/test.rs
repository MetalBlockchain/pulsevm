use criterion::{Criterion, criterion_group, criterion_main};
use pulsevm_serialization::{Read, Write};
use sha2::Digest;
use std::hint::black_box;

fn bench(value: &Vec<u8>) {
    //sha256::Hash::hash(value);
    sha2::Sha256::digest(value);
}

fn criterion_benchmark(c: &mut Criterion) {
    let value: Vec<u64> = (0..10000).map(|v| v + 1000).collect();
    let value = value.pack().unwrap();
    c.bench_function("sha256", |b| b.iter(|| bench(black_box(&value))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
