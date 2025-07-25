use criterion::{Criterion, criterion_group, criterion_main};
use pulsevm_serialization::{Read, Write};
use std::hint::black_box;

fn bench(value: &Vec<u8>) {
    let mut pos = 0;
    let result = Vec::<u8>::read(value, &mut pos).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let value: Vec<u64> = (0..100000).map(|v| v + 1000).collect();
    let value = value.pack().unwrap();
    c.bench_function("fib 20", |b| b.iter(|| bench(black_box(&value))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
