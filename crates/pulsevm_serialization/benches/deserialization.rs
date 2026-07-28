use criterion::{Criterion, criterion_group, criterion_main};
use pulsevm_serialization::{Read, Write};
use std::hint::black_box;

fn bench(value: &Vec<u8>) {
    let mut pos = 0;
    let _ = Vec::<u8>::read(value, &mut pos).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    // ~800 KB of packed bytes (100k u64s), read back as a length-prefixed byte vec.
    let value: Vec<u64> = (0..100000).map(|v| v + 1000).collect();
    let value = value.pack().unwrap();
    c.bench_function("read_vec_u8_800kb", |b| b.iter(|| bench(black_box(&value))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
