use std::collections::BTreeSet;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pulsevm_core::{
    mempool::{Mempool, MAX_MEMPOOL_SIZE},
    time::{TimePoint, TimePointSec},
    transaction::{PackedTransaction, SignedTransaction, Transaction, TransactionHeader},
};

fn full_unexpired_mempool() -> Mempool {
    let mut mempool = Mempool::new();
    for index in 0..MAX_MEMPOOL_SIZE {
        // A distinct header gives every transaction a distinct id. The empty
        // action/signature set is sufficient here because this benchmark is
        // deliberately limited to Mempool's expiry-index hot path.
        let transaction = Transaction::new(
            TransactionHeader::new(
                TimePointSec::new(u32::MAX),
                index as u16,
                index as u32,
                0u32.into(),
                0,
                0u32.into(),
            ),
            vec![],
            vec![],
        );
        let packed = PackedTransaction::from_signed_transaction(SignedTransaction::new(
            transaction,
            BTreeSet::new(),
            vec![],
        ))
        .unwrap();
        assert!(mempool.add_transaction(packed));
    }
    mempool
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut mempool = full_unexpired_mempool();
    c.bench_function("mempool_pruning/full_unexpired_pool_10k", |b| {
        b.iter(|| black_box(mempool.prune_expired(black_box(&TimePoint::now()))))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
