use criterion::{Criterion, criterion_group, criterion_main};
use fjall::{Config, PartitionCreateOptions, PartitionHandle};
use pulsevm_chainbase::{ChainbaseObject, Database, SecondaryKey, UndoSession};
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::{Read, Write};
use tempfile::{env::temp_dir, tempdir, tempfile};
use std::hint::black_box;

#[derive(Debug, Default, Clone, Read, Write, NumBytes)]
struct TestObject {
    id: u64,
    name: String,
}

impl ChainbaseObject for TestObject {
    type PrimaryKey = u64;

    fn primary_key(&self) -> Vec<u8> {
        TestObject::primary_key_to_bytes(self.id)
    }
    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.to_le_bytes().to_vec()
    }
    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
    fn table_name() -> &'static str {
        "test_object"
    }
}

fn bench(session: &mut UndoSession) {
    session
        .insert(&TestObject {
            id: 1,
            name: "test".to_string(),
        })
        .unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let path = tempdir().unwrap();
    let db = Database::new(path.path()).unwrap();
    let mut session = db.undo_session().unwrap();
    c.bench_function("insert", |b| b.iter(|| bench(black_box(&mut session))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
