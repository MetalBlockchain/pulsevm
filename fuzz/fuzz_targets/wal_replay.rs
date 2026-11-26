//! Arbitrary bytes as a write-ahead log. Replay must refuse or accept without a
//! panic, an unbounded allocation, or super-linear time (libFuzzer's timeout and
//! RSS limit are the checks).
#![no_main]

use libfuzzer_sys::fuzz_target;
use pulsevm_arena::{ArenaObject, BlobRef, Db, ObjectId};

#[repr(C)]
#[derive(
    Clone, Copy, Default, zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable,
    zerocopy::KnownLayout, ArenaObject,
)]
#[arena(type_id = 10)]
struct Account {
    id: ObjectId<Account>,
    #[arena(index)]
    name: u64,
    created: u32,
    _pad: u32,
    abi: BlobRef,
}

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wal");
    std::fs::write(&path, data).unwrap();
    let mut db = Db::new();
    db.add_table::<Account>().unwrap();
    let _ = db.replay_log_after(&path, 0);
});
