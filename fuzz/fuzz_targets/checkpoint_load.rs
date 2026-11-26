//! Arbitrary bytes as a checkpoint, the file a state-sync peer chooses. Loading
//! must refuse or accept without a panic or an allocation the bytes do not justify;
//! an accepted checkpoint must have a state root.
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
    let path = dir.path().join("cp");
    std::fs::write(&path, data).unwrap();
    let mut db = Db::new();
    db.add_table::<Account>().unwrap();
    if db.load(&path).is_ok() {
        let _ = db.state_root();
    }
});
