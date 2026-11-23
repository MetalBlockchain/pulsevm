//! Arbitrary bytes as a state-sync snapshot envelope and as a sparse payload.
//! Neither may panic, and a sparse payload may not write past the length it
//! declares or declare more than it carries.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pulsevm_database::peek_snapshot_header(data);
    if let Ok((_, payload)) = pulsevm_database::decode_snapshot(data) {
        let _ = pulsevm_database::sparse_expand(payload, |_, _| Ok(()));
    }
    let mut written = 0u64;
    let outcome = pulsevm_database::sparse_expand(data, |offset, run| {
        written += run.len() as u64;
        assert!(offset.checked_add(run.len() as u64).is_some());
        Ok(())
    });
    if let Ok(logical) = outcome {
        // What was written fits inside what was declared.
        assert!(written <= logical);
    }
});
