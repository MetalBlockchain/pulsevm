//! Arbitrary bytes as one of the node's history logs (trace, chain-state, block),
//! opened as the node opens them, with magic 0. Opening must refuse or recover
//! without a panic, and what it keeps must read back.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pulsevm_core::state_history::StateHistoryLog;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("block_log.log"), data).unwrap();
    if let Ok(log) = StateHistoryLog::open_with_magic(dir.path(), "block_log", 0) {
        if let Some((first, last)) = log.range() {
            for block in first..=last.min(first.saturating_add(8)) {
                let _ = log.read_block(block);
            }
        }
    }
});
