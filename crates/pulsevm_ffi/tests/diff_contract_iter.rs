//! Differential test of the primary `db_*_i64` iterator semantics: the Rust
//! arena `ContractDb` against the C++ chainbase through this crate's FFI. Same
//! rows, same navigation, and the consensus-observable outputs — iterator
//! handles (including the end-iterator encoding) and the primary keys from
//! traversal — must be identical. This is the real consensus check the earlier
//! Rust-vs-reference fuzzers stand in for.

use std::collections::HashSet;

use proptest::collection::vec;
use proptest::prelude::*;
use pulsevm_contractdb::ContractDb;
use pulsevm_ffi::{Database, KeyValueIteratorCache, TableObject};
use tempfile::tempdir;

const CODE: u64 = 1;
const SCOPE: u64 = 2;
const TABLE: u64 = 3;
const PAYER: u64 = 1;
const DB_SIZE: u64 = 8 * 1024 * 1024 * 1024;

/// Drives both stores identically, then compares end iterator, a full forward
/// walk, find(hit)/find(miss), and previous-from-end. Panics on any divergence.
fn compare(rows: &[u64]) {
    // ---- C++ chainbase via FFI ----
    let dir = tempdir().unwrap();
    let mut fdb = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
    fdb.add_indices().unwrap();
    let mut fc = KeyValueIteratorCache::new();
    // Tables come into existence on first store (as EOS db_store_i64 does), so
    // only create it on the C++ side when there are rows — keeping "table
    // exists" symmetric with the Rust side.
    if !rows.is_empty() {
        let table_ptr = fdb.create_table(CODE, SCOPE, TABLE, PAYER).unwrap();
        let table_ref: &TableObject = unsafe { &*table_ptr };
        for &pk in rows {
            fdb.create_key_value_object(table_ref, PAYER, pk, &pk.to_le_bytes())
                .unwrap();
        }
        fc.cache_table(table_ref).unwrap();
    }

    // ---- Rust arena ----
    let mut rdb = ContractDb::new();
    for &pk in rows {
        rdb.db_store_i64(CODE, SCOPE, TABLE, PAYER, pk, &pk.to_le_bytes());
    }
    rdb.reset_iterators(); // fresh cache, matching the fresh FFI cache

    // end iterator
    let fe = fdb.db_end_i64(&mut fc, CODE, SCOPE, TABLE).unwrap();
    let re = rdb.db_end_i64(CODE, SCOPE, TABLE);
    assert_eq!(fe, re, "end iterator differs for rows {rows:?}");

    // forward walk from lowerbound(0)
    let mut fit = fdb.db_lowerbound_i64(&mut fc, CODE, SCOPE, TABLE, 0).unwrap();
    let mut rit = rdb.db_lowerbound_i64(CODE, SCOPE, TABLE, 0);
    assert_eq!(fit, rit, "lowerbound(0) handle differs for rows {rows:?}");
    let mut steps = 0;
    while rit != re {
        let (mut fp, mut rp) = (0u64, 0u64);
        let fnext = fdb.db_next_i64(&mut fc, fit, &mut fp).unwrap();
        let rnext = rdb.db_next_i64(rit, &mut rp);
        assert_eq!(fp, rp, "next primary differs at step {steps} for rows {rows:?}");
        assert_eq!(fnext, rnext, "next handle differs at step {steps} for rows {rows:?}");
        fit = fnext;
        rit = rnext;
        steps += 1;
        assert!(steps <= rows.len() + 1, "walk overran for rows {rows:?}");
    }
    assert_eq!(fit, fe, "C++ walk did not terminate at end for rows {rows:?}");

    // find: a present key and a missing one
    if let Some(&present) = rows.first() {
        let f = fdb.db_find_i64(CODE, SCOPE, TABLE, present, &mut fc).unwrap();
        let r = rdb.db_find_i64(CODE, SCOPE, TABLE, present);
        assert_eq!(f, r, "find(present={present}) differs for rows {rows:?}");
    }
    let missing = rows.iter().max().copied().unwrap_or(0) + 1;
    let f = fdb.db_find_i64(CODE, SCOPE, TABLE, missing, &mut fc).unwrap();
    let r = rdb.db_find_i64(CODE, SCOPE, TABLE, missing);
    assert_eq!(f, r, "find(missing={missing}) differs for rows {rows:?}");

    // previous from the end iterator (only meaningful when the table exists)
    if !rows.is_empty() {
        let (mut fp, mut rp) = (0u64, 0u64);
        let fprev = fdb.db_previous_i64(&mut fc, fe, &mut fp).unwrap();
        let rprev = rdb.db_previous_i64(re, &mut rp);
        assert_eq!(fp, rp, "previous-from-end primary differs for rows {rows:?}");
        assert_eq!(fprev, rprev, "previous-from-end handle differs for rows {rows:?}");
    }
}

#[test]
fn iterator_semantics_match_cpp() {
    compare(&[]);
    compare(&[10]);
    compare(&[10, 20, 30]);
    compare(&[30, 10, 20]); // insertion order should not matter
    compare(&[5, 1, 9, 3, 7]);
    compare(&[100, 200, 150, 175, 125, 250]);
}

proptest! {
    // Each case builds a fresh C++ chainbase, so keep the count modest.
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Random distinct primary keys, inserted in random order: the Rust arena
    /// must agree with C++ chainbase on every iterator handle and primary.
    #[test]
    fn iterator_semantics_match_cpp_fuzz(raw in vec(0u64..40, 0..16)) {
        // Distinct keys, insertion order preserved.
        let mut seen = HashSet::new();
        let rows: Vec<u64> = raw.into_iter().filter(|k| seen.insert(*k)).collect();
        compare(&rows);
    }
}
