//! Differential test of the primary `db_*_i64` iterator semantics: the Rust
//! arena `ContractDb` against the C++ chainbase through this crate's FFI. Same
//! rows, same navigation, and the consensus-observable outputs — iterator
//! handles (including the end-iterator encoding) and the primary keys from
//! traversal — must be identical. This is the real consensus check the earlier
//! Rust-vs-reference fuzzers stand in for.

use std::collections::{
    BTreeMap,
    BTreeSet,
    HashSet,
};

use proptest::{
    collection::vec,
    prelude::*,
};
use pulsevm_contractdb::ContractDb;
use pulsevm_ffi::{
    Database,
    Index64IteratorCache,
    KeyValueIteratorCache,
    TableObject,
};
use tempfile::tempdir;

const CODE: u64 = 1;
const SCOPE: u64 = 2;
const TABLE: u64 = 3;
const PAYER: u64 = 1;
const DB_SIZE: u64 = 256 * 1024 * 1024;

// EOS `config::billable_size_v` for the row and table objects (the raw struct
// size rounded up to 16). The arena bills these same overheads; the C++ side
// here is driven from them independently so a wrong arena constant diverges.
const KV_OVERHEAD: i64 = 112;
const TABLE_OVERHEAD: i64 = 112;

// Accounts that can pay for rows. The C++ resource_usage records are created
// per account up front, so every payer we bill has somewhere to land.
const RAM_ACCOUNTS: [u64; 3] = [101, 102, 103];

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
    let mut fit = fdb
        .db_lowerbound_i64(&mut fc, CODE, SCOPE, TABLE, 0)
        .unwrap();
    let mut rit = rdb.db_lowerbound_i64(CODE, SCOPE, TABLE, 0);
    assert_eq!(fit, rit, "lowerbound(0) handle differs for rows {rows:?}");
    let mut steps = 0;
    while rit != re {
        let (mut fp, mut rp) = (0u64, 0u64);
        let fnext = fdb.db_next_i64(&mut fc, fit, &mut fp).unwrap();
        let rnext = rdb.db_next_i64(rit, &mut rp);
        assert_eq!(
            fp, rp,
            "next primary differs at step {steps} for rows {rows:?}"
        );
        assert_eq!(
            fnext, rnext,
            "next handle differs at step {steps} for rows {rows:?}"
        );
        fit = fnext;
        rit = rnext;
        steps += 1;
        assert!(steps <= rows.len() + 1, "walk overran for rows {rows:?}");
    }
    assert_eq!(
        fit, fe,
        "C++ walk did not terminate at end for rows {rows:?}"
    );

    // find: a present key and a missing one
    if let Some(&present) = rows.first() {
        let f = fdb
            .db_find_i64(CODE, SCOPE, TABLE, present, &mut fc)
            .unwrap();
        let r = rdb.db_find_i64(CODE, SCOPE, TABLE, present);
        assert_eq!(f, r, "find(present={present}) differs for rows {rows:?}");
    }
    let missing = rows.iter().max().copied().unwrap_or(0) + 1;
    let f = fdb
        .db_find_i64(CODE, SCOPE, TABLE, missing, &mut fc)
        .unwrap();
    let r = rdb.db_find_i64(CODE, SCOPE, TABLE, missing);
    assert_eq!(f, r, "find(missing={missing}) differs for rows {rows:?}");

    // previous from the end iterator (only meaningful when the table exists)
    if !rows.is_empty() {
        let (mut fp, mut rp) = (0u64, 0u64);
        let fprev = fdb.db_previous_i64(&mut fc, fe, &mut fp).unwrap();
        let rprev = rdb.db_previous_i64(re, &mut rp);
        assert_eq!(
            fp, rp,
            "previous-from-end primary differs for rows {rows:?}"
        );
        assert_eq!(
            fprev, rprev,
            "previous-from-end handle differs for rows {rows:?}"
        );
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

// ---- RAM billing: arena ResourceUsageObject vs C++ resource_usage_object ----

#[derive(Debug, Clone)]
enum RamOp {
    Store {
        scope: u64,
        payer: u64,
        value: Vec<u8>,
    },
    Update {
        sel: usize,
        payer: u64,
        value: Vec<u8>,
    },
    Remove {
        sel: usize,
    },
}

/// Replays the same store/update/remove sequence against the arena (which bills
/// internally) and against C++ chainbase (billed here from the EOS overheads),
/// then asserts every payer's RAM matches. The arena's own accounting — refunds
/// on remove, byte moves on a payer change, the one-time table overhead — is
/// what's under test; chainbase's resource_usage record is the oracle.
fn compare_ram(ops: &[RamOp]) {
    let dir = tempdir().unwrap();
    let mut fdb = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
    fdb.add_indices().unwrap();
    fdb.initialize_resource_limits().unwrap();
    for &acct in &RAM_ACCOUNTS {
        fdb.initialize_account_resource_limits(acct).unwrap();
    }

    let mut rdb = ContractDb::new();

    // Reference bookkeeping: the live rows (payer and value length) and the set
    // of tables that already exist, so we know when a store first bills a table.
    let mut rows: BTreeMap<(u64, u64), (u64, usize)> = BTreeMap::new();
    let mut tables: BTreeSet<u64> = BTreeSet::new();
    let mut next_pk = 0u64;

    for op in ops {
        match op {
            RamOp::Store {
                scope,
                payer,
                value,
            } => {
                let (scope, payer) = (*scope, *payer);
                let pk = next_pk;
                next_pk += 1;
                rdb.db_store_i64(CODE, scope, TABLE, payer, pk, value);
                if tables.insert(scope) {
                    fdb.add_pending_ram_usage(payer, TABLE_OVERHEAD).unwrap();
                }
                fdb.add_pending_ram_usage(payer, KV_OVERHEAD + value.len() as i64)
                    .unwrap();
                rows.insert((scope, pk), (payer, value.len()));
            }
            RamOp::Update { sel, payer, value } => {
                if rows.is_empty() {
                    continue;
                }
                let key = *rows.keys().nth(sel % rows.len()).unwrap();
                let (old_payer, old_len) = rows[&key];
                let it = rdb.db_find_i64(CODE, key.0, TABLE, key.1);
                rdb.db_update_i64(it, *payer, value);
                let old_bytes = old_len as i64 + KV_OVERHEAD;
                let new_bytes = value.len() as i64 + KV_OVERHEAD;
                if old_payer == *payer {
                    fdb.add_pending_ram_usage(*payer, new_bytes - old_bytes)
                        .unwrap();
                } else {
                    fdb.add_pending_ram_usage(old_payer, -old_bytes).unwrap();
                    fdb.add_pending_ram_usage(*payer, new_bytes).unwrap();
                }
                rows.insert(key, (*payer, value.len()));
            }
            RamOp::Remove { sel } => {
                if rows.is_empty() {
                    continue;
                }
                let key = *rows.keys().nth(sel % rows.len()).unwrap();
                let (payer, len) = rows.remove(&key).unwrap();
                let it = rdb.db_find_i64(CODE, key.0, TABLE, key.1);
                rdb.db_remove_i64(it);
                fdb.add_pending_ram_usage(payer, -(len as i64 + KV_OVERHEAD))
                    .unwrap();
            }
        }
    }

    for &acct in &RAM_ACCOUNTS {
        assert_eq!(
            rdb.ram_usage(acct),
            fdb.get_account_ram_usage(acct).unwrap(),
            "RAM diverges for account {acct} after ops {ops:?}"
        );
    }
}

#[test]
fn ram_usage_matches_cpp() {
    let s = |scope: u64, payer: u64, value: &[u8]| RamOp::Store {
        scope,
        payer,
        value: value.to_vec(),
    };
    compare_ram(&[]);
    compare_ram(&[s(0, 101, b"abcd")]);
    // Grow then shrink the same row (same payer): the delta tracks the value.
    compare_ram(&[
        s(0, 101, b"aa"),
        RamOp::Update {
            sel: 0,
            payer: 101,
            value: b"aaaaaa".to_vec(),
        },
    ]);
    // Payer change moves the row's bytes off the old payer onto the new one.
    compare_ram(&[
        s(0, 101, b"abcd"),
        RamOp::Update {
            sel: 0,
            payer: 102,
            value: b"abcd".to_vec(),
        },
    ]);
    // Remove refunds the row but leaves the table overhead on its first payer.
    compare_ram(&[s(0, 101, b"abcd"), RamOp::Remove { sel: 0 }]);
    // Two payers into one table: only the first store bills the table overhead.
    compare_ram(&[s(0, 101, b"ab"), s(0, 102, b"cde")]);
    // Distinct scopes each stand up their own table.
    compare_ram(&[s(0, 101, b"ab"), s(1, 101, b"cd"), s(2, 102, b"ef")]);
}

fn ram_op() -> impl Strategy<Value = RamOp> {
    prop_oneof![
        3 => (0u64..3, 0usize..RAM_ACCOUNTS.len(), vec(any::<u8>(), 0..12))
            .prop_map(|(scope, pi, value)| RamOp::Store { scope, payer: RAM_ACCOUNTS[pi], value }),
        2 => (any::<usize>(), 0usize..RAM_ACCOUNTS.len(), vec(any::<u8>(), 0..12))
            .prop_map(|(sel, pi, value)| RamOp::Update { sel, payer: RAM_ACCOUNTS[pi], value }),
        1 => any::<usize>().prop_map(|sel| RamOp::Remove { sel }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// A random store/update/remove sequence across a few scopes and payers:
    /// arena RAM must equal C++ chainbase RAM for every payer at the end.
    #[test]
    fn ram_usage_matches_cpp_fuzz(ops in vec(ram_op(), 0..24)) {
        compare_ram(&ops);
    }
}

// ---- idx64 secondary index: arena vs C++ chainbase, mirroring the primary ----

/// The secondary-index counterpart of `compare`. Both sides get the same
/// (primary, secondary) rows; then end, a full walk in (secondary, primary)
/// order, find_secondary/find_primary for present and missing keys, a
/// lower/upper-bound sweep over every query value in range, and
/// previous-from-end must all agree on handles and keys.
fn compare_idx64(pairs: &[(u64, u64)]) {
    // ---- C++ chainbase via FFI ----
    let dir = tempdir().unwrap();
    let mut fdb = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
    fdb.add_indices().unwrap();
    let mut fc = Index64IteratorCache::new();
    if !pairs.is_empty() {
        let table_ptr = fdb.create_table(CODE, SCOPE, TABLE, PAYER).unwrap();
        let table_ref: &TableObject = unsafe { &*table_ptr };
        for &(primary, secondary) in pairs {
            fdb.create_index64_object(table_ref, PAYER, primary, secondary)
                .unwrap();
        }
        fc.cache_table(table_ref).unwrap();
    }

    // ---- Rust arena ----
    let mut rdb = ContractDb::new();
    for &(primary, secondary) in pairs {
        rdb.db_idx64_store(CODE, SCOPE, TABLE, PAYER, primary, secondary);
    }
    rdb.reset_iterators();

    // end iterator
    let fe = fdb.db_idx64_end(&mut fc, CODE, SCOPE, TABLE).unwrap();
    let re = rdb.db_idx64_end(CODE, SCOPE, TABLE);
    assert_eq!(fe, re, "idx64 end iterator differs for pairs {pairs:?}");

    // forward walk from lowerbound(0), i.e. secondary then primary order
    let (mut fs, mut fp) = (0u64, 0u64);
    let (mut rs, mut rp) = (0u64, 0u64);
    let mut fit = fdb
        .db_idx64_lowerbound(&mut fc, CODE, SCOPE, TABLE, &mut fs, &mut fp)
        .unwrap();
    let mut rit = rdb.db_idx64_lowerbound(CODE, SCOPE, TABLE, &mut rs, &mut rp);
    assert_eq!(
        fit, rit,
        "idx64 lowerbound(0) handle differs for pairs {pairs:?}"
    );
    assert_eq!(
        (fs, fp),
        (rs, rp),
        "idx64 lowerbound(0) keys differ for pairs {pairs:?}"
    );
    let mut steps = 0;
    while rit != re {
        let (mut fnp, mut rnp) = (0u64, 0u64);
        let fnext = fdb.db_idx64_next(&mut fc, fit, &mut fnp).unwrap();
        let rnext = rdb.db_idx64_next(rit, &mut rnp);
        assert_eq!(
            fnp, rnp,
            "idx64 next primary differs at step {steps} for pairs {pairs:?}"
        );
        assert_eq!(
            fnext, rnext,
            "idx64 next handle differs at step {steps} for pairs {pairs:?}"
        );
        fit = fnext;
        rit = rnext;
        steps += 1;
        assert!(
            steps <= pairs.len() + 1,
            "idx64 walk overran for pairs {pairs:?}"
        );
    }
    assert_eq!(
        fit, fe,
        "idx64 C++ walk did not terminate at end for pairs {pairs:?}"
    );

    // find_secondary / find_primary for a present key
    if let Some(&(present_primary, present_secondary)) = pairs.first() {
        let (mut fpp, mut rpp) = (0u64, 0u64);
        let f = fdb
            .db_idx64_find_secondary(&mut fc, CODE, SCOPE, TABLE, present_secondary, &mut fpp)
            .unwrap();
        let r = rdb.db_idx64_find_secondary(CODE, SCOPE, TABLE, present_secondary, &mut rpp);
        assert_eq!(
            f, r,
            "idx64 find_secondary(present) handle differs for pairs {pairs:?}"
        );
        assert_eq!(
            fpp, rpp,
            "idx64 find_secondary(present) primary differs for pairs {pairs:?}"
        );

        let (mut fss, mut rss) = (0u64, 0u64);
        let f = fdb
            .db_idx64_find_primary(&mut fc, CODE, SCOPE, TABLE, &mut fss, present_primary)
            .unwrap();
        let r = rdb.db_idx64_find_primary(CODE, SCOPE, TABLE, &mut rss, present_primary);
        assert_eq!(
            f, r,
            "idx64 find_primary(present) handle differs for pairs {pairs:?}"
        );
        assert_eq!(
            fss, rss,
            "idx64 find_primary(present) secondary differs for pairs {pairs:?}"
        );
    }

    let max_secondary = pairs.iter().map(|&(_, s)| s).max().unwrap_or(0);
    let max_primary = pairs.iter().map(|&(p, _)| p).max().unwrap_or(0);

    // find_secondary / find_primary for a key that isn't there
    let (mut fpp, mut rpp) = (0u64, 0u64);
    let f = fdb
        .db_idx64_find_secondary(&mut fc, CODE, SCOPE, TABLE, max_secondary + 1, &mut fpp)
        .unwrap();
    let r = rdb.db_idx64_find_secondary(CODE, SCOPE, TABLE, max_secondary + 1, &mut rpp);
    assert_eq!(
        f, r,
        "idx64 find_secondary(missing) handle differs for pairs {pairs:?}"
    );
    assert_eq!(
        fpp, rpp,
        "idx64 find_secondary(missing) primary differs for pairs {pairs:?}"
    );

    let (mut fss, mut rss) = (0u64, 0u64);
    let f = fdb
        .db_idx64_find_primary(&mut fc, CODE, SCOPE, TABLE, &mut fss, max_primary + 1)
        .unwrap();
    let r = rdb.db_idx64_find_primary(CODE, SCOPE, TABLE, &mut rss, max_primary + 1);
    assert_eq!(
        f, r,
        "idx64 find_primary(missing) handle differs for pairs {pairs:?}"
    );
    assert_eq!(
        fss, rss,
        "idx64 find_primary(missing) secondary differs for pairs {pairs:?}"
    );

    // lower/upper bound at every query value in and just past the data
    for q in 0..=max_secondary + 1 {
        let (mut fs, mut fp) = (q, 0u64);
        let (mut rs, mut rp) = (q, 0u64);
        let fl = fdb
            .db_idx64_lowerbound(&mut fc, CODE, SCOPE, TABLE, &mut fs, &mut fp)
            .unwrap();
        let rl = rdb.db_idx64_lowerbound(CODE, SCOPE, TABLE, &mut rs, &mut rp);
        assert_eq!(
            fl, rl,
            "idx64 lowerbound({q}) handle differs for pairs {pairs:?}"
        );
        assert_eq!(
            (fs, fp),
            (rs, rp),
            "idx64 lowerbound({q}) keys differ for pairs {pairs:?}"
        );

        let (mut fs, mut fp) = (q, 0u64);
        let (mut rs, mut rp) = (q, 0u64);
        let fu = fdb
            .db_idx64_upperbound(&mut fc, CODE, SCOPE, TABLE, &mut fs, &mut fp)
            .unwrap();
        let ru = rdb.db_idx64_upperbound(CODE, SCOPE, TABLE, &mut rs, &mut rp);
        assert_eq!(
            fu, ru,
            "idx64 upperbound({q}) handle differs for pairs {pairs:?}"
        );
        assert_eq!(
            (fs, fp),
            (rs, rp),
            "idx64 upperbound({q}) keys differ for pairs {pairs:?}"
        );
    }

    // previous from the end iterator (only meaningful when the table exists)
    if !pairs.is_empty() {
        let (mut fp, mut rp) = (0u64, 0u64);
        let fprev = fdb.db_idx64_previous(&mut fc, fe, &mut fp).unwrap();
        let rprev = rdb.db_idx64_previous(re, &mut rp);
        assert_eq!(
            fp, rp,
            "idx64 previous-from-end primary differs for pairs {pairs:?}"
        );
        assert_eq!(
            fprev, rprev,
            "idx64 previous-from-end handle differs for pairs {pairs:?}"
        );
    }
}

#[test]
fn idx64_semantics_match_cpp() {
    compare_idx64(&[]);
    compare_idx64(&[(1, 10)]);
    compare_idx64(&[(1, 30), (2, 20), (3, 20), (4, 10)]); // ties on secondary 20
    compare_idx64(&[(7, 100), (5, 100), (9, 100)]); // all share a secondary
    compare_idx64(&[(1, 10), (2, 40), (3, 25)]);
    compare_idx64(&[(10, 5), (20, 1), (30, 9), (40, 3), (50, 7)]);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Random rows with distinct primaries and arbitrary (possibly colliding)
    /// secondaries: the arena idx64 must agree with C++ chainbase on every
    /// handle and key across the whole secondary-index surface.
    #[test]
    fn idx64_semantics_match_cpp_fuzz(raw in vec((0u64..40, 0u64..40), 0..16)) {
        // Distinct primary keys, insertion order preserved.
        let mut seen = HashSet::new();
        let pairs: Vec<(u64, u64)> = raw.into_iter().filter(|(p, _)| seen.insert(*p)).collect();
        compare_idx64(&pairs);
    }
}
