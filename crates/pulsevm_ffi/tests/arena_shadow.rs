//! End-to-end check that a ported write reaches the arena mirror through the
//! real `Database` wrapper: chainbase does the write, and the arena shadow —
//! carried inside `Database` and shared across clones — receives the same
//! mutation, so its state root moves, an undo reverts it, and a commit keeps it.
//!
//! This exercises the mirror seam itself (write path + arena session lifecycle),
//! not yet the controller's nested build/verify/accept session stack, which is
//! where the remaining integration work lives.

#![cfg(feature = "arena-shadow")]

use pulsevm_ffi::{
    Database,
    Float128,
    Index128IteratorCache,
    Index256IteratorCache,
    IndexDoubleIteratorCache,
    IndexLongDoubleIteratorCache,
    TableObject,
    U256,
};
use tempfile::tempdir;

const DB_SIZE: u64 = 8 * 1024 * 1024 * 1024;

const CODE: u64 = 1;
const SCOPE: u64 = 2;
const TABLE: u64 = 3;
const PAYER: u64 = 1;

fn shadowed_db(dir: &std::path::Path) -> Database {
    let mut db = Database::new(dir.to_str().unwrap(), DB_SIZE).unwrap();
    db.add_indices().unwrap();
    db.enable_shadow().unwrap();
    db.arena_start_undo_session();
    db
}

fn u256(lo: u128, hi: u128) -> U256 {
    let mut value = [0u8; 32];
    value[..16].copy_from_slice(&lo.to_le_bytes());
    value[16..].copy_from_slice(&hi.to_le_bytes());
    U256 { value }
}

#[test]
fn account_metadata_writes_mirror_into_the_arena() {
    let dir = tempdir().unwrap();
    let mut db = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
    db.add_indices().unwrap();
    db.enable_shadow().unwrap();

    let empty = db.arena_state_root().expect("shadow enabled");

    // A ported write moves the arena root...
    db.arena_start_undo_session();
    db.create_account_metadata(0x1111, false).unwrap();
    let one = db.arena_state_root().unwrap();
    assert_ne!(empty, one, "first mirrored write did not move the root");

    db.create_account_metadata(0x2222, true).unwrap();
    let two = db.arena_state_root().unwrap();
    assert_ne!(one, two, "second mirrored write did not move the root");

    // ...and undoing the session reverts both mirrored rows.
    db.arena_undo();
    assert_eq!(
        empty,
        db.arena_state_root().unwrap(),
        "undo did not revert the mirror"
    );

    // A committed session keeps its rows.
    db.arena_start_undo_session();
    db.create_account_metadata(0x3333, false).unwrap();
    let kept = db.arena_state_root().unwrap();
    assert_ne!(empty, kept);
    db.arena_commit(i64::MAX);
    assert_eq!(
        kept,
        db.arena_state_root().unwrap(),
        "commit did not keep the mirror"
    );
}

/// The resource_limits pending/commit cycle has no action path in this chain,
/// so it is exercised directly at the Database boundary: chainbase does each
/// write, and the mirror must agree with get_account_limits at every step —
/// unlimited at init, the staged values once set, and the same after commit.
#[test]
fn account_limits_pending_and_commit_mirror() {
    let dir = tempdir().unwrap();
    let mut db = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
    db.add_indices().unwrap();
    db.initialize_resource_limits().unwrap();
    db.enable_shadow().unwrap();
    db.arena_start_undo_session();

    let acct = 0x9999u64;

    let check = |db: &Database| {
        let (mut ram, mut net, mut cpu) = (0i64, 0i64, 0i64);
        db.get_account_limits(acct, &mut ram, &mut net, &mut cpu)
            .unwrap();
        assert_eq!(
            db.arena_account_limits(acct),
            Some((ram, net, cpu)),
            "mirror disagreed with chainbase get_account_limits"
        );
        (ram, net, cpu)
    };

    db.initialize_account_resource_limits(acct).unwrap();
    assert_eq!(check(&db), (-1, -1, -1), "init should be unlimited");

    // Staged on a pending row: the effective limits change immediately.
    db.set_account_limits(acct, 8192, 100, 200).unwrap();
    assert_eq!(check(&db), (8192, 100, 200), "pending limits not effective");

    // Commit merges pending into the committed row and drops the pending row.
    db.process_account_limit_updates().unwrap();
    assert_eq!(check(&db), (8192, 100, 200), "committed limits diverged");
}

/// The idx128 secondary-index read accessors the arena serves during execution
/// must answer exactly as chainbase does. Drive the same stores through the
/// Database (which mirrors them into the shadow), then compare the arena
/// accessors against chainbase's db_idx128_* for hits, misses, and the
/// lower/upper bound landing pair across the whole key range — including a
/// duplicate secondary key, where ordering is by (secondary, primary).
#[test]
fn idx128_read_accessors_match_chainbase() {
    const CODE: u64 = 1;
    const SCOPE: u64 = 2;
    const TABLE: u64 = 3;
    const PAYER: u64 = 1;

    let dir = tempdir().unwrap();
    let mut db = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
    db.add_indices().unwrap();
    db.enable_shadow().unwrap();
    db.arena_start_undo_session();

    let table_ptr = db.create_table(CODE, SCOPE, TABLE, PAYER).unwrap();
    let table_ref: &TableObject = unsafe { &*table_ptr };
    // (primary, secondary) — 50 is deliberately shared by two primaries.
    let pairs: [(u64, u128); 4] = [(10, 100), (20, 50), (30, 200), (40, 50)];
    for &(pk, sk) in &pairs {
        db.create_index128_object(table_ref, PAYER, pk, sk).unwrap();
    }

    let mut cache = Index128IteratorCache::new();

    // find_secondary: every stored key, plus a missing one. On a shared
    // secondary chainbase returns the lowest primary; the arena must match.
    for sk in [50u128, 100, 200, 999] {
        let mut fp = 0u64;
        let res = db
            .db_idx128_find_secondary(&mut cache, CODE, SCOPE, TABLE, sk, &mut fp)
            .unwrap();
        let ffi = (res >= 0).then_some(fp);
        assert_eq!(
            db.arena_idx128_find_secondary(CODE, SCOPE, TABLE, sk),
            ffi,
            "idx128 find_secondary mismatch at sk={sk}"
        );
    }

    // find_primary: every stored primary, plus a missing one.
    for pk in [10u64, 20, 30, 40, 999] {
        let mut fs = 0u128;
        let res = db
            .db_idx128_find_primary(&mut cache, CODE, SCOPE, TABLE, &mut fs, pk)
            .unwrap();
        let ffi = (res >= 0).then_some(fs);
        assert_eq!(
            db.arena_idx128_find_primary(CODE, SCOPE, TABLE, pk),
            ffi,
            "idx128 find_primary mismatch at pk={pk}"
        );
    }

    // lower/upper bound land on a row and return both its primary and secondary;
    // sweep search keys below, on, between, and above the stored keys.
    for search in [0u128, 50, 51, 100, 150, 200, 201] {
        let (mut ls, mut lp) = (search, 0u64);
        let res = db
            .db_idx128_lowerbound(&mut cache, CODE, SCOPE, TABLE, &mut ls, &mut lp)
            .unwrap();
        let ffi = (res >= 0).then_some((lp, ls));
        assert_eq!(
            db.arena_idx128_lower_bound(CODE, SCOPE, TABLE, search),
            ffi,
            "idx128 lowerbound mismatch at search={search}"
        );

        let (mut us, mut up) = (search, 0u64);
        let res = db
            .db_idx128_upperbound(&mut cache, CODE, SCOPE, TABLE, &mut us, &mut up)
            .unwrap();
        let ffi = (res >= 0).then_some((up, us));
        assert_eq!(
            db.arena_idx128_upper_bound(CODE, SCOPE, TABLE, search),
            ffi,
            "idx128 upperbound mismatch at search={search}"
        );
    }
}

/// idx_double read accessors vs chainbase. The intrinsic carries the float64 as
/// its raw u64 bits; the arena keys on f64. Same stores, then compare across the
/// key range including a shared secondary.
#[test]
fn idx_double_read_accessors_match_chainbase() {
    let dir = tempdir().unwrap();
    let mut db = shadowed_db(dir.path());
    let table_ptr = db.create_table(CODE, SCOPE, TABLE, PAYER).unwrap();
    let table_ref: &TableObject = unsafe { &*table_ptr };
    // (primary, secondary f64) — 2.5 shared by two primaries.
    let pairs: [(u64, f64); 4] = [(10, 1.5), (20, 2.5), (30, 4.0), (40, 2.5)];
    for &(pk, sk) in &pairs {
        db.create_idx_double_object(table_ref, PAYER, pk, sk.to_bits())
            .unwrap();
    }
    let mut cache = IndexDoubleIteratorCache::new();

    for sk in [1.5f64, 2.5, 4.0, 9.0] {
        let mut fp = 0u64;
        let res = db
            .db_idx_double_find_secondary(&mut cache, CODE, SCOPE, TABLE, sk.to_bits(), &mut fp)
            .unwrap();
        let ffi = (res >= 0).then_some(fp);
        assert_eq!(
            db.arena_idx_double_find_secondary(CODE, SCOPE, TABLE, sk.to_bits()),
            ffi,
            "idx_double find_secondary mismatch at sk={sk}"
        );
    }
    for pk in [10u64, 20, 30, 40, 999] {
        let mut fs = 0u64;
        let res = db
            .db_idx_double_find_primary(&mut cache, CODE, SCOPE, TABLE, &mut fs, pk)
            .unwrap();
        let ffi = (res >= 0).then_some(fs);
        assert_eq!(
            db.arena_idx_double_find_primary(CODE, SCOPE, TABLE, pk),
            ffi,
            "idx_double find_primary mismatch at pk={pk}"
        );
    }
    for search in [0.0f64, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0] {
        let (mut ls, mut lp) = (search.to_bits(), 0u64);
        let res = db
            .db_idx_double_lowerbound(&mut cache, CODE, SCOPE, TABLE, &mut ls, &mut lp)
            .unwrap();
        let ffi = (res >= 0).then_some((lp, ls));
        assert_eq!(
            db.arena_idx_double_lower_bound(CODE, SCOPE, TABLE, search.to_bits()),
            ffi,
            "idx_double lowerbound mismatch at search={search}"
        );
        let (mut us, mut up) = (search.to_bits(), 0u64);
        let res = db
            .db_idx_double_upperbound(&mut cache, CODE, SCOPE, TABLE, &mut us, &mut up)
            .unwrap();
        let ffi = (res >= 0).then_some((up, us));
        assert_eq!(
            db.arena_idx_double_upper_bound(CODE, SCOPE, TABLE, search.to_bits()),
            ffi,
            "idx_double upperbound mismatch at search={search}"
        );
    }
}

/// idx256 read accessors vs chainbase over the raw 32-byte key.
#[test]
fn idx256_read_accessors_match_chainbase() {
    let dir = tempdir().unwrap();
    let mut db = shadowed_db(dir.path());
    let table_ptr = db.create_table(CODE, SCOPE, TABLE, PAYER).unwrap();
    let table_ref: &TableObject = unsafe { &*table_ptr };
    let pairs: [(u64, (u128, u128)); 4] =
        [(10, (100, 0)), (20, (50, 0)), (30, (0, 7)), (40, (50, 0))];
    for &(pk, (lo, hi)) in &pairs {
        db.create_index256_object(table_ref, PAYER, pk, u256(lo, hi))
            .unwrap();
    }
    let mut cache = Index256IteratorCache::new();

    for (lo, hi) in [(100u128, 0u128), (50, 0), (0, 7), (123, 456)] {
        let mut fp = 0u64;
        let res = db
            .db_idx256_find_secondary(&mut cache, CODE, SCOPE, TABLE, u256(lo, hi), &mut fp)
            .unwrap();
        let ffi = (res >= 0).then_some(fp);
        assert_eq!(
            db.arena_idx256_find_secondary(CODE, SCOPE, TABLE, u256(lo, hi).value),
            ffi,
            "idx256 find_secondary mismatch at ({lo},{hi})"
        );
    }
    for pk in [10u64, 20, 30, 40, 999] {
        let mut fs = u256(0, 0);
        let res = db
            .db_idx256_find_primary(&mut cache, CODE, SCOPE, TABLE, &mut fs, pk)
            .unwrap();
        let ffi = (res >= 0).then_some(fs.value);
        assert_eq!(
            db.arena_idx256_find_primary(CODE, SCOPE, TABLE, pk),
            ffi,
            "idx256 find_primary mismatch at pk={pk}"
        );
    }
    for (lo, hi) in [(0u128, 0u128), (50, 0), (51, 0), (100, 0), (0, 7), (0, 8)] {
        let mut ls = u256(lo, hi);
        let mut lp = 0u64;
        let res = db
            .db_idx256_lowerbound(&mut cache, CODE, SCOPE, TABLE, &mut ls, &mut lp)
            .unwrap();
        let ffi = (res >= 0).then_some((lp, ls.value));
        assert_eq!(
            db.arena_idx256_lower_bound(CODE, SCOPE, TABLE, u256(lo, hi).value),
            ffi,
            "idx256 lowerbound mismatch at ({lo},{hi})"
        );
        let mut us = u256(lo, hi);
        let mut up = 0u64;
        let res = db
            .db_idx256_upperbound(&mut cache, CODE, SCOPE, TABLE, &mut us, &mut up)
            .unwrap();
        let ffi = (res >= 0).then_some((up, us.value));
        assert_eq!(
            db.arena_idx256_upper_bound(CODE, SCOPE, TABLE, u256(lo, hi).value),
            ffi,
            "idx256 upperbound mismatch at ({lo},{hi})"
        );
    }
}

/// idx_long_double read accessors vs chainbase. The float128 crosses as (lo, hi)
/// words; both backends must land identically under the same ordering.
#[test]
fn idx_long_double_read_accessors_match_chainbase() {
    let dir = tempdir().unwrap();
    let mut db = shadowed_db(dir.path());
    let table_ptr = db.create_table(CODE, SCOPE, TABLE, PAYER).unwrap();
    let table_ref: &TableObject = unsafe { &*table_ptr };
    // float128 bit patterns for 1.0, 2.0, 4.0 (hi holds sign+exponent), and a
    // repeat of 2.0 under a second primary.
    let f = |v: f64| -> (u64, u64) {
        // Reuse the C++ builtin conversion path by round-tripping through store:
        // here we just need distinct, ordered patterns, so synthesize from f64
        // exponent bits shifted into the float128 layout is overkill — instead
        // use small integer-valued patterns the ordering treats as increasing.
        let bits = v.to_bits();
        (0, bits) // hi carries the ordering-significant bits; lo = 0
    };
    let pairs: [(u64, (u64, u64)); 4] = [(10, f(1.0)), (20, f(2.0)), (30, f(4.0)), (40, f(2.0))];
    for &(pk, (lo, hi)) in &pairs {
        db.create_idx_long_double_object(table_ref, PAYER, pk, Float128 { lo, hi })
            .unwrap();
    }
    let mut cache = IndexLongDoubleIteratorCache::new();

    for (lo, hi) in [f(1.0), f(2.0), f(4.0), f(9.0)] {
        let mut fp = 0u64;
        let res = db
            .db_idx_long_double_find_secondary(
                &mut cache,
                CODE,
                SCOPE,
                TABLE,
                Float128 { lo, hi },
                &mut fp,
            )
            .unwrap();
        let ffi = (res >= 0).then_some(fp);
        assert_eq!(
            db.arena_idx_long_double_find_secondary(CODE, SCOPE, TABLE, (lo, hi)),
            ffi,
            "idx_long_double find_secondary mismatch at ({lo},{hi})"
        );
    }
    for pk in [10u64, 20, 30, 40, 999] {
        let mut fs = Float128 { lo: 0, hi: 0 };
        let res = db
            .db_idx_long_double_find_primary(&mut cache, CODE, SCOPE, TABLE, &mut fs, pk)
            .unwrap();
        let ffi = (res >= 0).then_some((fs.lo, fs.hi));
        assert_eq!(
            db.arena_idx_long_double_find_primary(CODE, SCOPE, TABLE, pk),
            ffi,
            "idx_long_double find_primary mismatch at pk={pk}"
        );
    }
    for (lo, hi) in [f(0.5), f(1.0), f(1.5), f(2.0), f(3.0), f(4.0), f(5.0)] {
        let mut ls = Float128 { lo, hi };
        let mut lp = 0u64;
        let res = db
            .db_idx_long_double_lowerbound(&mut cache, CODE, SCOPE, TABLE, &mut ls, &mut lp)
            .unwrap();
        let ffi = (res >= 0).then_some((lp, (ls.lo, ls.hi)));
        assert_eq!(
            db.arena_idx_long_double_lower_bound(CODE, SCOPE, TABLE, (lo, hi)),
            ffi,
            "idx_long_double lowerbound mismatch at ({lo},{hi})"
        );
        let mut us = Float128 { lo, hi };
        let mut up = 0u64;
        let res = db
            .db_idx_long_double_upperbound(&mut cache, CODE, SCOPE, TABLE, &mut us, &mut up)
            .unwrap();
        let ffi = (res >= 0).then_some((up, (us.lo, us.hi)));
        assert_eq!(
            db.arena_idx_long_double_upper_bound(CODE, SCOPE, TABLE, (lo, hi)),
            ffi,
            "idx_long_double upperbound mismatch at ({lo},{hi})"
        );
    }
}

#[test]
fn shadow_is_absent_until_enabled() {
    let dir = tempdir().unwrap();
    let db = Database::new(dir.path().to_str().unwrap(), DB_SIZE).unwrap();
    assert!(
        db.arena_state_root().is_none(),
        "no shadow before enable_shadow"
    );
}
