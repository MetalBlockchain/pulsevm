//! The idx_long_double secondary index. Like idx_double, its ordering is
//! consensus-critical: it must match EOS's `soft_long_double_less` (`f128_lt`) —
//! numeric order over IEEE binary128 values, negatives included, with `-0.0` and
//! `+0.0` treated as the same key. NaN is not a valid secondary key (EOS asserts
//! it away before it reaches the index), so it is not exercised here.
//!
//! Rust has no stable 128-bit float, so the secondary key crosses the API as its
//! raw 128-bit bit pattern (`u128`), exactly as the C++ `float128_t` does. The
//! [`f128_bits`] helper widens an `f64` to that pattern (every `f64` is exactly
//! representable in binary128), which keeps these cases readable while still
//! driving the real 128-bit comparator.

use pulsevm_contractdb::ContractDb;

const CODE: u64 = 1;
const SCOPE: u64 = 2;
const TABLE: u64 = 3;

/// Widens an `f64` to the IEEE binary128 bit pattern it represents. Handles the
/// values these tests use: normals, both zeros, and the infinities. (Subnormal
/// `f64`s and NaN are not used here and are not converted.)
fn f128_bits(x: f64) -> u128 {
    let b = x.to_bits();
    let sign = (b >> 63) as u128;
    let exp = (b >> 52) & 0x7ff;
    let mant = (b & 0x000f_ffff_ffff_ffff) as u128;
    let sign_bit = sign << 127;
    if exp == 0 {
        // Zero (both mant and exp are 0 for the values used here); keep the sign.
        return sign_bit;
    }
    if exp == 0x7ff {
        // Infinity: binary128 exponent all ones, mantissa 0.
        return sign_bit | (0x7fffu128 << 112);
    }
    // Normal: rebias the exponent (f64 bias 1023 -> binary128 bias 16383) and
    // left-align the 52-bit mantissa into the 112-bit binary128 field.
    let new_exp = (exp + (16383 - 1023)) as u128;
    sign_bit | (new_exp << 112) | (mant << 60)
}

fn store(db: &mut ContractDb, primary: u64, secondary: f64) -> i32 {
    db.db_idx_long_double_store(CODE, SCOPE, TABLE, CODE, primary, f128_bits(secondary))
}

fn traversal(db: &mut ContractDb) -> Vec<u64> {
    let end = db.db_idx_long_double_end(CODE, SCOPE, TABLE);
    let mut secondary = f128_bits(f64::NEG_INFINITY);
    let mut primary = 0u64;
    let mut it = db.db_idx_long_double_lowerbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    let mut order = Vec::new();
    while it != end {
        order.push(primary);
        it = db.db_idx_long_double_next(it, &mut primary);
    }
    order
}

#[test]
fn traverses_in_secondary_then_primary_order() {
    let mut db = ContractDb::new();
    store(&mut db, 1, 3.5);
    store(&mut db, 2, 2.0);
    store(&mut db, 3, 2.0);
    store(&mut db, 4, 1.25);

    let end = db.db_idx_long_double_end(CODE, SCOPE, TABLE);
    let mut secondary = f128_bits(f64::NEG_INFINITY);
    let mut primary = 0u64;
    let mut it = db.db_idx_long_double_lowerbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    let mut order = Vec::new();
    while it != end {
        let mut s = 0u128;
        let _ = db.db_idx_long_double_find_primary(CODE, SCOPE, TABLE, &mut s, primary);
        order.push((s, primary));
        it = db.db_idx_long_double_next(it, &mut primary);
    }
    assert_eq!(
        order,
        vec![
            (f128_bits(1.25), 4),
            (f128_bits(2.0), 2),
            (f128_bits(2.0), 3),
            (f128_bits(3.5), 1),
        ]
    );
}

#[test]
fn orders_negatives_below_positives() {
    let mut db = ContractDb::new();
    store(&mut db, 1, 1.0);
    store(&mut db, 2, -1.0);
    store(&mut db, 3, -1000.0);
    store(&mut db, 4, 0.0);
    assert_eq!(traversal(&mut db), vec![3, 2, 4, 1]);
}

#[test]
fn negative_and_positive_zero_are_the_same_key() {
    let mut db = ContractDb::new();
    store(&mut db, 1, 0.0);
    // -0.0 must not be a distinct secondary key: find_secondary on +0.0 finds it,
    // and ordering ties break on the primary key.
    store(&mut db, 2, -0.0);

    let mut primary = 0u64;
    let it =
        db.db_idx_long_double_find_secondary(CODE, SCOPE, TABLE, f128_bits(-0.0), &mut primary);
    assert!(it >= 0);
    assert_eq!(
        primary, 1,
        "+0.0 and -0.0 collapse to one key, lowest primary"
    );

    // Both rows sit adjacent with equal secondary; primary orders them.
    assert_eq!(traversal(&mut db), vec![1, 2]);
}

#[test]
fn find_secondary_returns_lowest_primary_for_that_key() {
    let mut db = ContractDb::new();
    store(&mut db, 7, 100.0);
    store(&mut db, 5, 100.0);
    store(&mut db, 9, 100.0);

    let mut primary = 0u64;
    let it =
        db.db_idx_long_double_find_secondary(CODE, SCOPE, TABLE, f128_bits(100.0), &mut primary);
    assert!(it >= 0);
    assert_eq!(primary, 5, "ties resolve to the lowest primary key");

    let end = db.db_idx_long_double_end(CODE, SCOPE, TABLE);
    let mut p = 0u64;
    assert_eq!(
        db.db_idx_long_double_find_secondary(CODE, SCOPE, TABLE, f128_bits(999.0), &mut p),
        end
    );
}

#[test]
fn find_primary_reports_secondary() {
    let mut db = ContractDb::new();
    store(&mut db, 42, -12.5);
    let mut secondary = 0u128;
    let it = db.db_idx_long_double_find_primary(CODE, SCOPE, TABLE, &mut secondary, 42);
    assert!(it >= 0);
    assert_eq!(secondary, f128_bits(-12.5));
}

#[test]
fn upperbound_skips_the_whole_secondary_key() {
    let mut db = ContractDb::new();
    store(&mut db, 1, 1.0);
    store(&mut db, 2, 2.0);
    store(&mut db, 3, 2.0);
    store(&mut db, 4, 3.0);

    let mut secondary = f128_bits(2.0);
    let mut primary = 0u64;
    let it = db.db_idx_long_double_upperbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    assert!(it >= 0);
    assert_eq!((secondary, primary), (f128_bits(3.0), 4));
}

#[test]
fn previous_from_end_is_highest_secondary() {
    let mut db = ContractDb::new();
    store(&mut db, 1, 1.0);
    store(&mut db, 2, 40.0);
    store(&mut db, 3, 25.0);

    let end = db.db_idx_long_double_end(CODE, SCOPE, TABLE);
    let mut primary = 0u64;
    let last = db.db_idx_long_double_previous(end, &mut primary);
    assert!(last >= 0);
    assert_eq!(primary, 2, "the highest secondary (40.0) is primary 2");
}

#[test]
fn distinguishes_keys_below_f64_precision() {
    // Two binary128 values one ULP apart at the 128-bit level: identical when
    // truncated to a double, distinct here. Proves the index keeps the full
    // 113-bit significand rather than collapsing to an f64 key.
    let mut db = ContractDb::new();
    let base = f128_bits(1.0);
    let a = base; // exactly 1.0
    let b = base + 1; // 1.0 + 2^-112, unrepresentable in f64

    // Store the larger key first with the larger primary to be sure ordering is
    // by secondary, not insertion or primary order.
    db.db_idx_long_double_store(CODE, SCOPE, TABLE, CODE, 2, b);
    db.db_idx_long_double_store(CODE, SCOPE, TABLE, CODE, 1, a);

    // They are different keys: find_secondary on `a` returns primary 1 only.
    let mut primary = 0u64;
    let it = db.db_idx_long_double_find_secondary(CODE, SCOPE, TABLE, a, &mut primary);
    assert!(it >= 0);
    assert_eq!(primary, 1);

    // And `a` sorts before `b`.
    assert_eq!(traversal(&mut db), vec![1, 2]);
}
