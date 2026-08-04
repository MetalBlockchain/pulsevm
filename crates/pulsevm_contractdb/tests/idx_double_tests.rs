//! The idx_double secondary index. Ordering is consensus-critical: it must match
//! EOS's `soft_double_less` (`f64_lt`) — numeric order over doubles, negatives
//! included, with `-0.0` and `+0.0` treated as the same key. NaN is not a valid
//! secondary key (EOS asserts it away before it reaches the index), so it is not
//! exercised here.

use pulsevm_contractdb::ContractDb;

const CODE: u64 = 1;
const SCOPE: u64 = 2;
const TABLE: u64 = 3;

fn store(db: &mut ContractDb, primary: u64, secondary: f64) -> i32 {
    db.db_idx_double_store(CODE, SCOPE, TABLE, CODE, primary, secondary)
}

fn traversal(db: &mut ContractDb) -> Vec<u64> {
    let end = db.db_idx_double_end(CODE, SCOPE, TABLE);
    let mut secondary = f64::NEG_INFINITY;
    let mut primary = 0u64;
    let mut it = db.db_idx_double_lowerbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    let mut order = Vec::new();
    while it != end {
        order.push(primary);
        it = db.db_idx_double_next(it, &mut primary);
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

    let end = db.db_idx_double_end(CODE, SCOPE, TABLE);
    let mut secondary = f64::NEG_INFINITY;
    let mut primary = 0u64;
    let mut it = db.db_idx_double_lowerbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    let mut order = Vec::new();
    while it != end {
        let mut s = 0f64;
        let _ = db.db_idx_double_find_primary(CODE, SCOPE, TABLE, &mut s, primary);
        order.push((s, primary));
        it = db.db_idx_double_next(it, &mut primary);
    }
    assert_eq!(order, vec![(1.25, 4), (2.0, 2), (2.0, 3), (3.5, 1)]);
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
    let it = db.db_idx_double_find_secondary(CODE, SCOPE, TABLE, -0.0, &mut primary);
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
    let it = db.db_idx_double_find_secondary(CODE, SCOPE, TABLE, 100.0, &mut primary);
    assert!(it >= 0);
    assert_eq!(primary, 5, "ties resolve to the lowest primary key");

    let end = db.db_idx_double_end(CODE, SCOPE, TABLE);
    let mut p = 0u64;
    assert_eq!(
        db.db_idx_double_find_secondary(CODE, SCOPE, TABLE, 999.0, &mut p),
        end
    );
}

#[test]
fn find_primary_reports_secondary() {
    let mut db = ContractDb::new();
    store(&mut db, 42, -12.5);
    let mut secondary = 0f64;
    let it = db.db_idx_double_find_primary(CODE, SCOPE, TABLE, &mut secondary, 42);
    assert!(it >= 0);
    assert_eq!(secondary, -12.5);
}

#[test]
fn upperbound_skips_the_whole_secondary_key() {
    let mut db = ContractDb::new();
    store(&mut db, 1, 1.0);
    store(&mut db, 2, 2.0);
    store(&mut db, 3, 2.0);
    store(&mut db, 4, 3.0);

    let mut secondary = 2.0;
    let mut primary = 0u64;
    let it = db.db_idx_double_upperbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    assert!(it >= 0);
    assert_eq!((secondary, primary), (3.0, 4));
}

#[test]
fn previous_from_end_is_highest_secondary() {
    let mut db = ContractDb::new();
    store(&mut db, 1, 1.0);
    store(&mut db, 2, 40.0);
    store(&mut db, 3, 25.0);

    let end = db.db_idx_double_end(CODE, SCOPE, TABLE);
    let mut primary = 0u64;
    let last = db.db_idx_double_previous(end, &mut primary);
    assert!(last >= 0);
    assert_eq!(primary, 2, "the highest secondary (40.0) is primary 2");
}
