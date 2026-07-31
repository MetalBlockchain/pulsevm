//! The idx64 secondary index: lookups and traversal follow secondary-key order,
//! with ties broken by primary key, matching EOS multi-index semantics.

use pulsevm_contractdb::ContractDb;

const CODE: u64 = 1;
const SCOPE: u64 = 2;
const TABLE: u64 = 3;

fn store(db: &mut ContractDb, primary: u64, secondary: u64) -> i32 {
    db.db_idx64_store(CODE, SCOPE, TABLE, CODE, primary, secondary)
}

#[test]
fn traverses_in_secondary_then_primary_order() {
    let mut db = ContractDb::new();
    // Insert out of order; two rows share secondary 20.
    store(&mut db, 1, 30);
    store(&mut db, 2, 20);
    store(&mut db, 3, 20);
    store(&mut db, 4, 10);

    let end = db.db_idx64_end(CODE, SCOPE, TABLE);
    let mut secondary = 0u64;
    let mut primary = 0u64;
    let mut it = db.db_idx64_lowerbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    let mut order = Vec::new();
    while it != end {
        // Record (secondary, primary) of the current entry.
        let mut s = 0u64;
        let cur = db.db_idx64_find_primary(CODE, SCOPE, TABLE, &mut s, primary);
        let _ = cur;
        order.push((s, primary));
        it = db.db_idx64_next(it, &mut primary);
    }
    assert_eq!(order, vec![(10, 4), (20, 2), (20, 3), (30, 1)]);
}

#[test]
fn find_secondary_returns_lowest_primary_for_that_key() {
    let mut db = ContractDb::new();
    store(&mut db, 7, 100);
    store(&mut db, 5, 100);
    store(&mut db, 9, 100);

    let mut primary = 0u64;
    let it = db.db_idx64_find_secondary(CODE, SCOPE, TABLE, 100, &mut primary);
    assert!(it >= 0);
    assert_eq!(primary, 5, "ties resolve to the lowest primary key");

    // A secondary key that isn't present gives the end iterator.
    let end = db.db_idx64_end(CODE, SCOPE, TABLE);
    let mut p = 0u64;
    assert_eq!(db.db_idx64_find_secondary(CODE, SCOPE, TABLE, 999, &mut p), end);
}

#[test]
fn find_primary_reports_secondary() {
    let mut db = ContractDb::new();
    store(&mut db, 42, 500);
    let mut secondary = 0u64;
    let it = db.db_idx64_find_primary(CODE, SCOPE, TABLE, &mut secondary, 42);
    assert!(it >= 0);
    assert_eq!(secondary, 500);
}

#[test]
fn upperbound_skips_the_whole_secondary_key() {
    let mut db = ContractDb::new();
    store(&mut db, 1, 10);
    store(&mut db, 2, 20);
    store(&mut db, 3, 20);
    store(&mut db, 4, 30);

    // upperbound(20) lands on the first entry with secondary > 20.
    let mut secondary = 20u64;
    let mut primary = 0u64;
    let it = db.db_idx64_upperbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    assert!(it >= 0);
    assert_eq!((secondary, primary), (30, 4));
}

#[test]
fn previous_from_end_is_highest_secondary() {
    let mut db = ContractDb::new();
    store(&mut db, 1, 10);
    store(&mut db, 2, 40);
    store(&mut db, 3, 25);

    let end = db.db_idx64_end(CODE, SCOPE, TABLE);
    let mut primary = 0u64;
    let last = db.db_idx64_previous(end, &mut primary);
    assert!(last >= 0);
    assert_eq!(primary, 2, "the highest secondary (40) is primary 2");
}
