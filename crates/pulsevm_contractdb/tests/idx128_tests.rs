//! The idx128 secondary index: same traversal contract as idx64, but the key is
//! a full `u128`, so the tests reach past 64 bits to prove nothing truncates.

use pulsevm_contractdb::ContractDb;

const CODE: u64 = 1;
const SCOPE: u64 = 2;
const TABLE: u64 = 3;

fn store(db: &mut ContractDb, primary: u64, secondary: u128) -> i32 {
    db.db_idx128_store(CODE, SCOPE, TABLE, CODE, primary, secondary)
}

// A value that lives entirely in the high 64 bits, to catch word-swap bugs.
const HIGH: u128 = 1u128 << 64;

#[test]
fn traverses_in_secondary_then_primary_order() {
    let mut db = ContractDb::new();
    store(&mut db, 1, HIGH + 30);
    store(&mut db, 2, HIGH + 20);
    store(&mut db, 3, HIGH + 20);
    store(&mut db, 4, HIGH + 10);

    let end = db.db_idx128_end(CODE, SCOPE, TABLE);
    let mut secondary = 0u128;
    let mut primary = 0u64;
    let mut it = db.db_idx128_lowerbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    let mut order = Vec::new();
    while it != end {
        let mut s = 0u128;
        let _ = db.db_idx128_find_primary(CODE, SCOPE, TABLE, &mut s, primary);
        order.push((s, primary));
        it = db.db_idx128_next(it, &mut primary);
    }
    assert_eq!(
        order,
        vec![
            (HIGH + 10, 4),
            (HIGH + 20, 2),
            (HIGH + 20, 3),
            (HIGH + 30, 1)
        ]
    );
}

#[test]
fn find_secondary_returns_lowest_primary_for_that_key() {
    let mut db = ContractDb::new();
    store(&mut db, 7, HIGH + 100);
    store(&mut db, 5, HIGH + 100);
    store(&mut db, 9, HIGH + 100);

    let mut primary = 0u64;
    let it = db.db_idx128_find_secondary(CODE, SCOPE, TABLE, HIGH + 100, &mut primary);
    assert!(it >= 0);
    assert_eq!(primary, 5, "ties resolve to the lowest primary key");

    let end = db.db_idx128_end(CODE, SCOPE, TABLE);
    let mut p = 0u64;
    assert_eq!(
        db.db_idx128_find_secondary(CODE, SCOPE, TABLE, HIGH + 999, &mut p),
        end
    );
}

#[test]
fn find_primary_reports_secondary() {
    let mut db = ContractDb::new();
    let big = (HIGH * 7) + 500;
    store(&mut db, 42, big);
    let mut secondary = 0u128;
    let it = db.db_idx128_find_primary(CODE, SCOPE, TABLE, &mut secondary, 42);
    assert!(it >= 0);
    assert_eq!(secondary, big);
}

#[test]
fn upperbound_skips_the_whole_secondary_key() {
    let mut db = ContractDb::new();
    store(&mut db, 1, HIGH + 10);
    store(&mut db, 2, HIGH + 20);
    store(&mut db, 3, HIGH + 20);
    store(&mut db, 4, HIGH + 30);

    let mut secondary = HIGH + 20;
    let mut primary = 0u64;
    let it = db.db_idx128_upperbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    assert!(it >= 0);
    assert_eq!((secondary, primary), (HIGH + 30, 4));
}

#[test]
fn previous_from_end_is_highest_secondary() {
    let mut db = ContractDb::new();
    store(&mut db, 1, HIGH + 10);
    store(&mut db, 2, HIGH + 40);
    store(&mut db, 3, HIGH + 25);

    let end = db.db_idx128_end(CODE, SCOPE, TABLE);
    let mut primary = 0u64;
    let last = db.db_idx128_previous(end, &mut primary);
    assert!(last >= 0);
    assert_eq!(primary, 2, "the highest secondary is primary 2");
}

#[test]
fn update_moves_the_entry_in_secondary_order() {
    let mut db = ContractDb::new();
    store(&mut db, 1, HIGH + 10);
    let it = store(&mut db, 2, HIGH + 20);
    // Move primary 2 below primary 1 in secondary order.
    db.db_idx128_update(it, HIGH + 5);

    let end = db.db_idx128_end(CODE, SCOPE, TABLE);
    let mut secondary = 0u128;
    let mut primary = 0u64;
    let mut cur = db.db_idx128_lowerbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    let mut order = Vec::new();
    while cur != end {
        order.push(primary);
        cur = db.db_idx128_next(cur, &mut primary);
    }
    assert_eq!(order, vec![2, 1]);
}
