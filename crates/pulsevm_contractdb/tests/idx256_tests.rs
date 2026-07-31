//! The idx256 secondary index. The key is `[u128; 2]` compared lexicographically
//! with element `[0]` most significant, mirroring EOS's `std::array<uint128_t,2>`
//! `operator<`; the tests pin that word order down.

use pulsevm_contractdb::ContractDb;

const CODE: u64 = 1;
const SCOPE: u64 = 2;
const TABLE: u64 = 3;

fn store(db: &mut ContractDb, primary: u64, secondary: [u128; 2]) -> i32 {
    db.db_idx256_store(CODE, SCOPE, TABLE, CODE, primary, secondary)
}

#[test]
fn traverses_in_secondary_then_primary_order() {
    let mut db = ContractDb::new();
    store(&mut db, 1, [0, 30]);
    store(&mut db, 2, [0, 20]);
    store(&mut db, 3, [0, 20]);
    store(&mut db, 4, [0, 10]);

    let end = db.db_idx256_end(CODE, SCOPE, TABLE);
    let mut secondary = [0u128; 2];
    let mut primary = 0u64;
    let mut it = db.db_idx256_lowerbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    let mut order = Vec::new();
    while it != end {
        let mut s = [0u128; 2];
        let _ = db.db_idx256_find_primary(CODE, SCOPE, TABLE, &mut s, primary);
        order.push((s, primary));
        it = db.db_idx256_next(it, &mut primary);
    }
    assert_eq!(
        order,
        vec![([0, 10], 4), ([0, 20], 2), ([0, 20], 3), ([0, 30], 1)]
    );
}

#[test]
fn high_word_dominates_ordering() {
    let mut db = ContractDb::new();
    // Primary 1 has the larger low word but a smaller high word, so it sorts
    // first — proving element [0] is the most significant.
    store(&mut db, 1, [1, u128::MAX]);
    store(&mut db, 2, [2, 0]);

    let end = db.db_idx256_end(CODE, SCOPE, TABLE);
    let mut secondary = [0u128; 2];
    let mut primary = 0u64;
    let mut it = db.db_idx256_lowerbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    let mut order = Vec::new();
    while it != end {
        order.push(primary);
        it = db.db_idx256_next(it, &mut primary);
    }
    assert_eq!(order, vec![1, 2]);
}

#[test]
fn find_secondary_returns_lowest_primary_for_that_key() {
    let mut db = ContractDb::new();
    let key = [7u128, 100];
    store(&mut db, 7, key);
    store(&mut db, 5, key);
    store(&mut db, 9, key);

    let mut primary = 0u64;
    let it = db.db_idx256_find_secondary(CODE, SCOPE, TABLE, key, &mut primary);
    assert!(it >= 0);
    assert_eq!(primary, 5, "ties resolve to the lowest primary key");

    let end = db.db_idx256_end(CODE, SCOPE, TABLE);
    let mut p = 0u64;
    assert_eq!(
        db.db_idx256_find_secondary(CODE, SCOPE, TABLE, [7, 999], &mut p),
        end
    );
}

#[test]
fn find_primary_reports_secondary() {
    let mut db = ContractDb::new();
    let key = [u128::MAX, 12345];
    store(&mut db, 42, key);
    let mut secondary = [0u128; 2];
    let it = db.db_idx256_find_primary(CODE, SCOPE, TABLE, &mut secondary, 42);
    assert!(it >= 0);
    assert_eq!(secondary, key);
}

#[test]
fn upperbound_skips_the_whole_secondary_key() {
    let mut db = ContractDb::new();
    store(&mut db, 1, [0, 10]);
    store(&mut db, 2, [0, 20]);
    store(&mut db, 3, [0, 20]);
    store(&mut db, 4, [0, 30]);

    let mut secondary = [0u128, 20];
    let mut primary = 0u64;
    let it = db.db_idx256_upperbound(CODE, SCOPE, TABLE, &mut secondary, &mut primary);
    assert!(it >= 0);
    assert_eq!((secondary, primary), ([0, 30], 4));
}

#[test]
fn previous_from_end_is_highest_secondary() {
    let mut db = ContractDb::new();
    store(&mut db, 1, [0, 10]);
    store(&mut db, 2, [5, 0]);
    store(&mut db, 3, [0, 25]);

    let end = db.db_idx256_end(CODE, SCOPE, TABLE);
    let mut primary = 0u64;
    let last = db.db_idx256_previous(end, &mut primary);
    assert!(last >= 0);
    assert_eq!(primary, 2, "[5, 0] is the highest key");
}
