//! The consensus-observable behaviour of the primary i64 iterator API: handle
//! encoding, end iterators, ordered traversal, boundary lookups, and table
//! isolation.

use pulsevm_contractdb::ContractDb;

const CODE: u64 = 1;
const SCOPE: u64 = 2;
const TABLE: u64 = 3;

fn store(db: &mut ContractDb, key: u64, val: &[u8]) -> i32 {
    db.db_store_i64(CODE, SCOPE, TABLE, CODE, key, val)
}

#[test]
fn store_and_get_round_trips() {
    let mut db = ContractDb::new();
    let it = store(&mut db, 10, b"hello");
    assert!(it >= 0, "a stored row gets a non-negative handle");
    assert_eq!(db.db_get_i64(it), b"hello");
}

#[test]
fn find_missing_returns_end_not_row() {
    let mut db = ContractDb::new();
    store(&mut db, 10, b"a");
    let end = db.db_end_i64(CODE, SCOPE, TABLE);
    assert!(end <= -2, "end iterator is a negative table marker");
    assert_eq!(db.db_find_i64(CODE, SCOPE, TABLE, 999), end);
    // A wholly unknown table is -1, distinct from a table's end.
    assert_eq!(db.db_find_i64(9, 9, 9, 1), -1);
}

#[test]
fn forward_traversal_visits_rows_in_key_order_then_end() {
    let mut db = ContractDb::new();
    for k in [30u64, 10, 20] {
        store(&mut db, k, format!("v{k}").as_bytes());
    }
    let end = db.db_end_i64(CODE, SCOPE, TABLE);

    // lower_bound(0) is the first row; walk with next until end.
    let mut it = db.db_lowerbound_i64(CODE, SCOPE, TABLE, 0);
    let mut seen = Vec::new();
    let mut primary = 0u64;
    while it != end {
        seen.push(db.db_get_i64(it));
        it = db.db_next_i64(it, &mut primary);
    }
    assert_eq!(
        seen,
        vec![b"v10".to_vec(), b"v20".to_vec(), b"v30".to_vec()]
    );
    // next on the end iterator stays put.
    assert_eq!(db.db_next_i64(end, &mut primary), end);
}

#[test]
fn previous_from_end_is_last_row() {
    let mut db = ContractDb::new();
    for k in [10u64, 20, 30] {
        store(&mut db, k, format!("v{k}").as_bytes());
    }
    let end = db.db_end_i64(CODE, SCOPE, TABLE);
    let mut primary = 0u64;
    let last = db.db_previous_i64(end, &mut primary);
    assert_eq!(primary, 30);
    assert_eq!(db.db_get_i64(last), b"v30");
    // Walking back to before the first row yields -1.
    let mut it = db.db_find_i64(CODE, SCOPE, TABLE, 10);
    assert_eq!(db.db_previous_i64(it, &mut primary), -1);
    it = db.db_next_i64(it, &mut primary);
    assert_eq!(primary, 20);
    let _ = it;
}

#[test]
fn lower_and_upper_bound_boundaries() {
    let mut db = ContractDb::new();
    for k in [10u64, 20, 30] {
        store(&mut db, k, format!("v{k}").as_bytes());
    }
    // lower_bound is inclusive, upper_bound exclusive.
    let lb = db.db_lowerbound_i64(CODE, SCOPE, TABLE, 20);
    assert_eq!(db.db_get_i64(lb), b"v20");
    let ub = db.db_upperbound_i64(CODE, SCOPE, TABLE, 20);
    assert_eq!(db.db_get_i64(ub), b"v30");
    // Past the end, both give the end iterator.
    let end = db.db_end_i64(CODE, SCOPE, TABLE);
    assert_eq!(db.db_lowerbound_i64(CODE, SCOPE, TABLE, 31), end);
    assert_eq!(db.db_upperbound_i64(CODE, SCOPE, TABLE, 30), end);
}

#[test]
fn update_and_remove() {
    let mut db = ContractDb::new();
    let it = store(&mut db, 10, b"before");
    db.db_update_i64(it, CODE, b"after");
    let found = db.db_find_i64(CODE, SCOPE, TABLE, 10);
    assert_eq!(db.db_get_i64(found), b"after");

    let found = db.db_find_i64(CODE, SCOPE, TABLE, 10);
    db.db_remove_i64(found);
    let end = db.db_end_i64(CODE, SCOPE, TABLE);
    assert_eq!(db.db_find_i64(CODE, SCOPE, TABLE, 10), end);
}

#[test]
fn tables_are_isolated_by_scope() {
    let mut db = ContractDb::new();
    db.db_store_i64(CODE, 100, TABLE, CODE, 1, b"in-100");
    db.db_store_i64(CODE, 200, TABLE, CODE, 1, b"in-200");

    // Same primary key, different scope -> different rows, and next stays within
    // the scope's table.
    let it = db.db_find_i64(CODE, 100, TABLE, 1);
    assert_eq!(db.db_get_i64(it), b"in-100");
    let mut primary = 0u64;
    let end_100 = db.db_end_i64(CODE, 100, TABLE);
    assert_eq!(db.db_next_i64(it, &mut primary), end_100);
}
