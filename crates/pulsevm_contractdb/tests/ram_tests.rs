//! RAM billing: writes charge the row payer, removes refund, updates adjust for
//! size and move bytes on a payer change — the accounting is consensus state.

use pulsevm_contractdb::ContractDb;

const CODE: u64 = 1;
const SCOPE: u64 = 2;
const TABLE: u64 = 3;
const ALICE: u64 = 100;
const BOB: u64 = 200;

// Overheads mirrored from the crate (kept in sync with its consts).
const KV_OVERHEAD: i64 = 112;
const IDX64_OVERHEAD: i64 = 128;
const TABLE_OVERHEAD: i64 = 112;

#[test]
fn store_bills_payer_including_table_and_value() {
    let mut db = ContractDb::new();
    let _ = db.db_store_i64(CODE, SCOPE, TABLE, ALICE, 1, b"abcd");
    // First write into a new table: table overhead + row overhead + value size.
    assert_eq!(db.ram_usage(ALICE), TABLE_OVERHEAD + KV_OVERHEAD + 4);
}

#[test]
fn remove_refunds_the_row() {
    let mut db = ContractDb::new();
    db.db_store_i64(CODE, SCOPE, TABLE, ALICE, 1, b"abcd");
    let after_store = db.ram_usage(ALICE);
    let it = db.db_find_i64(CODE, SCOPE, TABLE, 1);
    db.db_remove_i64(it);
    // The row's bytes come back (the table overhead stays, as in EOS until GC).
    assert_eq!(db.ram_usage(ALICE), after_store - (KV_OVERHEAD + 4));
}

#[test]
fn update_adjusts_for_size() {
    let mut db = ContractDb::new();
    db.db_store_i64(CODE, SCOPE, TABLE, ALICE, 1, b"aa");
    let before = db.ram_usage(ALICE);
    let it = db.db_find_i64(CODE, SCOPE, TABLE, 1);
    db.db_update_i64(it, ALICE, b"aaaaaa"); // 2 -> 6 bytes
    assert_eq!(db.ram_usage(ALICE), before + 4);
}

#[test]
fn update_moves_bytes_on_payer_change() {
    let mut db = ContractDb::new();
    db.db_store_i64(CODE, SCOPE, TABLE, ALICE, 1, b"abcd");
    let alice_before = db.ram_usage(ALICE);
    let it = db.db_find_i64(CODE, SCOPE, TABLE, 1);
    db.db_update_i64(it, BOB, b"abcd"); // same size, new payer

    // Alice keeps only the table overhead; Bob now carries the row.
    assert_eq!(db.ram_usage(ALICE), alice_before - (KV_OVERHEAD + 4));
    assert_eq!(db.ram_usage(BOB), KV_OVERHEAD + 4);
}

#[test]
fn secondary_index_store_and_remove_bill() {
    let mut db = ContractDb::new();
    let it = db.db_idx64_store(CODE, SCOPE, TABLE, ALICE, 1, 500);
    assert_eq!(db.ram_usage(ALICE), TABLE_OVERHEAD + IDX64_OVERHEAD);
    db.db_idx64_remove(it);
    assert_eq!(db.ram_usage(ALICE), TABLE_OVERHEAD); // row refunded, table stays
}
