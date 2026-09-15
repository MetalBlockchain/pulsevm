use pulsevm_billable_size::billable_size_v;
use pulsevm_database::{
    Database,
    Float128,
    Index64Object,
    Index128Object,
    Index256Object,
    IndexDoubleObject,
    IndexLongDoubleObject,
    KeyValueObject,
    TableObject,
    U256,
};
use pulsevm_name::Name;
use std::str::FromStr;
use tempfile::TempDir;

#[test]
fn empty_database_has_no_contract_table_ram() {
    let database = Database::default();
    assert!(database.contract_table_ram_billing().unwrap().is_empty());
}

#[test]
fn attributes_every_contract_object_to_its_table_and_payer() {
    let database = Database::default();
    let (code, scope, table) = (10, 20, 30);

    database
        .create_key_value_object_standalone(code, scope, table, 40, 1, b"old")
        .unwrap();
    // The table metadata remains billed to its creation payer while the row
    // itself moves to its new payer and value size.
    database
        .update_key_value_object_standalone(code, scope, table, 1, 41, b"abcdef")
        .unwrap();
    database
        .create_index64_object_standalone(code, scope, table, 40, 1, 7)
        .unwrap();
    database
        .create_index128_object_standalone(code, scope, table, 41, 1, 8)
        .unwrap();
    database
        .create_index256_object_standalone(code, scope, table, 42, 1, U256 { value: [9; 32] })
        .unwrap();
    database
        .create_idx_double_object_standalone(code, scope, table, 42, 1, 1.5f64.to_bits())
        .unwrap();
    database
        .create_idx_long_double_object_standalone(
            code,
            scope,
            table,
            42,
            1,
            Float128 { lo: 1, hi: 0 },
        )
        .unwrap();
    database
        .create_key_value_object_standalone(code, 21, table, 41, 2, b"xyz")
        .unwrap();

    let rows = database.contract_table_ram_billing().unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| (row.code, row.scope, row.table, row.payer))
            .collect::<Vec<_>>(),
        vec![
            (code, scope, table, 40),
            (code, scope, table, 41),
            (code, scope, table, 42),
            (code, 21, table, 41),
        ]
    );

    let table_payer = &rows[0];
    assert_eq!(
        table_payer.table_overhead_bytes,
        billable_size_v::<TableObject>() as i64
    );
    assert_eq!(table_payer.primary_rows, 0);
    assert_eq!(table_payer.index64_rows, 1);
    assert_eq!(
        table_payer.total_bytes().unwrap(),
        (billable_size_v::<TableObject>() + billable_size_v::<Index64Object>()) as i64
    );

    let primary_payer = &rows[1];
    assert_eq!(primary_payer.table_overhead_bytes, 0);
    assert_eq!(primary_payer.primary_rows, 1);
    assert_eq!(primary_payer.primary_value_bytes, 6);
    assert_eq!(
        primary_payer.primary_bytes,
        billable_size_v::<KeyValueObject>() as i64 + 6
    );
    assert_eq!(primary_payer.index128_rows, 1);
    assert_eq!(
        primary_payer.total_bytes().unwrap(),
        (billable_size_v::<KeyValueObject>() + billable_size_v::<Index128Object>()) as i64 + 6
    );

    let secondary_payer = &rows[2];
    assert_eq!(secondary_payer.index256_rows, 1);
    assert_eq!(secondary_payer.index_double_rows, 1);
    assert_eq!(secondary_payer.index_long_double_rows, 1);
    assert_eq!(
        secondary_payer.total_bytes().unwrap(),
        (billable_size_v::<Index256Object>()
            + billable_size_v::<IndexDoubleObject>()
            + billable_size_v::<IndexLongDoubleObject>()) as i64
    );

    let second_table = &rows[3];
    assert_eq!(
        second_table.total_bytes().unwrap(),
        (billable_size_v::<TableObject>() + billable_size_v::<KeyValueObject>()) as i64 + 3
    );
}

#[test]
fn per_table_totals_reconcile_with_account_contract_categories() {
    let database = Database::default();
    database
        .create_key_value_object_standalone(10, 20, 30, 40, 1, b"abc")
        .unwrap();
    database
        .create_index64_object_standalone(10, 20, 30, 41, 1, 7)
        .unwrap();
    database
        .create_key_value_object_standalone(11, 22, 33, 41, 2, b"hello")
        .unwrap();

    let rows = database.contract_table_ram_billing().unwrap();
    for payer in [40, 41] {
        assert_eq!(
            database
                .contract_table_ram_billing_for_payer(payer)
                .unwrap(),
            rows.iter()
                .filter(|row| row.payer == payer)
                .cloned()
                .collect::<Vec<_>>()
        );
        let expected = database.account_ram_billing_breakdown(payer).unwrap();
        let payer_rows: Vec<_> = rows.iter().filter(|row| row.payer == payer).collect();
        assert_eq!(
            payer_rows
                .iter()
                .map(|row| row.table_overhead_bytes)
                .sum::<i64>(),
            expected.contract_tables
        );
        assert_eq!(
            payer_rows.iter().map(|row| row.primary_bytes).sum::<i64>(),
            expected.contract_kv
        );
        assert_eq!(
            payer_rows.iter().map(|row| row.index64_bytes).sum::<i64>(),
            expected.contract_idx64
        );
    }
}

#[test]
fn payer_profile_survives_checkpoint_and_reopen() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().to_str().unwrap();
    let payer = Name::from_str("alice").unwrap().as_u64();

    let database = Database::new(path, 0).unwrap();
    database
        .set_system_account(Name::from_str("pulse").unwrap())
        .unwrap();
    database
        .create_key_value_object_standalone(10, 20, 30, payer, 1, b"persisted")
        .unwrap();
    database
        .create_index64_object_standalone(10, 20, 30, payer, 1, 7)
        .unwrap();
    let before = database.account_ram_billing_profile(payer).unwrap();
    database.close().unwrap();
    drop(database);

    let reopened = Database::new(path, 0).unwrap();
    let after = reopened.account_ram_billing_profile(payer).unwrap();
    assert_eq!(after, before);
    assert_eq!(after.tables.len(), 1);
    assert_eq!(after.tables[0].primary_value_bytes, 9);
}
