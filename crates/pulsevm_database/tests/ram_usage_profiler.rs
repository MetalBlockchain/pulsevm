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

#[test]
fn continuous_monitor_publishes_only_committed_ram_changes() {
    let mut database = Database::default();
    database.enable_ram_usage_monitor(8).unwrap();

    database.arena_start_undo_session();
    database
        .create_key_value_object_standalone(10, 20, 30, 40, 1, b"abc")
        .unwrap();
    database
        .create_index64_object_standalone(10, 20, 30, 40, 1, 7)
        .unwrap();
    database
        .create_index128_object_standalone(10, 20, 30, 40, 1, 8)
        .unwrap();
    database
        .create_index256_object_standalone(10, 20, 30, 40, 1, U256 { value: [9; 32] })
        .unwrap();
    database
        .create_idx_double_object_standalone(10, 20, 30, 40, 1, 1.5f64.to_bits())
        .unwrap();
    database
        .create_idx_long_double_object_standalone(10, 20, 30, 40, 1, Float128 { lo: 1, hi: 0 })
        .unwrap();

    let speculative = database.ram_usage_monitor_snapshot().unwrap();
    assert!(speculative.series.is_empty());
    assert_eq!(speculative.accepted_blocks_total, 0);

    database.commit(1).unwrap();
    let accepted = database.ram_usage_monitor_snapshot().unwrap();
    assert_eq!(accepted.revision, 1);
    assert_eq!(accepted.accepted_blocks_total, 1);
    assert_eq!(accepted.series.len(), 1);
    let expected = billable_size_v::<TableObject>()
        + billable_size_v::<KeyValueObject>()
        + 3
        + billable_size_v::<Index64Object>()
        + billable_size_v::<Index128Object>()
        + billable_size_v::<Index256Object>()
        + billable_size_v::<IndexDoubleObject>()
        + billable_size_v::<IndexLongDoubleObject>();
    assert_eq!(accepted.series[0].current_bytes, expected as i64);
    assert_eq!(accepted.series[0].allocated_bytes_total, expected);
    assert_eq!(accepted.series[0].freed_bytes_total, 0);
    assert_eq!(accepted.series[0].operations_total, 7);

    database.arena_start_undo_session();
    database
        .update_key_value_object_standalone(10, 20, 30, 1, 41, b"rejected")
        .unwrap();
    database
        .remove_index64_object_standalone(10, 20, 30, 1)
        .unwrap();
    database.arena_undo();
    assert_eq!(database.ram_usage_monitor_snapshot().unwrap(), accepted);
}

#[test]
fn continuous_monitor_tracks_nested_sessions_and_partial_commit() {
    let mut database = Database::default();
    database.enable_ram_usage_monitor(8).unwrap();

    database.arena_start_undo_session();
    database
        .create_key_value_object_standalone(10, 20, 30, 40, 1, b"outer")
        .unwrap();
    database.arena_start_undo_session();
    database
        .create_key_value_object_standalone(10, 20, 30, 40, 2, b"inner")
        .unwrap();
    database.arena_squash();
    assert!(
        database
            .ram_usage_monitor_snapshot()
            .unwrap()
            .series
            .is_empty()
    );
    database.commit(1).unwrap();
    let accepted = database.ram_usage_monitor_snapshot().unwrap();
    assert_eq!(accepted.accepted_blocks_total, 1);
    assert_eq!(accepted.series.len(), 1);

    database.arena_start_undo_session();
    database
        .create_key_value_object_standalone(11, 21, 31, 41, 1, b"pending")
        .unwrap();
    database.arena_undo();
    assert_eq!(database.ram_usage_monitor_snapshot().unwrap(), accepted);

    database.arena_start_undo_session();
    database
        .create_key_value_object_standalone(12, 22, 32, 42, 1, b"accepted-front")
        .unwrap();
    database.arena_start_undo_session();
    database
        .create_key_value_object_standalone(13, 23, 33, 43, 1, b"pending-back")
        .unwrap();
    database.commit(2).unwrap();
    let partial = database.ram_usage_monitor_snapshot().unwrap();
    assert_eq!(partial.revision, 2);
    assert_eq!(partial.accepted_blocks_total, 2);
    assert_eq!(partial.series.len(), 2);
    assert!(partial.series.iter().any(|series| series.key.code == 12));
    assert!(!partial.series.iter().any(|series| series.key.code == 13));
    database.arena_undo();
    assert_eq!(database.ram_usage_monitor_snapshot().unwrap(), partial);
}

#[test]
fn continuous_monitor_bounds_labels_and_aggregates_overflow_exactly() {
    let mut database = Database::default();
    database.enable_ram_usage_monitor(1).unwrap();
    database.arena_start_undo_session();
    database
        .create_key_value_object_standalone(10, 20, 30, 40, 1, b"tracked")
        .unwrap();
    database
        .create_key_value_object_standalone(11, 21, 31, 41, 1, b"overflow")
        .unwrap();
    database.commit(1).unwrap();

    let snapshot = database.ram_usage_monitor_snapshot().unwrap();
    assert_eq!(snapshot.series.len(), 1);
    assert_eq!(snapshot.max_series, 1);
    assert_eq!(snapshot.overflow_events_total, 2);
    assert_eq!(
        snapshot.overflow.current_bytes,
        (billable_size_v::<TableObject>() + billable_size_v::<KeyValueObject>() + 8) as i64
    );
}

#[test]
fn enabling_continuous_monitor_does_not_change_consensus_state() {
    fn apply(database: &mut Database) {
        database.arena_start_undo_session();
        database
            .create_key_value_object_standalone(10, 20, 30, 40, 1, b"same")
            .unwrap();
        database
            .create_index64_object_standalone(10, 20, 30, 40, 1, 7)
            .unwrap();
        database.commit(1).unwrap();
    }

    let mut plain = Database::default();
    let mut monitored = Database::default();
    monitored.enable_ram_usage_monitor(8).unwrap();
    apply(&mut plain);
    apply(&mut monitored);
    assert_eq!(plain.arena_state_root(), monitored.arena_state_root());
}

#[test]
fn continuous_monitor_reseeds_after_live_state_restore() {
    let source_dir = TempDir::new().unwrap();
    let mut source = Database::new(source_dir.path().to_str().unwrap(), 0).unwrap();
    source
        .create_key_value_object_standalone(10, 20, 30, 40, 1, b"source")
        .unwrap();
    source.set_revision(7).unwrap();
    let source_root = source.arena_state_root().unwrap();
    let checkpoint = source.snapshot_bytes().unwrap();

    let target_dir = TempDir::new().unwrap();
    let target = Database::new(target_dir.path().to_str().unwrap(), 0).unwrap();
    target
        .create_key_value_object_standalone(11, 21, 31, 41, 1, b"old-target")
        .unwrap();
    target.enable_ram_usage_monitor(8).unwrap();
    assert_eq!(target.ram_usage_monitor_snapshot().unwrap().revision, 0);

    target
        .restore_from_bytes(&checkpoint, &source_root)
        .unwrap();
    let snapshot = target.ram_usage_monitor_snapshot().unwrap();
    assert_eq!(snapshot.revision, 7);
    assert_eq!(snapshot.series.len(), 1);
    assert_eq!(snapshot.series[0].key.code, 10);
    assert_eq!(snapshot.series[0].allocated_bytes_total, 0);
    assert_eq!(snapshot.accepted_blocks_total, 0);
}
