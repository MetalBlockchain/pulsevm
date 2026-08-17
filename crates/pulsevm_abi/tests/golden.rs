//! Validates `bin_to_json` against the committed C++ oracle: for every table
//! that the golden captured both raw (hex) and decoded (json), decode the raw
//! bytes ourselves and require an exact semantic match with the C++ JSON.

use std::{
    collections::HashMap,
    path::PathBuf,
};

use pulsevm_abi::Abi;
use serde_json::Value;

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pulsevm_database/tests/rpc_golden.json")
}

/// The (code, scope, table) triple keys both raw and json row captures.
type Key = (u64, u64, u64);

fn triple(rec: &Value) -> Key {
    (
        rec["code"].as_u64().unwrap(),
        rec["scope"].as_u64().unwrap(),
        rec["table"].as_u64().unwrap(),
    )
}

#[test]
fn bin_to_json_matches_cpp_oracle() {
    let raw = std::fs::read(golden_path()).expect("read rpc_golden.json");
    let records: Vec<Value> = serde_json::from_slice(&raw).expect("parse golden json");

    let mut abis: HashMap<u64, Abi> = HashMap::new();
    let mut raw_rows: HashMap<Key, Value> = HashMap::new();
    let mut json_rows: HashMap<Key, Value> = HashMap::new();

    for rec in &records {
        match rec["kind"].as_str() {
            Some("abi") => {
                let code = rec["code"].as_u64().unwrap();
                let bytes = hex::decode(rec["abi_hex"].as_str().unwrap()).expect("abi hex");
                let abi = Abi::from_bytes(&bytes)
                    .unwrap_or_else(|e| panic!("parse abi for code {code}: {e}"));
                abis.insert(code, abi);
            }
            Some("table_rows_raw") => {
                raw_rows.insert(triple(rec), rec.clone());
            }
            Some("table_rows_json") => {
                json_rows.insert(triple(rec), rec.clone());
            }
            _ => {}
        }
    }

    let mut checked_rows = 0usize;
    let mut checked_tables = 0usize;

    for (key, raw_rec) in &raw_rows {
        let Some(json_rec) = json_rows.get(key) else {
            continue;
        };
        let (code, _scope, table) = *key;

        let abi = abis
            .get(&code)
            .unwrap_or_else(|| panic!("no abi record for code {code}"));
        let ty = abi
            .table_row_type(table)
            .unwrap_or_else(|| panic!("no table type for code {code} table {table}"));

        let raw_out: Value =
            serde_json::from_str(raw_rec["output"].as_str().unwrap()).expect("raw output json");
        let json_out: Value =
            serde_json::from_str(json_rec["output"].as_str().unwrap()).expect("json output json");

        let raw_list = raw_out["rows"].as_array().expect("raw rows array");
        let json_list = json_out["rows"].as_array().expect("json rows array");
        assert_eq!(
            raw_list.len(),
            json_list.len(),
            "row count mismatch for code {code} table {table}"
        );
        if raw_list.is_empty() {
            continue;
        }
        checked_tables += 1;

        for (raw_row, json_row) in raw_list.iter().zip(json_list) {
            let hex_data = raw_row["data"].as_str().expect("row data hex");
            let bytes = hex::decode(hex_data).expect("decode row hex");

            let mut cursor: &[u8] = &bytes;
            let decoded = abi.bin_to_json(&ty, &mut cursor).unwrap_or_else(|e| {
                panic!(
                    "decode failed code {code} table {table} type {ty}\n  hex: {hex_data}\n  err: {e}"
                )
            });

            let expected = &json_row["data"];
            assert_eq!(
                &decoded, expected,
                "mismatch code {code} table {table} type {ty}\n  hex: {hex_data}\n  expected: {expected}\n  got:      {decoded}"
            );
            assert!(
                cursor.is_empty(),
                "unconsumed bytes ({} left) code {code} table {table} type {ty}\n  hex: {hex_data}",
                cursor.len()
            );
            checked_rows += 1;
        }
    }

    eprintln!("checked {checked_rows} rows across {checked_tables} (code,scope,table) captures");
    assert!(checked_rows > 0, "no rows were checked");
}
