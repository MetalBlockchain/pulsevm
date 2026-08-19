//! Validates the RPC formatters against the committed C++ `fc::json` golden.
//!
//! For the table-rows and currency endpoints the golden carries both the inputs
//! (raw row bytes) and the exact nodeos output, so those are checked end to end.
//! `table_by_scope` and `account_info` lack row-level inputs in the golden, so
//! they get shape/encoding unit tests here; the arena replay covers them fully.

use std::str::FromStr;

use pulsevm_abi::Abi;
use pulsevm_name::Name;
use pulsevm_rpc::*;
use serde_json::Value;

fn load_golden() -> Vec<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../pulsevm_database/tests/rpc_golden.json"
    );
    let text = std::fs::read_to_string(path).expect("read golden");
    serde_json::from_str(&text).expect("parse golden")
}

fn name(s: &str) -> u64 {
    Name::from_str(s).expect("name").as_u64()
}

/// Every contract ABI in the golden, keyed by contract account.
fn abis(golden: &[Value]) -> std::collections::HashMap<u64, Abi> {
    let mut m = std::collections::HashMap::new();
    for r in golden {
        if r["kind"] == "abi" {
            let code = r["code"].as_u64().unwrap();
            let bytes = hex::decode(r["abi_hex"].as_str().unwrap()).unwrap();
            m.insert(code, Abi::from_bytes(&bytes).expect("parse abi"));
        }
    }
    m
}

/// Parse a `table_rows_raw` output's rows into `TableRow`s (payer name -> u64,
/// data hex -> bytes).
fn parse_raw_rows(output: &Value) -> Vec<TableRow> {
    output["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| TableRow {
            payer: name(row["payer"].as_str().unwrap()),
            data: hex::decode(row["data"].as_str().unwrap()).unwrap(),
        })
        .collect()
}

fn output_value(record: &Value) -> Value {
    serde_json::from_str(record["output"].as_str().unwrap()).unwrap()
}

#[test]
fn table_rows_match_golden() {
    let golden = load_golden();
    let abis = abis(&golden);

    let mut tables_checked = 0usize;
    let mut rows_checked = 0usize;

    for raw in golden.iter().filter(|r| r["kind"] == "table_rows_raw") {
        let (code, scope, table) = (
            raw["code"].as_u64().unwrap(),
            raw["scope"].as_u64().unwrap(),
            raw["table"].as_u64().unwrap(),
        );

        // The paired json record for the same key; skip if there isn't one.
        let json_rec = golden.iter().find(|r| {
            r["kind"] == "table_rows_json"
                && r["code"].as_u64() == Some(code)
                && r["scope"].as_u64() == Some(scope)
                && r["table"].as_u64() == Some(table)
        });
        let Some(json_rec) = json_rec else { continue };

        let abi = abis.get(&code).expect("abi for code");
        let row_type = abi.table_row_type(table).expect("row type");
        let rows = parse_raw_rows(&output_value(raw));

        let raw_out = output_value(raw);
        let more = raw_out["more"].as_bool().unwrap();
        let next_key = raw_out["next_key"].as_str().unwrap();

        let got_raw =
            format_table_rows(false, Some(abi), &row_type, &rows, more, next_key, true).unwrap();
        assert_eq!(got_raw, raw_out, "raw rows for table {table}");

        let got_json =
            format_table_rows(true, Some(abi), &row_type, &rows, more, next_key, true).unwrap();
        assert_eq!(
            got_json,
            output_value(json_rec),
            "json rows for table {table}"
        );

        tables_checked += 1;
        rows_checked += rows.len();
    }

    assert!(tables_checked > 0, "no paired tables were checked");
    assert!(rows_checked > 0, "no rows were checked");
    // The golden pairs a raw+json record for every table it captures.
    assert_eq!(tables_checked, 26);
}

#[test]
fn table_rows_without_payer_are_bare_values() {
    let rows = [TableRow {
        payer: name("alice"),
        data: vec![0xde, 0xad],
    }];
    let got = format_table_rows(false, None, "", &rows, true, "7", false).unwrap();
    assert_eq!(got["rows"], serde_json::json!(["dead"]));
    assert_eq!(got["more"], true);
    assert_eq!(got["next_key"], "7");
}

#[test]
fn currency_balance_matches_golden() {
    let golden = load_golden();
    let accounts_table = name("accounts");

    let mut cases = 0usize;
    for rec in golden.iter().filter(|r| r["kind"] == "currency_balance") {
        let code = rec["code"].as_u64().unwrap();
        let account = rec["account"].as_u64().unwrap();

        let raw = golden
            .iter()
            .find(|r| {
                r["kind"] == "table_rows_raw"
                    && r["code"].as_u64() == Some(code)
                    && r["scope"].as_u64() == Some(account)
                    && r["table"].as_u64() == Some(accounts_table)
            })
            .expect("matching accounts raw record");

        let rows: Vec<Vec<u8>> = output_value(raw)["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| hex::decode(row["data"].as_str().unwrap()).unwrap())
            .collect();

        let got = format_currency_balance(&rows).unwrap();
        assert_eq!(got, output_value(rec), "balance for account {account}");
        cases += 1;
    }

    assert_eq!(cases, 6, "expected all six balance cases checked");
}

#[test]
fn currency_stats_matches_golden() {
    let golden = load_golden();
    let stat_table = name("stat");

    let stat_rows: Vec<Vec<u8>> = golden
        .iter()
        .filter(|r| r["kind"] == "table_rows_raw" && r["table"].as_u64() == Some(stat_table))
        .flat_map(|r| {
            output_value(r)["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| hex::decode(row["data"].as_str().unwrap()).unwrap())
                .collect::<Vec<_>>()
        })
        .collect();

    let mut cases = 0usize;
    for rec in golden.iter().filter(|r| r["kind"] == "currency_stats") {
        let symbol = rec["symbol"].as_str().unwrap();

        // Find the stat row whose formatted output is keyed by this symbol.
        let formatted = stat_rows
            .iter()
            .map(|bytes| format_currency_stats(std::slice::from_ref(bytes)).unwrap())
            .find(|v| v.as_object().unwrap().contains_key(symbol))
            .expect("stat row for symbol");

        assert_eq!(formatted, output_value(rec), "stats for {symbol}");
        cases += 1;
    }

    assert_eq!(cases, 2, "expected both stat cases checked");
}

#[test]
fn table_by_scope_shape() {
    let rows = vec![
        ScopeRow {
            code: name("oracles"),
            scope: name("oracles"),
            table: name("data"),
            payer: name("oracles"),
            count: 24,
        },
        ScopeRow {
            code: name("pulse.token"),
            scope: name("pulse"),
            table: name("accounts"),
            payer: name("pulse"),
            count: 2,
        },
    ];

    let got = format_table_by_scope(&rows, "pulse");
    let expected = serde_json::json!({
        "rows": [
            {
                "code": "oracles",
                "scope": "oracles",
                "table": "data",
                "payer": "oracles",
                "count": 24
            },
            {
                "code": "pulse.token",
                "scope": "pulse",
                "table": "accounts",
                "payer": "pulse",
                "count": 2
            }
        ],
        "more": "pulse"
    });
    assert_eq!(got, expected);

    // Exhausted listings carry an empty `more`.
    let empty = format_table_by_scope(&[], "");
    assert_eq!(empty, serde_json::json!({ "rows": [], "more": "" }));
}

#[test]
fn account_info_shape() {
    // Modelled on the golden's `pulse` account: privileged, unlimited (-1)
    // quotas, an active+owner permission each holding one key, a decoded
    // voter_info and the resource rows left null.
    let key = "PUB_K1_7VmChdZ1C2Bi7YQa6WoydpBgUNhXnQT7E15h5CQFTKwFBm5vK3";
    let auth = || Authority {
        threshold: 1,
        keys: vec![KeyWeight {
            key: key.to_string(),
            weight: 1,
        }],
        accounts: vec![],
        waits: vec![],
    };
    let unlimited = || ResourceLimit {
        used: -1,
        available: -1,
        max: -1,
        last_usage_update_time: 1_785_925_227_000_000,
        current_used: -1,
    };

    let voter_info = serde_json::json!({
        "owner": "pulse",
        "proxy": "",
        "producers": [],
        "staked": 1400000,
        "last_vote_weight": "0.00000000000000000",
        "proxied_vote_weight": "0.00000000000000000",
        "is_proxy": 0,
        "flags1": 0,
        "reserved2": 0,
        "reserved3": "0 "
    });

    let info = AccountInfo {
        account_name: name("pulse"),
        head_block_num: 1697,
        head_block_time: 1_785_925_227_000_000,
        privileged: true,
        last_code_update: 1_785_922_714_000_000,
        created: 1_785_110_400_000_000,
        core_liquid_balance: Some("999999160.0000 SYS".to_string()),
        ram_quota: -1,
        net_weight: -1,
        cpu_weight: -1,
        net_limit: unlimited(),
        cpu_limit: unlimited(),
        ram_usage: 817593,
        permissions: vec![
            Permission {
                perm_name: name("active"),
                parent: name("owner"),
                required_auth: auth(),
                linked_actions: vec![LinkedAction {
                    account: name("pulse.token"),
                    action: Some(name("transfer")),
                }],
            },
            Permission {
                perm_name: name("owner"),
                parent: 0,
                required_auth: auth(),
                linked_actions: vec![],
            },
        ],
        total_resources: Value::Null,
        self_delegated_bandwidth: Value::Null,
        refund_request: Value::Null,
        voter_info: voter_info.clone(),
        rex_info: Value::Null,
        subjective_cpu_bill_limit: ResourceLimit {
            used: 0,
            available: 0,
            max: 0,
            last_usage_update_time: 946_684_800_000_000,
            current_used: 0,
        },
        eosio_any_linked_actions: vec![LinkedAction {
            account: name("pulse"),
            action: None,
        }],
    };

    let unlimited_json = serde_json::json!({
        "used": -1,
        "available": -1,
        "max": -1,
        "last_usage_update_time": "2026-08-05T10:20:27.000",
        "current_used": -1
    });
    let perm = |name_: &str, parent: &str, linked_actions: Value| {
        serde_json::json!({
            "perm_name": name_,
            "parent": parent,
            "required_auth": {
                "threshold": 1,
                "keys": [{ "key": key, "weight": 1 }],
                "accounts": [],
                "waits": []
            },
            "linked_actions": linked_actions
        })
    };

    let expected = serde_json::json!({
        "account_name": "pulse",
        "head_block_num": 1697,
        "head_block_time": "2026-08-05T10:20:27.000",
        "privileged": true,
        "last_code_update": "2026-08-05T09:38:34.000",
        "created": "2026-07-27T00:00:00.000",
        "core_liquid_balance": "999999160.0000 SYS",
        "ram_quota": -1,
        "net_weight": -1,
        "cpu_weight": -1,
        "net_limit": unlimited_json,
        "cpu_limit": unlimited_json,
        "ram_usage": 817593,
        "permissions": [
            perm("active", "owner", serde_json::json!([{
                "account": "pulse.token", "action": "transfer"
            }])),
            perm("owner", "", serde_json::json!([]))
        ],
        "total_resources": Value::Null,
        "self_delegated_bandwidth": Value::Null,
        "refund_request": Value::Null,
        "voter_info": voter_info,
        "rex_info": Value::Null,
        "subjective_cpu_bill_limit": {
            "used": 0,
            "available": 0,
            "max": 0,
            "last_usage_update_time": "2000-01-01T00:00:00.000",
            "current_used": 0
        },
        "eosio_any_linked_actions": [{ "account": "pulse" }]
    });

    assert_eq!(format_account_info(&info), expected);

    // fc omits an empty optional core balance; it does not emit JSON null.
    let mut without_balance = info;
    without_balance.core_liquid_balance = None;
    without_balance.net_limit.max = i32::MAX as i64 + 1;
    let formatted = format_account_info(&without_balance);
    assert!(
        !formatted
            .as_object()
            .unwrap()
            .contains_key("core_liquid_balance")
    );
    assert_eq!(formatted["net_limit"]["max"], "2147483648");
}
