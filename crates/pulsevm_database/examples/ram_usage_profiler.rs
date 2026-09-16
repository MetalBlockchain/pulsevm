//! Rank contract-table RAM usage in an Arena checkpoint.

use std::{
    cmp::Ordering,
    env,
    fs,
    io,
    path::Path,
    str::FromStr,
    time::{
        Instant,
        UNIX_EPOCH,
    },
};

use pulsevm_database::{
    AccountRamBillingBreakdown,
    ContractTableRamBilling,
    Database,
};
use pulsevm_name::Name;
use serde_json::{
    Value,
    json,
};

struct Options {
    arena_dir: String,
    payer: Option<Name>,
    limit: Option<usize>,
    json: bool,
}

fn usage(program: &str) -> String {
    format!("Usage: {program} <arena-dir> [--payer <account>] [--limit <rows> | --all] [--json]")
}

fn parse_options() -> Result<Options, String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "ram_usage_profiler".into());
    let Some(arena_dir) = args.next() else {
        return Err(usage(&program));
    };
    if arena_dir == "-h" || arena_dir == "--help" {
        println!("{}", usage(&program));
        std::process::exit(0);
    }

    let mut payer = None;
    let mut limit = Some(25usize);
    let mut json = false;
    let mut args = args.peekable();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--payer" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--payer requires an account name".to_string())?;
                payer = Some(
                    Name::from_str(&value)
                        .map_err(|error| format!("invalid payer {value:?}: {error}"))?,
                );
            }
            "--limit" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--limit requires a row count".to_string())?;
                let parsed = value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid limit {value:?}: {error}"))?;
                if parsed == 0 {
                    return Err("--limit must be greater than zero; use --all for every row".into());
                }
                limit = Some(parsed);
            }
            "--all" => limit = None,
            "--json" => json = true,
            "-h" | "--help" => {
                println!("{}", usage(&program));
                std::process::exit(0);
            }
            _ => {
                return Err(format!(
                    "unknown argument {argument:?}\n{}",
                    usage(&program)
                ));
            }
        }
    }
    Ok(Options {
        arena_dir,
        payer,
        limit,
        json,
    })
}

fn breakdown_json(billing: &AccountRamBillingBreakdown) -> Value {
    json!({
        "account": billing.account,
        "abi": billing.abi,
        "code": billing.code,
        "permissions": billing.permissions,
        "permission_links": billing.permission_links,
        "contract_tables": billing.contract_tables,
        "contract_kv": billing.contract_kv,
        "contract_idx64": billing.contract_idx64,
        "contract_idx128": billing.contract_idx128,
        "contract_idx256": billing.contract_idx256,
        "contract_idx_double": billing.contract_idx_double,
        "contract_idx_long_double": billing.contract_idx_long_double,
        "deferred": billing.deferred,
    })
}

fn table_json(row: &ContractTableRamBilling, total_bytes: i64) -> Value {
    json!({
        "code": Name::new(row.code).to_string(),
        "scope": Name::new(row.scope).to_string(),
        "table": Name::new(row.table).to_string(),
        "payer": Name::new(row.payer).to_string(),
        "total_bytes": total_bytes,
        "table_overhead_bytes": row.table_overhead_bytes,
        "primary": {
            "rows": row.primary_rows,
            "value_bytes": row.primary_value_bytes,
            "billed_bytes": row.primary_bytes,
        },
        "index64": { "rows": row.index64_rows, "billed_bytes": row.index64_bytes },
        "index128": { "rows": row.index128_rows, "billed_bytes": row.index128_bytes },
        "index256": { "rows": row.index256_rows, "billed_bytes": row.index256_bytes },
        "index_double": {
            "rows": row.index_double_rows,
            "billed_bytes": row.index_double_bytes,
        },
        "index_long_double": {
            "rows": row.index_long_double_rows,
            "billed_bytes": row.index_long_double_bytes,
        },
    })
}

fn compare_table_rank(
    (left, left_total): &(ContractTableRamBilling, i64),
    (right, right_total): &(ContractTableRamBilling, i64),
) -> Ordering {
    right_total.cmp(left_total).then_with(|| {
        (left.code, left.scope, left.table, left.payer).cmp(&(
            right.code,
            right.scope,
            right.table,
            right.payer,
        ))
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_options().map_err(io::Error::other)?;
    let checkpoint_path = Path::new(&options.arena_dir).join("arena_state.bin");
    let checkpoint_metadata = fs::metadata(&checkpoint_path).map_err(|error| {
        io::Error::other(format!(
            "cannot read Arena checkpoint {}: {error}",
            checkpoint_path.display()
        ))
    })?;
    let checkpoint_modified_unix_ms = checkpoint_metadata
        .modified()?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("checkpoint modification time predates unix epoch"))?
        .as_millis();
    let load_started = Instant::now();
    let database = Database::new(&options.arena_dir, 0).map_err(io::Error::other)?;
    let load_ms = load_started.elapsed().as_millis();
    let payer = options.payer.map(|name| name.as_u64());

    let scan_started = Instant::now();
    let (billing, account_billing) = match payer {
        Some(payer) => {
            let profile = database.account_ram_billing_profile(payer)?;
            (profile.tables, Some(profile.account))
        }
        None => (database.contract_table_ram_billing()?, None),
    };
    let scan_ms = scan_started.elapsed().as_millis();
    let mut rows = billing
        .into_iter()
        .map(|row| {
            let total = row.total_bytes()?;
            Ok((row, total))
        })
        .collect::<Result<Vec<_>, pulsevm_error::ChainError>>()?;
    let matched_entries = rows.len();
    let matched_bytes = rows.iter().try_fold(0i64, |total, (_, bytes)| {
        total
            .checked_add(*bytes)
            .ok_or_else(|| io::Error::other("RAM total overflow"))
    })?;
    if let Some(limit) = options.limit
        && rows.len() > limit
    {
        rows.select_nth_unstable_by(limit, compare_table_rank);
        rows.truncate(limit);
    }
    rows.sort_unstable_by(compare_table_rank);
    let shown_bytes = rows.iter().try_fold(0i64, |total, (_, bytes)| {
        total
            .checked_add(*bytes)
            .ok_or_else(|| io::Error::other("RAM total overflow"))
    })?;

    let account_summary = if let (Some(payer), Some(billing)) = (payer, account_billing) {
        let represented = billing.total()?;
        let stored = database
            .arena_account_ram_usage(payer)
            .map(i64::try_from)
            .transpose()
            .map_err(|_| io::Error::other("stored RAM usage exceeds i64"))?;
        Some((billing, represented, stored))
    } else {
        None
    };

    if options.json {
        let account = account_summary
            .as_ref()
            .map(|(billing, represented, stored)| {
                json!({
                    "payer": Name::new(payer.expect("summary requires payer")).to_string(),
                    "stored_bytes": stored,
                    "represented_bytes": represented,
                    "residual_bytes": stored.map(|stored| stored - represented),
                    "categories": breakdown_json(billing),
                })
            });
        let tables: Vec<_> = rows
            .iter()
            .map(|(row, total)| table_json(row, *total))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "revision": database.revision(),
                "checkpoint": {
                    "path": checkpoint_path,
                    "bytes": checkpoint_metadata.len(),
                    "modified_unix_ms": checkpoint_modified_unix_ms,
                    "load_ms": load_ms,
                    "scan_ms": scan_ms,
                },
                "account": account,
                "matched_entries": matched_entries,
                "matched_bytes": matched_bytes,
                "shown_entries": rows.len(),
                "shown_bytes": shown_bytes,
                "tables": tables,
            }))?
        );
        return Ok(());
    }

    println!(
        "revision={} checkpoint_bytes={} checkpoint_modified_unix_ms={} load_ms={} scan_ms={} matched_entries={} matched_bytes={} shown_entries={} shown_bytes={}",
        database.revision(),
        checkpoint_metadata.len(),
        checkpoint_modified_unix_ms,
        load_ms,
        scan_ms,
        matched_entries,
        matched_bytes,
        rows.len(),
        shown_bytes,
    );
    if let Some((billing, represented, stored)) = account_summary {
        let stored_display = stored
            .map(|value| value.to_string())
            .unwrap_or_else(|| "missing".into());
        let residual_display = stored
            .map(|stored| (stored - represented).to_string())
            .unwrap_or_else(|| "unknown".into());
        println!(
            "payer={} stored_bytes={} represented_bytes={} residual_bytes={} account={} abi={} code={} permissions={} permission_links={} contract_tables={} contract_kv={} idx64={} idx128={} idx256={} idx_double={} idx_long_double={} deferred={}",
            Name::new(payer.expect("summary requires payer")),
            stored_display,
            represented,
            residual_display,
            billing.account,
            billing.abi,
            billing.code,
            billing.permissions,
            billing.permission_links,
            billing.contract_tables,
            billing.contract_kv,
            billing.contract_idx64,
            billing.contract_idx128,
            billing.contract_idx256,
            billing.contract_idx_double,
            billing.contract_idx_long_double,
            billing.deferred,
        );
    }
    for (row, total) in rows {
        println!(
            "bytes={} code={} scope={} table={} payer={} table_overhead={} primary_bytes={} primary_rows={} primary_value_bytes={} idx64_bytes={} idx64_rows={} idx128_bytes={} idx128_rows={} idx256_bytes={} idx256_rows={} idx_double_bytes={} idx_double_rows={} idx_long_double_bytes={} idx_long_double_rows={}",
            total,
            Name::new(row.code),
            Name::new(row.scope),
            Name::new(row.table),
            Name::new(row.payer),
            row.table_overhead_bytes,
            row.primary_bytes,
            row.primary_rows,
            row.primary_value_bytes,
            row.index64_bytes,
            row.index64_rows,
            row.index128_bytes,
            row.index128_rows,
            row.index256_bytes,
            row.index256_rows,
            row.index_double_bytes,
            row.index_double_rows,
            row.index_long_double_bytes,
            row.index_long_double_rows,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(code: u64, bytes: i64) -> (ContractTableRamBilling, i64) {
        (
            ContractTableRamBilling {
                code,
                primary_bytes: bytes,
                primary_rows: 1,
                primary_value_bytes: u64::try_from(bytes).unwrap(),
                ..Default::default()
            },
            bytes,
        )
    }

    #[test]
    fn rank_orders_largest_first_then_by_table_key() {
        let mut rows = [row(3, 10), row(2, 20), row(1, 20)];
        rows.sort_unstable_by(compare_table_rank);
        assert_eq!(
            rows.iter().map(|(row, _)| row.code).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn json_exposes_primary_and_every_secondary_family() {
        let row = ContractTableRamBilling {
            code: 1,
            scope: 2,
            table: 3,
            payer: 4,
            table_overhead_bytes: 5,
            primary_rows: 6,
            primary_value_bytes: 7,
            primary_bytes: 8,
            index64_rows: 9,
            index64_bytes: 10,
            index128_rows: 11,
            index128_bytes: 12,
            index256_rows: 13,
            index256_bytes: 14,
            index_double_rows: 15,
            index_double_bytes: 16,
            index_long_double_rows: 17,
            index_long_double_bytes: 18,
        };
        let value = table_json(&row, 83);
        assert_eq!(value["total_bytes"], 83);
        assert_eq!(value["primary"]["value_bytes"], 7);
        assert_eq!(value["index64"]["rows"], 9);
        assert_eq!(value["index128"]["rows"], 11);
        assert_eq!(value["index256"]["rows"], 13);
        assert_eq!(value["index_double"]["rows"], 15);
        assert_eq!(value["index_long_double"]["rows"], 17);
    }
}
