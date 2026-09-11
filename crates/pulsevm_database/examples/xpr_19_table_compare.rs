//! Compare the complete 19-table SHiP snapshot emitted by nodeos with Arena's
//! re-serialized snapshot. This compares the serialized logical row multiset:
//! chainbase object ids determine nodeos's row order but are not present in the
//! SHiP payload, so a different internal Arena allocation order is immaterial.
//! It does not compare Rust's internal table bytes or rely on the importer summary.
//!
//! Usage:
//! xpr_19_table_compare <nodeos-chain-state-history.log> <arena-checkpoint>
//!     <arena-directory> <source-chain-id-hex> [report.json]

use std::{
    collections::BTreeMap,
    env,
    fs,
    path::Path,
    process::ExitCode,
};

use pulsevm_database::{
    Database,
    parse_initial_state_history_log,
};
use sha2::{
    Digest,
    Sha256,
};

const TABLES: [&str; 19] = [
    "account",
    "account_metadata",
    "code",
    "contract_table",
    "contract_row",
    "contract_index64",
    "contract_index128",
    "contract_index256",
    "contract_index_double",
    "contract_index_long_double",
    "global_property",
    "generated_transaction",
    "protocol_state",
    "permission",
    "permission_link",
    "resource_limits",
    "resource_usage",
    "resource_limits_state",
    "resource_limits_config",
];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct TableReport {
    rows: usize,
    sha256: String,
}

#[derive(Debug, serde::Serialize)]
struct Report {
    source_block_id: String,
    source_chain_id: String,
    tables: BTreeMap<String, TableReport>,
}

type TableRows = BTreeMap<String, Vec<(bool, Vec<u8>)>>;

fn usage() {
    eprintln!(
        "Usage: xpr_19_table_compare <nodeos-log> <checkpoint> <arena-dir> <source-chain-id-hex> [report.json]"
    );
}

fn read_uvar(bytes: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = *bytes
            .get(*pos)
            .ok_or_else(|| "truncated SHiP varuint".to_owned())?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err("SHiP varuint overflows u64".into());
        }
    }
}

fn hash_rows(rows: &[(bool, Vec<u8>)]) -> TableReport {
    let mut hasher = Sha256::new();
    let mut rows = rows.iter().collect::<Vec<_>>();
    rows.sort_unstable();
    let row_count = rows.len();
    for (present, payload) in rows {
        hasher.update([u8::from(*present)]);
        let mut len = payload.len() as u64;
        loop {
            let mut byte = (len as u8) & 0x7f;
            len >>= 7;
            if len != 0 {
                byte |= 0x80;
            }
            hasher.update([byte]);
            if len == 0 {
                break;
            }
        }
        hasher.update(payload);
    }
    TableReport {
        rows: row_count,
        sha256: hex::encode(hasher.finalize()),
    }
}

fn parse_framed_tables(bytes: &[u8]) -> Result<TableRows, String> {
    let mut pos = 0;
    let count = read_uvar(bytes, &mut pos)? as usize;
    let mut result = BTreeMap::new();
    for _ in 0..count {
        let version = read_uvar(bytes, &mut pos)?;
        if version != 0 {
            return Err(format!("unsupported table_delta version {version}"));
        }
        let name_len = read_uvar(bytes, &mut pos)? as usize;
        let end = pos
            .checked_add(name_len)
            .ok_or_else(|| "table name length overflows".to_owned())?;
        let name = std::str::from_utf8(
            bytes
                .get(pos..end)
                .ok_or_else(|| "truncated table name".to_owned())?,
        )
        .map_err(|_| "table name is not UTF-8".to_owned())?
        .to_owned();
        pos = end;
        let row_count = read_uvar(bytes, &mut pos)? as usize;
        let mut rows = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            let present = *bytes
                .get(pos)
                .ok_or_else(|| "truncated row presence flag".to_owned())?
                != 0;
            pos += 1;
            let row_len = read_uvar(bytes, &mut pos)? as usize;
            let end = pos
                .checked_add(row_len)
                .ok_or_else(|| "row length overflows".to_owned())?;
            rows.push((
                present,
                bytes
                    .get(pos..end)
                    .ok_or_else(|| "truncated row payload".to_owned())?
                    .to_vec(),
            ));
            pos = end;
        }
        if result.insert(name.clone(), rows).is_some() {
            return Err(format!("duplicate table {name:?}"));
        }
    }
    if pos != bytes.len() {
        return Err("trailing bytes after SHiP tables".into());
    }
    Ok(result)
}

fn source_tables(entry: &pulsevm_database::StateHistoryEntry) -> Result<TableRows, String> {
    let mut tables = BTreeMap::new();
    for delta in &entry.deltas {
        let rows = delta
            .rows
            .iter()
            .map(|row| (row.present, row.data.clone()))
            .collect::<Vec<_>>();
        if tables.insert(delta.name.clone(), rows).is_some() {
            return Err(format!("duplicate nodeos table {:?}", delta.name));
        }
    }
    Ok(tables)
}

fn row_key(table: &str, row: &[u8]) -> String {
    let fields = match table {
        "contract_row"
        | "contract_index64"
        | "contract_index128"
        | "contract_index256"
        | "contract_index_double"
        | "contract_index_long_double" => 5,
        "permission" => 3,
        _ => 0,
    };
    let mut pos = 0;
    if fields == 0 || read_uvar(row, &mut pos).is_err() {
        return String::new();
    }
    let mut values = Vec::with_capacity(fields);
    for _ in 0..fields {
        let Some(bytes) = row.get(pos..pos + 8) else {
            return String::new();
        };
        values.push(u64::from_le_bytes(bytes.try_into().unwrap()));
        pos += 8;
    }
    format!(" key={values:?}")
}

fn row_preview(row: &(bool, Vec<u8>)) -> String {
    const PREVIEW_BYTES: usize = 96;
    let shown = row.1.len().min(PREVIEW_BYTES);
    let suffix = if shown < row.1.len() { "..." } else { "" };
    format!(
        "present={} bytes={} hex={}{}",
        row.0,
        row.1.len(),
        hex::encode(&row.1[..shown]),
        suffix
    )
}

fn diagnose_rows(table: &str, nodeos: &[(bool, Vec<u8>)], arena: &[(bool, Vec<u8>)]) {
    let mut nodeos = nodeos.iter().collect::<Vec<_>>();
    let mut arena = arena.iter().collect::<Vec<_>>();
    nodeos.sort_unstable();
    arena.sort_unstable();
    let mut shown = 0;
    for index in 0..nodeos.len().max(arena.len()) {
        let left = nodeos.get(index);
        let right = arena.get(index);
        if left == right {
            continue;
        }
        eprintln!("table {table}: first differing row index {index}");
        if let Some(row) = left {
            eprintln!("  nodeos{} {}", row_key(table, &row.1), row_preview(row));
        } else {
            eprintln!("  nodeos=<missing>");
        }
        if let Some(row) = right {
            eprintln!("  arena{} {}", row_key(table, &row.1), row_preview(row));
        } else {
            eprintln!("  arena=<missing>");
        }
        shown += 1;
        if shown == 3 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::hash_rows;

    #[test]
    fn logical_row_hash_ignores_allocation_order() {
        let first = vec![(true, vec![1, 2]), (true, vec![3]), (false, vec![4])];
        let reordered = vec![(false, vec![4]), (true, vec![1, 2]), (true, vec![3])];
        assert_eq!(hash_rows(&first), hash_rows(&reordered));
    }

    #[test]
    fn logical_row_hash_commits_presence_and_payload() {
        let row = vec![(true, vec![1, 2])];
        assert_ne!(hash_rows(&row), hash_rows(&[(false, vec![1, 2])]));
        assert_ne!(hash_rows(&row), hash_rows(&[(true, vec![1, 3])]));
    }
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(log_path) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let Some(checkpoint_path) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let Some(arena_path) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let Some(chain_id) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let report_path = args.next();
    if args.next().is_some() {
        usage();
        return ExitCode::from(2);
    }

    let chain_id_text = chain_id.to_string_lossy();
    let chain_id = match hex::decode(chain_id_text.as_bytes()) {
        Ok(bytes) if bytes.len() == 32 => <[u8; 32]>::try_from(bytes).unwrap(),
        _ => {
            eprintln!("source chain id must be exactly 64 hexadecimal characters");
            return ExitCode::from(2);
        }
    };
    let log = match fs::read(&log_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read nodeos history log: {error}");
            return ExitCode::from(1);
        }
    };
    let entry = match parse_initial_state_history_log(&log) {
        Ok(entry) => entry,
        Err(error) => {
            eprintln!("cannot parse nodeos full-state record: {error}");
            return ExitCode::from(1);
        }
    };
    let source_rows = match source_tables(&entry) {
        Ok(tables) => tables,
        Err(error) => {
            eprintln!("invalid nodeos table set: {error}");
            return ExitCode::from(1);
        }
    };
    let mut database = match Database::new(&arena_path.to_string_lossy(), 64 * 1024 * 1024) {
        Ok(database) => database,
        Err(error) => {
            eprintln!("cannot create Arena database: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) = database.add_indices() {
        eprintln!("cannot initialize Arena tables: {error}");
        return ExitCode::from(1);
    }
    if let Err(error) = database.restore_from_path(Path::new(&checkpoint_path)) {
        eprintln!("cannot restore Arena checkpoint: {error}");
        return ExitCode::from(1);
    }
    let arena_rows = match parse_framed_tables(&database.pack_deltas(true, &chain_id)) {
        Ok(tables) => tables,
        Err(error) => {
            eprintln!("cannot parse Arena SHiP snapshot: {error}");
            return ExitCode::from(1);
        }
    };

    let mut report_tables = BTreeMap::new();
    let mut mismatch = false;
    for name in TABLES {
        let left_rows = source_rows.get(name);
        let right_rows = arena_rows.get(name);
        let left = left_rows.map(|rows| hash_rows(rows));
        let right = right_rows.map(|rows| hash_rows(rows));
        if left != right {
            mismatch = true;
            eprintln!("table {name}: nodeos={left:?} arena={right:?}");
            if let (Some(left_rows), Some(right_rows)) = (left_rows, right_rows) {
                diagnose_rows(name, left_rows, right_rows);
            }
        } else if let Some(value) = &left {
            println!("table {name}: rows={} sha256={}", value.rows, value.sha256);
            report_tables.insert(name.to_owned(), value.clone());
        }
        if left.is_none() && right.is_none() {
            continue;
        }
        if left.is_none() || right.is_none() {
            mismatch = true;
        }
    }
    for name in source_rows.keys().chain(arena_rows.keys()) {
        if !TABLES.contains(&name.as_str()) {
            mismatch = true;
            eprintln!("unexpected table {name:?}");
        }
    }

    let report = Report {
        source_block_id: hex::encode(entry.block_id),
        source_chain_id: hex::encode(chain_id),
        tables: report_tables,
    };
    if let Some(path) = report_path {
        let bytes = match serde_json::to_vec_pretty(&report) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("cannot serialize comparison report: {error}");
                return ExitCode::from(1);
            }
        };
        if let Err(error) = fs::write(&path, bytes) {
            eprintln!("cannot write comparison report: {error}");
            return ExitCode::from(1);
        }
    }
    if mismatch {
        eprintln!("19-table nodeos/Arena comparison FAILED");
        ExitCode::from(1)
    } else {
        println!("19-table nodeos/Arena comparison passed");
        ExitCode::SUCCESS
    }
}
