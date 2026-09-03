//! Compare the complete 19-table SHiP snapshot emitted by nodeos with Arena's
//! re-serialized snapshot. This is deliberately a wire-level comparison: it
//! does not compare Rust's internal table bytes or rely on the importer summary.
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
        rows: rows.len(),
        sha256: hex::encode(hasher.finalize()),
    }
}

fn parse_framed_tables(bytes: &[u8]) -> Result<BTreeMap<String, TableReport>, String> {
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
        if result.insert(name.clone(), hash_rows(&rows)).is_some() {
            return Err(format!("duplicate table {name:?}"));
        }
    }
    if pos != bytes.len() {
        return Err("trailing bytes after SHiP tables".into());
    }
    Ok(result)
}

fn source_tables(
    entry: &pulsevm_database::StateHistoryEntry,
) -> Result<BTreeMap<String, TableReport>, String> {
    let mut tables = BTreeMap::new();
    for delta in &entry.deltas {
        let rows = delta
            .rows
            .iter()
            .map(|row| (row.present, row.data.clone()))
            .collect::<Vec<_>>();
        if tables
            .insert(delta.name.clone(), hash_rows(&rows))
            .is_some()
        {
            return Err(format!("duplicate nodeos table {:?}", delta.name));
        }
    }
    Ok(tables)
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
    let source = match source_tables(&entry) {
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
    let arena = match parse_framed_tables(&database.pack_deltas(true, &chain_id)) {
        Ok(tables) => tables,
        Err(error) => {
            eprintln!("cannot parse Arena SHiP snapshot: {error}");
            return ExitCode::from(1);
        }
    };

    let mut report_tables = BTreeMap::new();
    let mut mismatch = false;
    for name in TABLES {
        let left = source.get(name);
        let right = arena.get(name);
        if left != right {
            mismatch = true;
            eprintln!("table {name}: nodeos={left:?} arena={right:?}");
        } else if let Some(value) = left {
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
    for name in source.keys().chain(arena.keys()) {
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
