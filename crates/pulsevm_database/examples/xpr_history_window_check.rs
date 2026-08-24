//! Validate the framing and table shape of a bounded XPR SHiP history window.
//!
//! Usage: xpr_history_window_check <chain_state_history.log> [post-snapshot-entries]

use std::{env, process::ExitCode};

use pulsevm_database::inspect_state_history_log;

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(path) = args.next() else {
        eprintln!(
            "Usage: xpr_history_window_check <chain_state_history.log> [post-snapshot-entries]"
        );
        return ExitCode::from(2);
    };
    let limit = match args.next() {
        Some(value) => match value.to_string_lossy().parse::<u64>() {
            Ok(limit) => limit,
            Err(error) => {
                eprintln!("invalid post-snapshot entry limit: {error}");
                return ExitCode::from(2);
            }
        },
        None => 10_000,
    };
    if args.next().is_some() {
        eprintln!(
            "Usage: xpr_history_window_check <chain_state_history.log> [post-snapshot-entries]"
        );
        return ExitCode::from(2);
    }

    match inspect_state_history_log(&path, limit) {
        Ok(summary) => {
            println!("first_block_id={}", hex::encode(summary.first_block_id));
            println!("last_block_id={}", hex::encode(summary.last_block_id));
            println!("first_payload_bytes={}", summary.first_payload_bytes);
            println!("entries={}", summary.entries);
            println!("post_snapshot_entries={}", summary.post_snapshot_entries);
            println!("complete={}", summary.complete);
            println!("generated_transactions={}", summary.generated_transactions);
            for (table, rows) in summary.table_rows {
                println!("table.{table}={rows}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("invalid XPR history log: {error}");
            ExitCode::from(1)
        }
    }
}
