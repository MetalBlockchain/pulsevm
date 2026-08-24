//! Apply a bounded post-snapshot XPR SHiP window to an Arena checkpoint.
//!
//! Usage: xpr_apply_history_window <checkpoint> <history-log> <arena-dir> [entries]

use std::{env, process::ExitCode, path::Path};

use pulsevm_database::{Database, apply_state_history_log_window};

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(checkpoint) = args.next() else {
        eprintln!("Usage: xpr_apply_history_window <checkpoint> <history-log> <arena-dir> [entries]");
        return ExitCode::from(2);
    };
    let Some(history) = args.next() else {
        eprintln!("Usage: xpr_apply_history_window <checkpoint> <history-log> <arena-dir> [entries]");
        return ExitCode::from(2);
    };
    let Some(arena_dir) = args.next() else {
        eprintln!("Usage: xpr_apply_history_window <checkpoint> <history-log> <arena-dir> [entries]");
        return ExitCode::from(2);
    };
    let entries = match args.next() {
        Some(value) => match value.to_string_lossy().parse::<u64>() {
            Ok(entries) => entries,
            Err(error) => {
                eprintln!("invalid entry limit: {error}");
                return ExitCode::from(2);
            }
        },
        None => 10_000,
    };
    if args.next().is_some() {
        eprintln!("Usage: xpr_apply_history_window <checkpoint> <history-log> <arena-dir> [entries]");
        return ExitCode::from(2);
    }

    let mut database = match Database::new(&arena_dir.to_string_lossy(), 64 * 1024 * 1024) {
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
    if let Err(error) = database.restore_from_path(Path::new(&checkpoint)) {
        eprintln!("cannot restore checkpoint: {error}");
        return ExitCode::from(1);
    }
    match apply_state_history_log_window(&mut database, &history, entries) {
        Ok(applied) => {
            println!("applied post-snapshot SHiP entries={applied}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("history window stopped: {error}");
            ExitCode::from(1)
        }
    }
}
