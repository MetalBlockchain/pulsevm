//! Apply a bounded post-snapshot XPR SHiP window to an Arena checkpoint.
//!
//! Usage: xpr_apply_history_window <checkpoint> <history-log> <arena-dir> [sidecar-dir] [entries]

use std::{
    env,
    path::{
        Path,
        PathBuf,
    },
    process::ExitCode,
};

use pulsevm_database::{
    Database,
    apply_state_history_log_window,
    apply_state_history_log_window_with_sidecars,
};

const USAGE: &str = "Usage: xpr_apply_history_window <checkpoint> <history-log> <arena-dir> [sidecar-dir] [entries]";

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(checkpoint) = args.next() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(history) = args.next() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(arena_dir) = args.next() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let rest: Vec<_> = args.collect();
    let (sidecar_dir, entries) = match rest.as_slice() {
        [] => (None, 10_000),
        [value] => match value.to_string_lossy().parse::<u64>() {
            Ok(entries) => (None, entries),
            Err(_) => (Some(PathBuf::from(value)), 10_000),
        },
        [sidecars, entries] => {
            let entries = match entries.to_string_lossy().parse::<u64>() {
                Ok(entries) => entries,
                Err(error) => {
                    eprintln!("invalid entry limit: {error}");
                    return ExitCode::from(2);
                }
            };
            (Some(PathBuf::from(sidecars)), entries)
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

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
    let result = match sidecar_dir {
        Some(sidecar_dir) => apply_state_history_log_window_with_sidecars(
            &mut database,
            &history,
            sidecar_dir,
            entries,
        ),
        None => apply_state_history_log_window(&mut database, &history, entries),
    };
    match result {
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
