use std::{env, fs, process::ExitCode};

use pulsevm_database::{hydrate_full_state, parse_initial_state_history_log, Database};

fn usage() {
    eprintln!("Usage: xpr_import_check <chain_state_history.log> <arena-directory>");
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(log_path) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let Some(database_path) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        usage();
        return ExitCode::from(2);
    }

    let log = match fs::read(&log_path) {
        Ok(log) => log,
        Err(error) => {
            eprintln!("cannot read {}: {error}", log_path.to_string_lossy());
            return ExitCode::from(1);
        }
    };
    let entry = match parse_initial_state_history_log(&log) {
        Ok(entry) => entry,
        Err(error) => {
            eprintln!("cannot parse XPR state-history log: {error}");
            return ExitCode::from(1);
        }
    };
    let mut database = match Database::new(&database_path.to_string_lossy(), 64 * 1024 * 1024) {
        Ok(database) => database,
        Err(error) => {
            eprintln!("cannot create Arena database: {error}");
            return ExitCode::from(1);
        }
    };

    match hydrate_full_state(&mut database, &entry) {
        Ok(summary) => {
            println!("XPR state imported successfully: {summary:?}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("XPR state is not importable yet: {error}");
            ExitCode::from(1)
        }
    }
}
