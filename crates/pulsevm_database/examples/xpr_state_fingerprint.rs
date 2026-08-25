//! Print a stable Arena state fingerprint for an imported XPR checkpoint.
//!
//! Usage: xpr_state_fingerprint <checkpoint> <arena-directory>

use std::{env, path::Path, process::ExitCode};

use pulsevm_database::Database;
use sha2::{Digest, Sha256};

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(checkpoint) = args.next() else {
        eprintln!("Usage: xpr_state_fingerprint <checkpoint> <arena-directory>");
        return ExitCode::from(2);
    };
    let Some(arena_directory) = args.next() else {
        eprintln!("Usage: xpr_state_fingerprint <checkpoint> <arena-directory>");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("Usage: xpr_state_fingerprint <checkpoint> <arena-directory>");
        return ExitCode::from(2);
    }

    let arena_directory = arena_directory.to_string_lossy();
    let mut database = match Database::new(&arena_directory, 64 * 1024 * 1024) {
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

    let state_root = database.arena_state_root().unwrap_or_default();
    println!("revision {}", database.revision());
    println!("state_root {}", hex::encode(state_root));
    for (name, bytes) in database.arena_state_table_bytes() {
        let hash = Sha256::digest(&bytes);
        println!("table {name} bytes={} sha256={}", bytes.len(), hex::encode(hash));
    }
    ExitCode::SUCCESS
}
