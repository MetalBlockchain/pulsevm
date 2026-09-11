use std::{
    env,
    path::Path,
    process::ExitCode,
};

use pulsevm_database::Database;

fn usage() {
    eprintln!("Usage: xpr_restore_checkpoint <migration.snapshot> <arena-directory>");
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(snapshot) = args.next() else {
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

    let database_path = database_path.to_string_lossy();
    let mut database = match Database::new(&database_path, 64 * 1024 * 1024) {
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
    let header = match database.restore_from_path(Path::new(&snapshot)) {
        Ok(header) => header,
        Err(error) => {
            eprintln!("cannot restore checkpoint: {error}");
            return ExitCode::from(1);
        }
    };
    println!(
        "restored checkpoint revision={} payload_bytes={} into {}",
        header.revision, header.payload_len, database_path
    );
    ExitCode::SUCCESS
}
