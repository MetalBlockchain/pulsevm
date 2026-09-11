//! Serialize a stopped Arena database into the portable snapshot envelope.

use std::{
    env,
    fs::OpenOptions,
    io::Write,
    process::ExitCode,
};

use pulsevm_database::Database;

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(arena_dir) = args.next() else {
        eprintln!("Usage: xpr_checkpoint_existing <arena-directory> <checkpoint-file>");
        return ExitCode::from(2);
    };
    let Some(checkpoint_path) = args.next() else {
        eprintln!("Usage: xpr_checkpoint_existing <arena-directory> <checkpoint-file>");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("Usage: xpr_checkpoint_existing <arena-directory> <checkpoint-file>");
        return ExitCode::from(2);
    }

    let database = match Database::new(&arena_dir.to_string_lossy(), 0) {
        Ok(database) => database,
        Err(error) => {
            eprintln!("cannot open Arena database: {error}");
            return ExitCode::from(1);
        }
    };
    let revision = database.revision();
    let checkpoint = match database.snapshot_bytes() {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            eprintln!("cannot serialize Arena checkpoint: {error}");
            return ExitCode::from(1);
        }
    };
    let write_result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&checkpoint_path)
        .and_then(|mut file| {
            file.write_all(&checkpoint)?;
            file.sync_all()
        });
    if let Err(error) = write_result {
        eprintln!("cannot write Arena checkpoint: {error}");
        return ExitCode::from(1);
    }
    println!(
        "wrote revision {revision} checkpoint to {} ({} bytes)",
        checkpoint_path.to_string_lossy(),
        checkpoint.len()
    );
    ExitCode::SUCCESS
}
