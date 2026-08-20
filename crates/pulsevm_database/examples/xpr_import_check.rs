use std::{env, fs, process::ExitCode};

use pulsevm_database::{
    Database,
    MigrationManifest,
    hydrate_full_state,
    parse_initial_state_history_log,
};

fn usage() {
    eprintln!("Usage: xpr_import_check <chain_state_history.log> <arena-directory> [checkpoint-file]");
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
    let checkpoint_path = args.next();
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
    for delta in &entry.deltas {
        eprintln!(
            "XPR table {:<30} rows={} payload-bytes={}",
            delta.name,
            delta.rows.len(),
            delta.rows.iter().map(|row| row.data.len()).sum::<usize>()
        );
        if delta.name == "global_property" {
            for row in &delta.rows {
                eprintln!("global_property: {}", hex::encode(&row.data));
            }
        }
    }
    let mut database = match Database::new(&database_path.to_string_lossy(), 64 * 1024 * 1024) {
        Ok(database) => database,
        Err(error) => {
            eprintln!("cannot create Arena database: {error}");
            return ExitCode::from(1);
        }
    };

    match hydrate_full_state(&mut database, &entry) {
        Ok(summary) => {
            if let Some(checkpoint_path) = checkpoint_path {
                if let Err(error) = database.set_revision(1) {
                    eprintln!("cannot set migration checkpoint revision: {error}");
                    return ExitCode::from(1);
                }
                let checkpoint = match database.snapshot_bytes() {
                    Ok(checkpoint) => checkpoint,
                    Err(error) => {
                        eprintln!("cannot serialize migration checkpoint: {error}");
                        return ExitCode::from(1);
                    }
                };
                if let Err(error) = fs::write(&checkpoint_path, &checkpoint) {
                    eprintln!(
                        "cannot write migration checkpoint {}: {error}",
                        checkpoint_path.to_string_lossy()
                    );
                    return ExitCode::from(1);
                }
                let manifest_path = format!("{}.manifest.json", checkpoint_path.to_string_lossy());
                let manifest = MigrationManifest::new(
                    &log,
                    entry.block_id,
                    &checkpoint,
                    database.revision(),
                    summary,
                );
                let manifest = match serde_json::to_vec_pretty(&manifest) {
                    Ok(manifest) => manifest,
                    Err(error) => {
                        eprintln!("cannot serialize migration manifest: {error}");
                        return ExitCode::from(1);
                    }
                };
                if let Err(error) = fs::write(&manifest_path, manifest) {
                    eprintln!("cannot write migration manifest {manifest_path}: {error}");
                    return ExitCode::from(1);
                }
                println!("wrote migration checkpoint: {}", checkpoint_path.to_string_lossy());
                println!("wrote migration manifest: {manifest_path}");
            }
            println!("XPR state imported successfully: {summary:?}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("XPR state is not importable yet: {error}");
            ExitCode::from(1)
        }
    }
}
