use std::{
    env,
    fs,
    process::ExitCode,
};

use pulsevm_database::{
    Database,
    DeferredTransactionSidecar,
    MigrationManifest,
    SourceSchedule,
    hydrate_full_state_with_deferred_transactions,
    parse_initial_state_history_log,
    write_source_schedule,
};

fn usage() {
    eprintln!(
        "Usage: xpr_import_check <chain_state_history.log> <arena-directory> [checkpoint-file] [deferred-transactions.json] [--leap-snapshot snapshot.bin --schedule-sha256 HEX] [--no-deferred-sidecar]\n\
         --leap-snapshot reads H's active producer schedule from the Leap snapshot the state history was exported from and\n\
         writes it into the checkpoint, so the checkpoint hash binds the committee. Required for any checkpoint a cutover\n\
         restores from.\n\
         --schedule-sha256 is the published hash of the source chain's active schedule (print it with xpr_snapshot_schedule\n\
         from any current snapshot, publish it ahead, and pin it in the genesis); the conversion refuses a snapshot whose\n\
         committee hashes to anything else.\n\
         A checkpoint also needs the complete deferred-transaction sidecar (v2, with source_chain_id): without it the\n\
         replay-protection set and action sequences are lost and the hash differs from every BP that had it.\n\
         --no-deferred-sidecar waives that for rehearsal fixtures only."
    );
}

fn main() -> ExitCode {
    // `--leap-snapshot PATH` may appear anywhere; everything else is
    // positional, as before.
    let mut raw: Vec<std::ffi::OsString> = env::args_os().collect();
    let mut leap_snapshot_path = None;
    if let Some(position) = raw.iter().position(|arg| arg == "--leap-snapshot") {
        if position + 1 >= raw.len() {
            usage();
            return ExitCode::from(2);
        }
        leap_snapshot_path = Some(raw.remove(position + 1));
        raw.remove(position);
    }
    let mut schedule_sha256_arg: Option<String> = None;
    if let Some(position) = raw.iter().position(|arg| arg == "--schedule-sha256") {
        if position + 1 >= raw.len() {
            usage();
            return ExitCode::from(2);
        }
        schedule_sha256_arg = raw.remove(position + 1).into_string().ok();
        raw.remove(position);
    }
    let mut no_deferred_sidecar = false;
    if let Some(position) = raw.iter().position(|arg| arg == "--no-deferred-sidecar") {
        no_deferred_sidecar = true;
        raw.remove(position);
    }
    let mut args = raw.into_iter();
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
    let deferred_transactions_path = args.next();
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
    let deferred_transactions = match deferred_transactions_path {
        Some(path) => {
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    eprintln!("cannot read {}: {error}", path.to_string_lossy());
                    return ExitCode::from(1);
                }
            };
            let sidecar = match DeferredTransactionSidecar::from_json_bytes(&bytes) {
                Ok(sidecar) => sidecar,
                Err(error) => {
                    eprintln!("cannot parse deferred-transaction sidecar: {error}");
                    return ExitCode::from(1);
                }
            };
            Some((bytes, sidecar))
        }
        None => None,
    };
    // A checkpoint a cutover restores from must carry the complete sidecar:
    // a sidecar-less conversion silently drops the replay-protection set and
    // action sequences, so that BP lands on a different hash than the rest.
    if checkpoint_path.is_some() && !no_deferred_sidecar {
        match &deferred_transactions {
            None => {
                eprintln!(
                    "refusing to write a migration checkpoint without the deferred-transaction sidecar (pass it as the fourth argument, or --no-deferred-sidecar for a rehearsal fixture)"
                );
                return ExitCode::from(1);
            }
            Some((_, sidecar)) if sidecar.source_chain_id.is_none() => {
                eprintln!(
                    "refusing to write a migration checkpoint from a legacy sidecar without source_chain_id: re-export with the v2 sidecar plugin"
                );
                return ExitCode::from(1);
            }
            Some(_) => {}
        }
    } else if checkpoint_path.is_some() {
        eprintln!(
            "WARNING: --no-deferred-sidecar: this checkpoint is for rehearsal only and will not match a fleet that converted with the sidecar"
        );
    }
    // A leftover arena would fail with a duplicate-account error or, worse,
    // hash something other than this export: start from an empty directory.
    if let Ok(mut existing) = fs::read_dir(&database_path)
        && existing.next().is_some()
    {
        eprintln!(
            "refusing a non-empty arena directory {}: convert into a fresh one",
            database_path.to_string_lossy()
        );
        return ExitCode::from(1);
    }
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

    match hydrate_full_state_with_deferred_transactions(
        &mut database,
        &entry,
        deferred_transactions.as_ref().map(|(_, sidecar)| sidecar),
    ) {
        Ok(summary) => {
            if let Some(checkpoint_path) = checkpoint_path {
                // Arena's revision is the source chain height. Keeping the
                // actual SHiP anchor here lets startup and SHiP advertise the
                // first post-import block instead of pretending the snapshot
                // was block one.
                let source_block = u32::from_be_bytes(entry.block_id[..4].try_into().unwrap());
                if source_block == 0 {
                    eprintln!("cannot write migration checkpoint: source block id has height 0");
                    return ExitCode::from(1);
                }
                if let Err(error) = database.set_revision(i64::from(source_block)) {
                    eprintln!("cannot set migration checkpoint revision: {error}");
                    return ExitCode::from(1);
                }
                // The committee at H, read from the Leap snapshot (never from
                // an API capture) and written into the state the checkpoint
                // hash covers. It must be for the very block the state
                // history was anchored at.
                if let Some(path) = &leap_snapshot_path {
                    let snapshot = match fs::read(path) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            eprintln!("cannot read {}: {error}", path.to_string_lossy());
                            return ExitCode::from(1);
                        }
                    };
                    let schedule = match SourceSchedule::from_snapshot_bytes(&snapshot) {
                        Ok(schedule) => schedule,
                        Err(error) => {
                            eprintln!("cannot read the source schedule from the snapshot: {error}");
                            return ExitCode::from(1);
                        }
                    };
                    // The committee must be the published one: a fact from
                    // outside this bundle, not something the snapshot (or an
                    // exporter) can state for itself.
                    let Some(expected_schedule) = schedule_sha256_arg.as_deref() else {
                        eprintln!(
                            "refusing to write a migration checkpoint without --schedule-sha256: pin the published source schedule hash (xpr_snapshot_schedule prints it)"
                        );
                        return ExitCode::from(1);
                    };
                    let actual_schedule = hex::encode(schedule.schedule_sha256());
                    if !expected_schedule.eq_ignore_ascii_case(&actual_schedule) {
                        eprintln!(
                            "the snapshot's committee (schedule v{}) hashes to {actual_schedule}, not the published {expected_schedule}: refusing",
                            schedule.schedule_version
                        );
                        return ExitCode::from(1);
                    }
                    if schedule.head_block_id != entry.block_id {
                        eprintln!(
                            "the Leap snapshot head {} is not the state-history block {}: wrong snapshot for this export",
                            hex::encode(schedule.head_block_id),
                            hex::encode(entry.block_id)
                        );
                        return ExitCode::from(1);
                    }
                    if let Err(error) = write_source_schedule(&database, &schedule) {
                        eprintln!("cannot write the source schedule into the checkpoint: {error}");
                        return ExitCode::from(1);
                    }
                    println!(
                        "source schedule: {} producers, version {}, bound into the checkpoint",
                        schedule.producers.len(),
                        schedule.schedule_version
                    );
                } else {
                    // A schedule-less checkpoint can be hashed and pinned
                    // into a genesis, burning a ceremony round before the
                    // restore gate refuses it. Refuse to produce one.
                    eprintln!(
                        "refusing to write a migration checkpoint without --leap-snapshot: it would carry no source schedule and the restore gate would refuse it"
                    );
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
                let mut manifest = MigrationManifest::new(
                    &log,
                    entry.block_id,
                    &checkpoint,
                    database.revision(),
                    summary,
                );
                if let Some((_, sidecar)) = &deferred_transactions
                    && let Some(source_chain_id) = &sidecar.source_chain_id
                {
                    let bytes = match hex::decode(source_chain_id) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            eprintln!("invalid source chain id in sidecar: {error}");
                            return ExitCode::from(1);
                        }
                    };
                    let source_chain_id: [u8; 32] = match bytes.try_into() {
                        Ok(id) => id,
                        Err(_) => {
                            eprintln!("invalid source chain id length in sidecar");
                            return ExitCode::from(1);
                        }
                    };
                    manifest = manifest.with_source_chain_id(source_chain_id);
                }
                if let Some((bytes, _)) = &deferred_transactions {
                    manifest = manifest.with_deferred_transaction_sidecar(bytes);
                }
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
                println!(
                    "wrote migration checkpoint: {}",
                    checkpoint_path.to_string_lossy()
                );
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
