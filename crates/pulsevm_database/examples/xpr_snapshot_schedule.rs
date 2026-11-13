//! Preflight for the cutover's schedule anchor: reads a Leap snapshot and runs
//! the same checks the converter runs on H's snapshot, without needing a state
//! history export. Any recent snapshot of the real chain works, because the
//! committee only changes through a schedule proposal: if this passes today it
//! will pass at H unless the schedule changes in between.
//!
//! Usage: xpr_snapshot_schedule <leap-snapshot.bin>
//!
//! Exit 0 prints the head block, schedule version, producer count and whether
//! the active schedule hashes to the pending-schedule hash that the head
//! block's producer signature covers. Exit 1 names the reason (non-K1 or
//! multi-key producer, hash mismatch, bad signature, unreadable snapshot).

use std::{
    fs,
    process::ExitCode,
};

use pulsevm_database::SourceSchedule;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("Usage: xpr_snapshot_schedule <leap-snapshot.bin>");
        return ExitCode::from(2);
    };
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {path}: {error}");
            return ExitCode::from(1);
        }
    };
    match SourceSchedule::from_snapshot_bytes(&bytes) {
        Ok(schedule) => {
            println!(
                "head block {} (id {}), schedule version {}, {} producers",
                schedule.head_block_num,
                hex::encode(schedule.head_block_id),
                schedule.schedule_version,
                schedule.producers.len()
            );
            if schedule.pending_schedule_staged {
                println!(
                    "note: a schedule change is staged; the ceremony must wait until it activates"
                );
            }
            if schedule.schedule_version == 0 {
                println!(
                    "note: version 0 is the genesis schedule; the signed schedule-hash anchor does not apply"
                );
            } else {
                println!(
                    "schedule consistency: ok (active schedule hashes to the pending-schedule hash in the head's signed digest)"
                );
            }
            println!("head producer signature: ok");
            println!(
                "schedule sha256 (publish this and pin it in the migration genesis): {}",
                hex::encode(schedule.schedule_sha256())
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("schedule preflight FAILED: {error}");
            ExitCode::from(1)
        }
    }
}
