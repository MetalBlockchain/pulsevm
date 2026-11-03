//! The source chain's active producer schedule, carried inside the checkpoint.
//!
//! The restore gate has to know who the real committee was at H. Taking that
//! from the exporter's JSON (a `get_block_header_state` capture) leaves the
//! committee authenticated by nothing but the exporter. The Leap snapshot the
//! checkpoint is converted from already carries it: its
//! `eosio::chain::block_state` section is H's `block_header_state`, with the
//! active schedule, the pending schedule and the header that re-derives the
//! snapshot's block id. This module reads that section, re-checks it against
//! itself, and writes the schedule into the checkpoint as ordinary contract
//! rows, so the checkpoint hash the ceremony confirms covers it. Each BP
//! takes the snapshot from its own node, and the fleet agreeing on the
//! checkpoint hash is what authenticates the committee.
//!
//! Rows live under code `eosio`, scope `eosio`, table `migsrcsched`:
//! primary key 0 is the header row, keys 1..=n are the producers in the
//! schedule's own order. Order matters: Leap picks the producer for a slot by
//! position in this list.

use std::str::FromStr;

use pulsevm_crypto::{
    Digest,
    k1::K1PublicKey,
};
use pulsevm_snapshot::{
    BlockSigningAuthority,
    SnapshotPublicKey,
    SnapshotReader,
};

use crate::{
    Database,
    xpr_import::MigrationHaltRosterEntry,
};

const SYSTEM_ACCOUNT: &str = "eosio";
const TABLE: &str = "migsrcsched";
/// block id (32) | block num (u32 LE) | schedule version (u32 LE) | pending
/// staged (u8) | producer count (u32 LE).
const HEADER_ROW_LEN: usize = 32 + 4 + 4 + 1 + 4;
/// producer name (u64 LE) | compressed K1 key (33).
const PRODUCER_ROW_LEN: usize = 8 + 33;
/// A real committee is 21; this only bounds a hostile snapshot.
const MAX_PRODUCERS: u32 = 1024;

/// One scheduled producer: its name and its single K1 block-signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceScheduleMember {
    pub producer: u64,
    pub key: [u8; 33],
}

/// H's active schedule as the snapshot states it, in schedule order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSchedule {
    /// Id of the snapshot's head block: the checkpoint's own H.
    pub head_block_id: [u8; 32],
    pub head_block_num: u32,
    pub schedule_version: u32,
    /// Whether the snapshot's head state carries a pending (proposed)
    /// schedule. The cutover requires none.
    pub pending_schedule_staged: bool,
    pub producers: Vec<SourceScheduleMember>,
}

fn name_value(text: &str) -> Result<u64, String> {
    pulsevm_name::Name::from_str(text)
        .map(|name| name.as_u64())
        .map_err(|error| format!("invalid reserved name {text}: {error}"))
}

fn varuint(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

impl SourceSchedule {
    /// Primary-key-ordered rows: the header at 0, then one row per producer.
    pub fn to_rows(&self) -> Vec<(u64, Vec<u8>)> {
        let mut header = Vec::with_capacity(HEADER_ROW_LEN);
        header.extend_from_slice(&self.head_block_id);
        header.extend_from_slice(&self.head_block_num.to_le_bytes());
        header.extend_from_slice(&self.schedule_version.to_le_bytes());
        header.push(u8::from(self.pending_schedule_staged));
        header.extend_from_slice(&(self.producers.len() as u32).to_le_bytes());
        let mut rows = vec![(0u64, header)];
        for (index, member) in self.producers.iter().enumerate() {
            let mut row = Vec::with_capacity(PRODUCER_ROW_LEN);
            row.extend_from_slice(&member.producer.to_le_bytes());
            row.extend_from_slice(&member.key);
            rows.push((index as u64 + 1, row));
        }
        rows
    }

    /// Rebuild from the restored rows. Exact shapes only: a missing header,
    /// a gap, a count that disagrees with the rows, a duplicate producer or a
    /// trailing byte all fail closed.
    pub fn from_rows(rows: &[(u64, Vec<u8>)]) -> Result<Self, String> {
        let Some((first_key, header)) = rows.first() else {
            return Err("source schedule table is empty".to_string());
        };
        if *first_key != 0 {
            return Err(format!(
                "source schedule has no header row (first key {first_key})"
            ));
        }
        if header.len() != HEADER_ROW_LEN {
            return Err(format!(
                "source schedule header row is {} bytes (expected {HEADER_ROW_LEN})",
                header.len()
            ));
        }
        let head_block_id: [u8; 32] = header[0..32]
            .try_into()
            .map_err(|_| "source schedule header id unreadable".to_string())?;
        let head_block_num = u32::from_le_bytes(
            header[32..36]
                .try_into()
                .map_err(|_| "source schedule header number unreadable".to_string())?,
        );
        let schedule_version = u32::from_le_bytes(
            header[36..40]
                .try_into()
                .map_err(|_| "source schedule header version unreadable".to_string())?,
        );
        let pending_schedule_staged = match header[40] {
            0 => false,
            1 => true,
            other => return Err(format!("source schedule pending flag is {other}")),
        };
        let count = u32::from_le_bytes(
            header[41..45]
                .try_into()
                .map_err(|_| "source schedule header count unreadable".to_string())?,
        );
        if count == 0 || count > MAX_PRODUCERS {
            return Err(format!("source schedule declares {count} producers"));
        }
        if rows.len() != count as usize + 1 {
            return Err(format!(
                "source schedule header declares {count} producers but {} rows follow",
                rows.len() - 1
            ));
        }
        let mut producers = Vec::with_capacity(count as usize);
        for (index, (key, row)) in rows[1..].iter().enumerate() {
            if *key != index as u64 + 1 {
                return Err(format!(
                    "source schedule row {key} is out of order (expected {})",
                    index + 1
                ));
            }
            if row.len() != PRODUCER_ROW_LEN {
                return Err(format!(
                    "source schedule producer row {key} is {} bytes (expected {PRODUCER_ROW_LEN})",
                    row.len()
                ));
            }
            let producer = u64::from_le_bytes(
                row[0..8]
                    .try_into()
                    .map_err(|_| "source schedule producer name unreadable".to_string())?,
            );
            let key_bytes: [u8; 33] = row[8..41]
                .try_into()
                .map_err(|_| "source schedule producer key unreadable".to_string())?;
            if producers
                .iter()
                .any(|existing: &SourceScheduleMember| existing.producer == producer)
            {
                return Err(format!(
                    "source schedule names producer {} twice",
                    pulsevm_name::Name::new(producer)
                ));
            }
            producers.push(SourceScheduleMember {
                producer,
                key: key_bytes,
            });
        }
        Ok(Self {
            head_block_id,
            head_block_num,
            schedule_version,
            pending_schedule_staged,
            producers,
        })
    }

    /// The schedule as unit-weight roster entries, in schedule order. Every
    /// key must be a valid K1 point: a key nobody can sign for fails here.
    pub fn to_roster(&self) -> Result<Vec<MigrationHaltRosterEntry>, String> {
        self.producers
            .iter()
            .map(|member| {
                let key = K1PublicKey::from_compressed(&member.key).map_err(|error| {
                    format!(
                        "source schedule key for {} is not a valid K1 key: {error:?}",
                        pulsevm_name::Name::new(member.producer)
                    )
                })?;
                Ok(MigrationHaltRosterEntry {
                    producer: pulsevm_name::Name::new(member.producer).to_string(),
                    key: key.to_string(),
                    weight: pulsevm_chain_types::HaltWeight::MEMBER,
                })
            })
            .collect()
    }

    /// Read H's schedule out of a Leap snapshot's `block_state` section and
    /// check the section against itself before trusting it: the embedded
    /// block number matches the id, the header re-derives the id exactly,
    /// and the header's schedule version is the schedule's. Every scheduled
    /// producer must hold exactly one weight-one K1 key, because the gate
    /// verifies block signatures against single keys.
    pub fn from_snapshot_bytes(snapshot: &[u8]) -> Result<Self, String> {
        let reader = SnapshotReader::new(snapshot)
            .map_err(|error| format!("leap snapshot unreadable: {error:?}"))?;
        let state = reader
            .block_header_state()
            .map_err(|error| format!("leap snapshot has no readable block_state: {error:?}"))?;
        if state.block_num_from_id() != state.block_num {
            return Err(format!(
                "snapshot block_state number {} does not match its id {}",
                state.block_num, state.id
            ));
        }
        let header = &state.header;
        if header.new_producers.is_some() {
            return Err(
                "snapshot head block carries a legacy schedule change: freeze the ceremony after it activates"
                    .to_string(),
            );
        }
        let mut packed = Vec::with_capacity(128);
        packed.extend_from_slice(&header.timestamp.slot().to_le_bytes());
        packed.extend_from_slice(&header.producer.as_u64().to_le_bytes());
        packed.extend_from_slice(&header.confirmed.to_le_bytes());
        packed.extend_from_slice(header.previous.as_bytes());
        packed.extend_from_slice(header.transaction_mroot.as_bytes());
        packed.extend_from_slice(header.action_mroot.as_bytes());
        packed.extend_from_slice(&header.schedule_version.to_le_bytes());
        packed.push(0); // no legacy new_producers
        varuint(header.header_extensions.len() as u32, &mut packed);
        for (id, payload) in &header.header_extensions {
            packed.extend_from_slice(&id.to_le_bytes());
            varuint(payload.len() as u32, &mut packed);
            packed.extend_from_slice(payload.as_ref());
        }
        let mut derived = Digest::hash(&packed).0;
        derived[0..4].copy_from_slice(&state.block_num.to_be_bytes());
        if derived != *state.id.as_bytes() {
            return Err(
                "snapshot block_state header does not re-derive the snapshot block id".to_string(),
            );
        }
        if header.schedule_version != state.active_schedule.version {
            return Err(format!(
                "snapshot header schedule version {} disagrees with the active schedule version {}",
                header.schedule_version, state.active_schedule.version
            ));
        }
        let mut producers = Vec::with_capacity(state.active_schedule.producers.len());
        for entry in &state.active_schedule.producers {
            let BlockSigningAuthority::V0(authority) = &entry.authority;
            let producer = entry.producer_name.as_u64();
            let name = pulsevm_name::Name::new(producer);
            let [single] = authority.keys.as_slice() else {
                return Err(format!(
                    "scheduled producer {name} holds {} keys: only single-key schedules are supported",
                    authority.keys.len()
                ));
            };
            if authority.threshold != 1 || single.weight != 1 {
                return Err(format!(
                    "scheduled producer {name} has threshold {} weight {}: only threshold 1 / weight 1 is supported",
                    authority.threshold, single.weight
                ));
            }
            let SnapshotPublicKey::K1(point) = &single.key else {
                return Err(format!("scheduled producer {name} holds a non-K1 key"));
            };
            producers.push(SourceScheduleMember {
                producer,
                key: *point,
            });
        }
        Ok(Self {
            head_block_id: *state.id.as_bytes(),
            head_block_num: state.block_num,
            schedule_version: state.active_schedule.version,
            pending_schedule_staged: !state.pending_schedule.schedule.producers.is_empty(),
            producers,
        })
    }
}

/// Write the schedule into the checkpoint state. Called once by the
/// converter, before the checkpoint is serialized and hashed.
pub fn write_source_schedule(db: &Database, schedule: &SourceSchedule) -> Result<(), String> {
    let system = name_value(SYSTEM_ACCOUNT)?;
    let table = name_value(TABLE)?;
    for (primary, row) in schedule.to_rows() {
        db.create_key_value_object_standalone(system, system, table, system, primary, &row)
            .map_err(|error| format!("cannot store source schedule row {primary}: {error}"))?;
    }
    Ok(())
}

/// Read the schedule back out of restored checkpoint state; `None` when the
/// checkpoint carries none (it was not converted from a Leap snapshot).
pub fn read_source_schedule(db: &Database) -> Result<Option<SourceSchedule>, String> {
    let system = name_value(SYSTEM_ACCOUNT)?;
    let table = name_value(TABLE)?;
    let rows = db.arena_table_range(system, system, table);
    if rows.is_empty() {
        return Ok(None);
    }
    SourceSchedule::from_rows(&rows).map(Some)
}

/// The restore-time and offline binding: the checkpoint's own schedule must
/// be for exactly the block the confirmation names as H, carry H's schedule
/// version and no pending change, and equal the schedule the manifest
/// records, entry for entry and in order. The recorded copy is transport; the
/// checkpoint copy is what the checkpoint hash covers. Returns the schedule.
pub fn verify_source_schedule_binding(
    db: &Database,
    recorded: Option<&[MigrationHaltRosterEntry]>,
    head_block_id: &[u8; 32],
    header_schedule_version: u32,
) -> Result<SourceSchedule, String> {
    let schedule = read_source_schedule(db)?.ok_or_else(|| {
        "checkpoint carries no source schedule: it must be converted from the Leap snapshot of H (xpr_import_check --leap-snapshot)"
            .to_string()
    })?;
    if &schedule.head_block_id != head_block_id {
        return Err(
            "checkpoint source schedule is for a different block than the terminal block H"
                .to_string(),
        );
    }
    if schedule.schedule_version != header_schedule_version {
        return Err(format!(
            "checkpoint source schedule is version {} but H carries version {header_schedule_version}",
            schedule.schedule_version
        ));
    }
    if schedule.pending_schedule_staged {
        return Err(
            "checkpoint source schedule attests a pending producer schedule at H".to_string(),
        );
    }
    let recorded = recorded.ok_or_else(|| {
        "migration manifest records no schedule to compare with the checkpoint".to_string()
    })?;
    let from_checkpoint = schedule.to_roster()?;
    if recorded.len() != from_checkpoint.len() {
        return Err(format!(
            "manifest records {} scheduled producers but the checkpoint carries {}",
            recorded.len(),
            from_checkpoint.len()
        ));
    }
    for (position, (left, right)) in recorded.iter().zip(from_checkpoint.iter()).enumerate() {
        let same_key = K1PublicKey::from_string(&left.key)
            .ok()
            .zip(K1PublicKey::from_string(&right.key).ok())
            .is_some_and(|(a, b)| a == b);
        if left.producer != right.producer || !same_key {
            return Err(format!(
                "manifest schedule differs from the checkpoint schedule at position {position} ({} vs {})",
                left.producer, right.producer
            ));
        }
    }
    Ok(schedule)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(name: &str, seed: u8) -> SourceScheduleMember {
        let key = pulsevm_crypto::k1::K1PrivateKey::from_seed_string(&format!("sched-{seed}"))
            .expect("seed key")
            .public_key();
        SourceScheduleMember {
            producer: name_value(name).expect("name"),
            key: key.compressed(),
        }
    }

    fn schedule() -> SourceSchedule {
        SourceSchedule {
            head_block_id: [0xAB; 32],
            head_block_num: 0xABAB_ABAB,
            schedule_version: 814,
            pending_schedule_staged: false,
            producers: vec![member("alice", 1), member("bob", 2), member("carol", 3)],
        }
    }

    #[test]
    fn rows_round_trip_in_schedule_order() {
        let original = schedule();
        let rebuilt = SourceSchedule::from_rows(&original.to_rows()).expect("round trip");
        assert_eq!(rebuilt, original);
        // Order is part of the schedule: Leap picks the producer for a slot
        // by position, so a reordered copy is a different schedule.
        let mut reordered = original.clone();
        reordered.producers.swap(0, 2);
        assert_ne!(
            SourceSchedule::from_rows(&reordered.to_rows()).expect("rows"),
            original
        );
    }

    #[test]
    fn malformed_rows_fail_closed() {
        let rows = schedule().to_rows();
        assert!(SourceSchedule::from_rows(&[]).is_err(), "empty table");
        assert!(
            SourceSchedule::from_rows(&rows[1..]).is_err(),
            "no header row"
        );
        let mut short = rows.clone();
        short.pop();
        assert!(
            SourceSchedule::from_rows(&short).is_err(),
            "count disagrees with rows"
        );
        let mut gap = rows.clone();
        gap[2].0 = 9;
        assert!(SourceSchedule::from_rows(&gap).is_err(), "gap in keys");
        let mut trailing = rows.clone();
        trailing[1].1.push(0);
        assert!(
            SourceSchedule::from_rows(&trailing).is_err(),
            "trailing byte"
        );
        let mut duplicate = rows.clone();
        duplicate[2].1 = duplicate[1].1.clone();
        assert!(
            SourceSchedule::from_rows(&duplicate).is_err(),
            "producer named twice"
        );
        let mut bad_flag = rows.clone();
        bad_flag[0].1[40] = 7;
        assert!(
            SourceSchedule::from_rows(&bad_flag).is_err(),
            "pending flag outside 0/1"
        );
    }

    fn checkpoint_with(schedule: &SourceSchedule) -> (tempfile::TempDir, Database) {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let db = Database::new(dir.path().join("arena").to_str().unwrap(), 64 * 1024 * 1024)
            .expect("database");
        write_source_schedule(&db, schedule).expect("write");
        (dir, db)
    }

    #[test]
    fn binding_accepts_the_exact_schedule_and_rejects_every_divergence() {
        let schedule = schedule();
        let (_dir, db) = checkpoint_with(&schedule);
        let recorded = schedule.to_roster().expect("roster");
        let id = schedule.head_block_id;
        let version = schedule.schedule_version;

        // Round trip through real restored rows.
        assert_eq!(
            read_source_schedule(&db).expect("read").expect("present"),
            schedule
        );
        let bound = verify_source_schedule_binding(&db, Some(&recorded), &id, version)
            .expect("the exact schedule must bind");
        assert_eq!(bound, schedule);

        // The checkpoint's copy is for exactly H, at H's version.
        assert!(
            verify_source_schedule_binding(&db, Some(&recorded), &[0x01; 32], version)
                .unwrap_err()
                .contains("different block")
        );
        assert!(
            verify_source_schedule_binding(&db, Some(&recorded), &id, version + 1)
                .unwrap_err()
                .contains("version")
        );

        // The exporter's recorded copy is transport: any difference from the
        // checkpoint fails, including order (slot assignment depends on it).
        let mut swapped = recorded.clone();
        swapped.swap(0, 1);
        assert!(
            verify_source_schedule_binding(&db, Some(&swapped), &id, version)
                .unwrap_err()
                .contains("differs from the checkpoint schedule")
        );
        let mut forged_key = recorded.clone();
        forged_key[1].key = recorded[2].key.clone();
        assert!(
            verify_source_schedule_binding(&db, Some(&forged_key), &id, version)
                .unwrap_err()
                .contains("differs from the checkpoint schedule")
        );
        // A forged committee: same size, a member swapped for an outsider.
        let mut outsider = recorded.clone();
        outsider[2].producer = "mallory".to_string();
        assert!(verify_source_schedule_binding(&db, Some(&outsider), &id, version).is_err());
        let truncated = &recorded[..2];
        assert!(
            verify_source_schedule_binding(&db, Some(truncated), &id, version)
                .unwrap_err()
                .contains("records 2 scheduled producers")
        );
        assert!(
            verify_source_schedule_binding(&db, None, &id, version)
                .unwrap_err()
                .contains("records no schedule")
        );
    }

    #[test]
    fn binding_refuses_a_checkpoint_without_the_schedule_or_with_a_pending_change() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let empty = Database::new(dir.path().join("arena").to_str().unwrap(), 64 * 1024 * 1024)
            .expect("database");
        let schedule = schedule();
        let recorded = schedule.to_roster().expect("roster");
        assert!(read_source_schedule(&empty).expect("read").is_none());
        let error = verify_source_schedule_binding(
            &empty,
            Some(&recorded),
            &schedule.head_block_id,
            schedule.schedule_version,
        )
        .unwrap_err();
        assert!(error.contains("no source schedule"), "got: {error}");

        let mut pending = schedule.clone();
        pending.pending_schedule_staged = true;
        let (_dir, db) = checkpoint_with(&pending);
        let error = verify_source_schedule_binding(
            &db,
            Some(&recorded),
            &pending.head_block_id,
            pending.schedule_version,
        )
        .unwrap_err();
        assert!(error.contains("pending"), "got: {error}");
    }

    #[test]
    fn roster_keeps_order_and_rejects_invalid_keys() {
        let roster = schedule().to_roster().expect("roster");
        assert_eq!(
            roster
                .iter()
                .map(|entry| entry.producer.as_str())
                .collect::<Vec<_>>(),
            ["alice", "bob", "carol"]
        );
        let mut bad = schedule();
        bad.producers[1].key = [0u8; 33];
        assert!(bad.to_roster().is_err(), "an unusable key must fail");
    }
}
