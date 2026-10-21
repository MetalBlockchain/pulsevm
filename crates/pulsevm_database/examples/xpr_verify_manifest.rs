//! Offline migration-manifest verifier: the go/no-go gate's second pair of
//! eyes. It runs every check the restore gate runs — manifest↔checkpoint
//! binding, halt-commitment crypto (v1 single-key, v2 checkpoint-bound,
//! weighted quorum with a roster), and roster↔checkpoint-state binding —
//! without booting a node. The checkpoint is restored into a scratch Arena
//! directory, so the node binary is never involved.
//!
//! Structural source-block checks (exact consumption, transaction-root
//! recomputation) still run at restore; this tool checks the commitment,
//! the roster, and every hash binding around them.

use std::{
    env,
    fs,
    path::{
        Path,
        PathBuf,
    },
    process::ExitCode,
};

use pulsevm_database::{
    Database,
    MigrationManifest,
    migration_state_producer_keys,
    verify_migration_halt_commitment,
    verify_migration_halt_pair,
};

fn usage() {
    eprintln!(
        "Usage: xpr_verify_manifest <manifest.json> <checkpoint> [--work-dir <dir>] [--genesis <migration-genesis.json>] [--platform-chain-id <hex>]"
    );
    eprintln!("       xpr_verify_manifest --emit-roster <checkpoint> [--work-dir <dir>]");
    eprintln!("  Verifies the manifest, halt proof, roster, and state binding,");
    eprintln!("  restoring the checkpoint into a scratch Arena directory (a");
    eprintln!("  temporary one unless --work-dir is given). --emit-roster prints");
    eprintln!("  a starting-point roster derived from the checkpoint instead.");
    eprintln!("  --genesis (the migration genesis the new network boots from) is");
    eprintln!("  required when the manifest carries the two-step pair: the");
    eprintln!("  successor chain id is derived from it, never typed by hand.");
    eprintln!("  --platform-chain-id (the MetalGo blockchain id wallets sign under, hex or");
    eprintln!("  the base58 log rendering) independently confirms the confirmation's platform");
    eprintln!("  binding, exactly as the restore gate does. Without it the binding's signatures");
    eprintln!("  still verify but the id itself goes unchecked — the gate remains the");
    eprintln!("  verify but the id itself is unchecked — the gate remains the");
    eprintln!("  enforcer, since only boot config knows the real platform id.");
}

fn fail(message: String) -> ExitCode {
    eprintln!("xpr_verify_manifest: FAIL: {message}");
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(first) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    if first == "--emit-roster" {
        let Some(checkpoint_path) = args.next() else {
            usage();
            return ExitCode::from(2);
        };
        let mut work_dir: Option<PathBuf> = None;
        while let Some(arg) = args.next() {
            if arg == "--work-dir" {
                let Some(dir) = args.next() else {
                    usage();
                    return ExitCode::from(2);
                };
                work_dir = Some(PathBuf::from(dir));
            } else {
                usage();
                return ExitCode::from(2);
            }
        }
        return emit_roster(Path::new(&checkpoint_path), work_dir.as_deref());
    }
    let manifest_path = first;
    let Some(checkpoint_path) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let mut work_dir: Option<PathBuf> = None;
    let mut genesis: Option<String> = None;
    let mut platform: Option<[u8; 32]> = None;
    while let Some(arg) = args.next() {
        if arg == "--work-dir" {
            let Some(dir) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            work_dir = Some(PathBuf::from(dir));
        } else if arg == "--genesis" {
            let Some(path) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            genesis = Some(path.to_string_lossy().into_owned());
        } else if arg == "--platform-chain-id" {
            let Some(hex) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            let text = hex.to_string_lossy().into_owned();
            match pulsevm_crypto::parse_chain_id(&text) {
                Ok(id) => platform = Some(id),
                Err(error) => {
                    eprintln!("xpr_verify_manifest: --platform-chain-id: {error}");
                    return ExitCode::from(2);
                }
            }
        } else {
            usage();
            return ExitCode::from(2);
        }
    }

    run(
        Path::new(&manifest_path),
        Path::new(&checkpoint_path),
        work_dir.as_deref(),
        genesis.as_deref(),
        platform.as_ref(),
    )
}

fn run(
    manifest_path: &Path,
    checkpoint_path: &Path,
    work_dir: Option<&Path>,
    genesis_path: Option<&str>,
    platform_chain_id: Option<&[u8; 32]>,
) -> ExitCode {
    let manifest: MigrationManifest = match fs::read(manifest_path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(manifest) => manifest,
            Err(error) => {
                return fail(format!(
                    "cannot parse {}: {error}",
                    manifest_path.to_string_lossy()
                ));
            }
        },
        Err(error) => {
            return fail(format!(
                "cannot read {}: {error}",
                manifest_path.to_string_lossy()
            ));
        }
    };
    println!("manifest version: {}", manifest.version);
    if let Err(error) = manifest.verify_checkpoint_path(checkpoint_path) {
        return fail(format!("checkpoint binding rejected: {error}"));
    }
    println!("checkpoint binding: ok ({})", manifest.checkpoint_sha256);

    let has_commitment = manifest.halt_commitment.is_some();
    let has_pair = manifest.halt_declaration.is_some();
    if !has_pair {
        return fail(
            "migration manifest carries no two-step cutover pair: a restore requires the declaration and its confirmation"
                .into(),
        );
    }
    if !has_commitment {
        println!("note: no legacy halt commitment attached; verifying the cutover pair");
    }
    if manifest.source_block.is_none() {
        return fail("halt proof requires an attached source block".into());
    }
    let block_id: [u8; 32] = match hex::decode(&manifest.source_block_id) {
        Ok(bytes) => match bytes.try_into() {
            Ok(id) => id,
            Err(_) => return fail("manifest source block id has the wrong length".into()),
        },
        Err(error) => return fail(format!("manifest source block id invalid: {error}")),
    };
    let checkpoint_sha256: [u8; 32] = match hex::decode(&manifest.checkpoint_sha256) {
        Ok(bytes) => match bytes.try_into() {
            Ok(hash) => hash,
            Err(_) => return fail("manifest checkpoint hash has the wrong length".into()),
        },
        Err(error) => return fail(format!("manifest checkpoint hash invalid: {error}")),
    };
    let height = match u32::try_from(manifest.checkpoint_revision) {
        Ok(height) if height > 0 => height,
        _ => {
            return fail(format!(
                "manifest checkpoint revision {} is not a usable block height",
                manifest.checkpoint_revision
            ));
        }
    };
    if has_commitment {
        let commitment = manifest
            .halt_commitment
            .as_ref()
            .expect("commitment presence checked above");
        if let Err(error) =
            verify_migration_halt_commitment(&manifest, height, &block_id, &checkpoint_sha256)
        {
            return fail(error);
        }
        println!(
            "halt commitment: ok (version {}, height {height})",
            commitment.version
        );
    }
    let mut pair_roster = None;
    if has_pair {
        let Some(genesis_path) = genesis_path else {
            return fail(
                "--genesis <migration genesis> is required for the declaration pair".into(),
            );
        };
        let genesis_bytes = match fs::read(genesis_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                return fail(format!(
                    "cannot read migration genesis {}: {error}",
                    Path::new(genesis_path).to_string_lossy()
                ));
            }
        };
        let genesis = match pulsevm_database::GenesisState::from_bytes(&genesis_bytes) {
            Ok(genesis) => genesis,
            Err(error) => return fail(format!("migration genesis rejected: {error}")),
        };
        if genesis.migration_checkpoint_sha256.is_none() {
            return fail("migration genesis carries no migration checkpoint binding".into());
        }
        let new_chain_id = genesis.compute_chain_id();
        let header_schedule_version = match manifest
            .source_block
            .as_deref()
            .ok_or_else(|| "halt proof requires an attached source block".to_string())
            .and_then(pulsevm_database::packed_source_block_schedule_version)
        {
            Ok(version) => version,
            Err(error) => {
                return fail(format!("source block schedule version unreadable: {error}"));
            }
        };
        if platform_chain_id.is_none() {
            println!(
                "note: no --platform-chain-id given; the confirmation's platform binding is signature-checked but not independently confirmed"
            );
        }
        match verify_migration_halt_pair(
            &manifest,
            height,
            &block_id,
            &checkpoint_sha256,
            &new_chain_id,
            header_schedule_version,
            platform_chain_id,
        ) {
            Ok(roster) => {
                println!(
                    "halt declaration + confirmation: ok (height {height}, {} declared members, new chain {})",
                    roster.len(),
                    hex::encode(new_chain_id)
                );
                match manifest.halt_declaration_inclusion {
                    Some(inclusion) => println!(
                        "vote window: declaration committed at block {inclusion} ({} blocks before H{})",
                        height - inclusion,
                        manifest
                            .halt_max_declaration_lag
                            .map(|lag| format!(", max lag {lag}"))
                            .unwrap_or_default()
                    ),
                    None => println!(
                        "vote window: no declaration inclusion recorded (off-chain signatures; timing not provable)"
                    ),
                }
                match manifest.halt_confirmation_inclusion {
                    Some(inclusion) => println!(
                        "vote window: confirmation committed at block {inclusion} ({} blocks after H{})",
                        inclusion - height,
                        manifest
                            .halt_max_confirmation_lag
                            .map(|lag| format!(", deadline +{lag}"))
                            .unwrap_or_default()
                    ),
                    None => println!(
                        "vote window: no confirmation inclusion recorded (off-chain signatures; timing not provable)"
                    ),
                }
                pair_roster = Some(roster);
            }
            Err(error) => return fail(error),
        }
        match &manifest.halt_contract_ceremony {
            Some(ceremony) => println!(
                "cutover contract: ok ({} votes on {}, finalized at block {}, tally {}/{})",
                ceremony.votes.len(),
                ceremony.contract,
                ceremony.finalized_block,
                ceremony.voted_weight.0,
                ceremony.total_weight.0,
            ),
            None => println!("cutover contract: no on-chain ceremony evidence attached"),
        }
        match &manifest.halt_schedule_version {
            Some(version) => println!("schedule version: {version} (unanimous across votes and H)"),
            None => println!("schedule version: unattested"),
        }
    }

    let Some(roster) = pair_roster else {
        return fail("cutover pair verification produced no roster".into());
    };

    // Held until the end of run so a scratch directory is cleaned up.
    let scratch_guard = match work_dir {
        Some(_) => None,
        None => match tempfile::TempDir::new() {
            Ok(temp) => Some(temp),
            Err(error) => return fail(format!("cannot create scratch directory: {error}")),
        },
    };
    let arena_dir: PathBuf = match work_dir {
        Some(dir) => dir.to_path_buf(),
        None => scratch_guard
            .as_ref()
            .expect("scratch guard exists when no work dir is given")
            .path()
            .join("arena"),
    };
    if let Err(error) =
        verify_roster_against_checkpoint(&manifest, checkpoint_path, &arena_dir, &roster)
    {
        return fail(error);
    }
    println!("PASS");
    drop(scratch_guard);
    ExitCode::SUCCESS
}

fn emit_roster(checkpoint_path: &Path, work_dir: Option<&Path>) -> ExitCode {
    let scratch_guard = match work_dir {
        Some(_) => None,
        None => match tempfile::TempDir::new() {
            Ok(temp) => Some(temp),
            Err(error) => return fail(format!("cannot create scratch directory: {error}")),
        },
    };
    let arena_dir: PathBuf = match work_dir {
        Some(dir) => dir.to_path_buf(),
        None => scratch_guard
            .as_ref()
            .expect("scratch guard exists when no work dir is given")
            .path()
            .join("arena"),
    };
    let result = (|| -> Result<(), String> {
        let checkpoint_len = fs::metadata(checkpoint_path)
            .map_err(|e| format!("cannot stat checkpoint: {e}"))?
            .len();
        let database = Database::new(
            &arena_dir.to_string_lossy(),
            checkpoint_len.saturating_add(64 * 1024 * 1024),
        )
        .map_err(|e| format!("cannot open scratch Arena: {e}"))?;
        database
            .restore_from_path(checkpoint_path)
            .map_err(|e| format!("cannot restore checkpoint: {e}"))?;
        let template = pulsevm_database::migration_halt_roster_template(&database)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&template)
                .map_err(|e| format!("cannot serialize roster: {e}"))?
        );
        Ok(())
    })();
    drop(scratch_guard);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(error),
    }
}

fn verify_roster_against_checkpoint(
    manifest: &MigrationManifest,
    checkpoint_path: &Path,
    arena_dir: &Path,
    roster: &[pulsevm_chain_types::HaltRosterEntry],
) -> Result<(), String> {
    let checkpoint_len = fs::metadata(checkpoint_path)
        .map_err(|e| format!("cannot stat checkpoint: {e}"))?
        .len();
    let db_size = checkpoint_len.saturating_add(64 * 1024 * 1024);
    let database = Database::new(&arena_dir.to_string_lossy(), db_size)
        .map_err(|e| format!("cannot open scratch Arena: {e}"))?;
    let header = database
        .restore_from_path(checkpoint_path)
        .map_err(|e| format!("cannot restore checkpoint: {e}"))?;
    if header.revision != manifest.checkpoint_revision {
        return Err(format!(
            "restored revision {} does not match manifest {}",
            header.revision, manifest.checkpoint_revision
        ));
    }
    let state_keys = migration_state_producer_keys(&database)?;
    if state_keys.is_empty() {
        println!("note: no producers table in checkpoint state; cross-check skipped");
        return Ok(());
    }
    // The pair path enforces the light-client rule: the declared set must
    // equal the on-chain schedule exactly (same members, same keys; weights
    // pinned by the frozen tally when contract evidence is attached, by
    // H-state on the memo path).
    match pulsevm_database::check_halt_roster_matches_state(roster, &state_keys)? {
        Some(matched) => {
            println!("roster schedule match: ok ({matched} producers)");
        }
        None => {
            println!("note: no producers table in checkpoint state; cross-check skipped");
        }
    }
    if manifest.halt_contract_ceremony.is_none() {
        let matched = pulsevm_database::check_halt_roster_weights_match_state(roster, &state_keys)?;
        println!("roster weight pin: ok ({matched} producers, memo path)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use pulsevm_database::{
        Database,
        HaltConfirmation,
        HaltDeclaration,
        HaltDeclarationMember,
        HaltSignature,
        ImportSummary,
        MigrationHaltRosterEntry,
        MigrationManifest,
        StateHistoryEntry,
        TableDelta,
        TableDeltaRow,
        hydrate_full_state,
    };
    use pulsevm_name::Name;

    use super::run;

    fn producer_info_row(owner: u64, key: &[u8; 33]) -> Vec<u8> {
        let mut row = Vec::new();
        row.extend_from_slice(&owner.to_le_bytes());
        row.extend_from_slice(&100.0f64.to_le_bytes());
        row.push(0); // K1 key type
        row.extend_from_slice(key);
        row.push(1); // is_active
        row.push(3); // url length
        row.extend_from_slice(b"url");
        row.extend_from_slice(&0u32.to_le_bytes());
        row.extend_from_slice(&0i64.to_le_bytes());
        row.extend_from_slice(&0u16.to_le_bytes());
        // Canonical 1-of-1 authority tail over the schedule key (live layout).
        row.push(0); // variant index
        row.extend_from_slice(&1u32.to_le_bytes()); // threshold
        row.push(1); // one key
        row.push(0); // K1 key type
        row.extend_from_slice(key);
        row.extend_from_slice(&1u16.to_le_bytes()); // weight
        row
    }

    fn table_delta(name: &str, data: Vec<u8>) -> TableDelta {
        TableDelta {
            name: name.into(),
            rows: vec![TableDeltaRow {
                present: true,
                data,
            }],
        }
    }

    struct Fixture {
        dir: tempfile::TempDir,
        manifest: std::path::PathBuf,
        checkpoint: std::path::PathBuf,
        genesis: std::path::PathBuf,
    }

    /// Platform id the fixture confirmation binds (mirrors the ceremony
    /// config the voter/agent would carry into production).
    const FIXTURE_PLATFORM: [u8; 32] = [0x51; 32];

    fn migration_genesis_json(checkpoint_sha256: &str, initial_key: &str) -> serde_json::Value {
        serde_json::json!({
            "initial_timestamp": "2023-01-01T00:00:00",
            "initial_key": initial_key,
            "initial_configuration": {
                "max_block_net_usage": 1048576,
                "target_block_net_usage_pct": 1000,
                "max_transaction_net_usage": 524288,
                "base_per_transaction_net_usage": 12,
                "net_usage_leeway": 500,
                "context_free_discount_net_usage_num": 20,
                "context_free_discount_net_usage_den": 100,
                "max_block_cpu_usage": 3000000000u64,
                "target_block_cpu_usage_pct": 2500,
                "max_transaction_cpu_usage": 1000000000u64,
                "min_transaction_cpu_usage": 100000,
                "max_transaction_lifetime": 3600,
                "deferred_trx_expiration_window": 600,
                "max_transaction_delay": 3888000,
                "max_inline_action_size": 4096,
                "max_inline_action_depth": 6,
                "max_authority_depth": 6,
                "max_action_return_value_size": 256
            },
            "migration_checkpoint_sha256": checkpoint_sha256,
        })
    }

    fn write_genesis(
        dir: &std::path::Path,
        name: &str,
        initial_key: &str,
        checkpoint: &str,
    ) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&migration_genesis_json(checkpoint, initial_key)).unwrap(),
        )
        .unwrap();
        path
    }

    /// Build a checkpoint whose producers table holds one producer, plus a
    /// matching manifest carrying the two-step pair and the on-chain
    /// ceremony (run with the matching successor chain id). When
    /// `tamper_roster` is set the roster key is swapped so the state
    /// binding must fail. Legacy roster-less manifests are not built: the
    /// verifier rejects them.
    fn fixture(tamper_roster: bool) -> Fixture {
        let dir = tempfile::TempDir::new().unwrap();
        let system = Name::from_str("eosio").unwrap().as_u64();
        let producers = Name::from_str("producers").unwrap().as_u64();
        let owner = Name::from_str("prod.a").unwrap().as_u64();
        let signing =
            pulsevm_crypto::k1::K1PrivateKey::from_seed_string("verifier-test-1").unwrap();
        let other = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("verifier-test-2").unwrap();

        let mut db =
            Database::new(dir.path().join("build").to_str().unwrap(), 64 * 1024 * 1024).unwrap();
        let mut table_row = vec![0u8];
        for value in [system, system, producers, 55u64] {
            table_row.extend_from_slice(&value.to_le_bytes());
        }
        let mut kv_row = vec![0u8];
        for value in [system, system, producers, owner, 55u64] {
            kv_row.extend_from_slice(&value.to_le_bytes());
        }
        let value = producer_info_row(owner, &signing.public_key().compressed());
        kv_row.push(value.len() as u8);
        kv_row.extend_from_slice(&value);
        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [0; 32],
            deltas: vec![
                table_delta("contract_table", table_row),
                table_delta("contract_row", kv_row),
            ],
        };
        hydrate_full_state(&mut db, &entry).unwrap();
        db.set_revision(7).unwrap();
        let checkpoint_bytes = db.snapshot_bytes().unwrap();
        drop(db);
        let checkpoint = dir.path().join("migration.snapshot");
        std::fs::write(&checkpoint, &checkpoint_bytes).unwrap();

        let mut manifest = MigrationManifest::new(
            b"fixture log",
            [9; 32],
            &checkpoint_bytes,
            7,
            ImportSummary::default(),
        );
        // Minimal packed source-block prefix: zeros with schedule version 1
        // at the version offset. The verifier only reads the prefix (the
        // restore decodes the full block); the offset itself is pinned by a
        // golden test against a decoded block in the controller tests.
        manifest.source_block = Some(format!("{}01000000", "00".repeat(110)));
        let roster_key = if tamper_roster {
            other.public_key()
        } else {
            signing.public_key()
        };
        manifest = manifest.with_halt_roster(vec![MigrationHaltRosterEntry {
            producer: "prod.a".to_string(),
            key: roster_key.to_string(),
            weight: pulsevm_chain_types::HaltWeight(100),
        }]);
        // The migration genesis binds the checkpoint; confirmations and the
        // restore gate derive the successor id from these exact bytes.
        let genesis = write_genesis(
            dir.path(),
            "migration.genesis.json",
            &signing.public_key().to_string(),
            &manifest.checkpoint_sha256,
        );
        let mut members = vec![HaltDeclarationMember {
            producer: "prod.a".to_string(),
            key: signing.public_key().to_string(),
            weight: pulsevm_chain_types::HaltWeight(100),
        }];
        HaltDeclaration::sort_members(&mut members);
        let unsigned = HaltDeclaration {
            version: HaltDeclaration::VERSION,
            source_chain_id: "41".repeat(32),
            last_height: 7,
            validator_set: members,
            signatures: Vec::new(),
        };
        let decl_digest = unsigned.digest().unwrap();
        let vote_signature = signing.sign(&decl_digest).to_string();
        let declaration = HaltDeclaration {
            signatures: vec![HaltSignature {
                producer: "prod.a".to_string(),
                key: signing.public_key().to_string(),
                signature: vote_signature.clone(),
            }],
            ..unsigned
        };
        declaration.verify(7).unwrap();
        let genesis_id =
            pulsevm_database::GenesisState::from_bytes(&std::fs::read(&genesis).unwrap())
                .unwrap()
                .compute_chain_id();
        let template = HaltConfirmation {
            version: HaltConfirmation::VERSION,
            declaration_digest: hex::encode(declaration.digest().unwrap()),
            halt_height: 7,
            halt_block_id: "09".repeat(32),
            checkpoint_sha256: manifest.checkpoint_sha256.clone(),
            new_chain_id: hex::encode(genesis_id),
            platform_chain_id: Some(hex::encode(FIXTURE_PLATFORM)),
            signatures: Vec::new(),
        };
        let conf_digest = template.digest().unwrap();
        manifest.halt_declaration = Some(declaration);
        manifest.halt_confirmation = Some(HaltConfirmation {
            signatures: vec![HaltSignature {
                producer: "prod.a".to_string(),
                key: signing.public_key().to_string(),
                signature: signing.sign(&conf_digest).to_string(),
            }],
            ..template
        });
        // The on-chain ceremony is mandatory: the single vote lands before
        // H, the singleton is finalized before H, and the captured tally
        // equals the recomputed signer weight.
        manifest.halt_contract_ceremony = Some(pulsevm_database::HaltContractCeremony {
            contract: "cutover".to_string(),
            declaration_digest: hex::encode(decl_digest),
            total_weight: pulsevm_chain_types::HaltWeight(100),
            voted_weight: pulsevm_chain_types::HaltWeight(100),
            finalized: true,
            finalized_block: 6,
            votes: vec![pulsevm_database::HaltContractVote {
                producer: "prod.a".to_string(),
                block: 5,
                schedule_version: 1,
                key: signing.public_key().to_string(),
                signature: vote_signature,
            }],
        });
        manifest.halt_schedule_version = Some(1);
        let manifest_path = dir.path().join("migration.manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        Fixture {
            dir,
            manifest: manifest_path,
            checkpoint,
            genesis,
        }
    }

    fn genesis_str(fixture: &Fixture) -> &str {
        fixture
            .genesis
            .to_str()
            .expect("fixture genesis path is UTF-8")
    }

    #[test]
    fn verifies_matching_fixture_end_to_end() {
        let fixture = fixture(false);
        assert_eq!(
            run(
                &fixture.manifest,
                &fixture.checkpoint,
                None,
                Some(genesis_str(&fixture)),
                Some(&FIXTURE_PLATFORM)
            ),
            std::process::ExitCode::SUCCESS
        );
        // Keep the fixture alive until the scratch verification finishes.
        drop(fixture.dir);
    }

    #[test]
    fn rejects_fixture_with_forged_roster_key() {
        let fixture = fixture(true);
        assert_ne!(
            run(
                &fixture.manifest,
                &fixture.checkpoint,
                None,
                Some(genesis_str(&fixture)),
                Some(&FIXTURE_PLATFORM)
            ),
            std::process::ExitCode::SUCCESS
        );
        drop(fixture.dir);
    }

    #[test]
    fn verifies_cutover_pair_end_to_end() {
        let fixture = fixture(false);
        assert_eq!(
            run(
                &fixture.manifest,
                &fixture.checkpoint,
                None,
                Some(genesis_str(&fixture)),
                Some(&FIXTURE_PLATFORM)
            ),
            std::process::ExitCode::SUCCESS
        );
        drop(fixture.dir);
    }

    #[test]
    fn rejects_pair_on_wrong_successor_chain() {
        let fixture = fixture(false);
        // A migration genesis with a different initial key derives a
        // different successor id, which the confirmation does not bind.
        let wrong = write_genesis(
            fixture.dir.path(),
            "wrong.genesis.json",
            "PUB_K1_8mck1q4iw94nBCaaUKVdSfDFBZBw4PHRAvkNKrHbpJ8UPCkJ9N",
            &serde_json::from_slice::<MigrationManifest>(
                &std::fs::read(&fixture.manifest).unwrap(),
            )
            .unwrap()
            .checkpoint_sha256,
        );
        assert_ne!(
            run(
                &fixture.manifest,
                &fixture.checkpoint,
                None,
                Some(wrong.to_str().expect("genesis path is UTF-8")),
                Some(&FIXTURE_PLATFORM)
            ),
            std::process::ExitCode::SUCCESS
        );
        drop(fixture.dir);
    }

    #[test]
    fn rejects_pair_when_roster_diverges_from_declared_set() {
        let fixture = fixture(true);
        assert_ne!(
            run(
                &fixture.manifest,
                &fixture.checkpoint,
                None,
                Some(genesis_str(&fixture)),
                Some(&FIXTURE_PLATFORM)
            ),
            std::process::ExitCode::SUCCESS
        );
        drop(fixture.dir);
    }

    #[test]
    fn rejects_pair_when_platform_diverges() {
        let fixture = fixture(false);
        let other = [0x52; 32];
        assert_ne!(
            run(
                &fixture.manifest,
                &fixture.checkpoint,
                None,
                Some(genesis_str(&fixture)),
                Some(&other)
            ),
            std::process::ExitCode::SUCCESS
        );
        drop(fixture.dir);
    }

    #[test]
    fn rejects_pair_when_confirmation_is_missing() {
        let fixture = fixture(false);
        let mut manifest: MigrationManifest =
            serde_json::from_slice(&std::fs::read(&fixture.manifest).unwrap()).unwrap();
        manifest.halt_confirmation = None;
        std::fs::write(
            &fixture.manifest,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert_ne!(
            run(
                &fixture.manifest,
                &fixture.checkpoint,
                None,
                Some(genesis_str(&fixture)),
                Some(&FIXTURE_PLATFORM)
            ),
            std::process::ExitCode::SUCCESS
        );
        drop(fixture.dir);
    }
}
