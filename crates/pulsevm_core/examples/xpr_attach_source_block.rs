//! Attach an id-exact XPR checkpoint-boundary block to a migration manifest.
//!
//! The source JSON is the response from `v1/chain/get_block`. Snapshot
//! boundaries with transactions or schedule changes are deliberately rejected;
//! choose an empty boundary block so the migration anchor can be independently
//! reconstructed and checked without trusting pruned transaction JSON.
//!
//! With `--halt-key <wif>` the tool additionally signs the old network's halt
//! commitment over the boundary block and embeds it in the manifest, so the
//! new network verifies the producers agreed to freeze before promoting.

use std::{
    env,
    fs,
    path::Path,
    process::ExitCode,
};

use pulsevm_core::{
    id::Id,
    migration_attach::{
        parse_boundary_block,
        post_window_unix_micros,
        record_halt_schedule,
        record_post_blocks,
    },
};
use pulsevm_crypto::K1PrivateKey;
use pulsevm_database::{
    DeferredTransactionSidecar,
    HaltCommitment,
    HaltConfirmation,
    HaltDeclaration,
    HaltSignature,
    MigrationHaltRosterEntry,
    MigrationManifest,
};

/// Export-time deferred-transaction inventory: no migrated deferred may
/// be due between the cutover block and the last staged post-H header.
/// A row due in-window would set a post-H `transaction_mroot` and fail
/// the boot closed at the emptiness gate — correct, but only after the
/// ceremony, snapshot, and freeze. Failing here names the row pre-H.
fn check_deferred_inventory(
    halt: &Value,
    posts: &[(&str, &Value)],
    sidecar_path: &str,
) -> Result<(), String> {
    let bytes = fs::read(sidecar_path)
        .map_err(|error| format!("read deferred sidecar {sidecar_path}: {error}"))?;
    let sidecar = DeferredTransactionSidecar::from_json_bytes(&bytes)
        .map_err(|error| format!("deferred sidecar {sidecar_path} rejected: {error}"))?;
    let (start, end) = post_window_unix_micros(halt, posts)
        .map_err(|error| format!("deferred inventory window unreadable: {error}"))?;
    pulsevm_database::check_no_deferred_due_in_window(&sidecar.transactions, start, end)
        .map_err(|error| format!("deferred inventory rejected: {error}"))?;
    eprintln!(
        "deferred inventory clear: {} sidecar rows, none due between {start} and {end}",
        sidecar.transactions.len()
    );
    Ok(())
}
use pulsevm_serialization::Write;
use serde_json::Value;

fn usage() {
    eprintln!(
        "Usage: xpr_attach_source_block <manifest.json> <get-block.json> <output-manifest.json> [--halt-key <wif>] [--halt-key-v2 <wif>] [--halt-roster <roster.json>] [--declaration <declaration.json> --confirmation <confirmation.json> [--declaration-inclusion <height>] [--confirmation-inclusion <height>] [--max-declaration-lag <K>] [--max-confirmation-lag <J>] [--contract-ceremony <fragment.json> --schedule-version <n> --proposed-schedule <true|false>] [--schedule <schedule.json>] [--post-block <get-block.json> --post-state <header-state.json>]... [--deferred-sidecar <deferred-transactions.json>]"
    );
    eprintln!(
        "  --halt-key-v2 signs a version 2 checkpoint-bound commitment; --halt-roster attaches a"
    );
    eprintln!(
        "  weighted roster JSON array ([{{\"producer\", \"key\", \"weight\"}}]) for quorum verification."
    );
    eprintln!(
        "  --declaration/--confirmation embed the two-step cutover pair; the transport roster is"
    );
    eprintln!("  then taken from the declared set (an explicit --halt-roster must agree with it).");
    eprintln!(
        "  --contract-ceremony attaches the on-chain ceremony fragment (its digest must equal"
    );
    eprintln!(
        "  the declaration digest); --schedule-version records the unanimous schedule version"
    );
    eprintln!("  across votes and H (required with contract evidence; export-enforced).");
    eprintln!("  --proposed-schedule records whether the checkpoint carries a proposed producer");
    eprintln!(
        "  schedule (read from the live get_producer_schedule at export time); only false boots."
    );
    eprintln!("  --schedule records the frozen active schedule from a get_producer_schedule");
    eprintln!("  response (unit weight, H version pinned); --post-block records one get_block");
    eprintln!("  response per post-H header, hash-linked from H and signed by the recorded key;");
    eprintln!("  every --post-block needs its matching --post-state (get_block_header_state, same");
    eprintln!("  order): the state supplies the blockroot and schedule hash Leap signed over.");
    eprintln!("  --deferred-sidecar checks the chainbase deferred inventory against the staged");
    eprintln!("  window: no migrated deferred may be due between H and the last staged header, or");
    eprintln!(
        "  the boot would fail closed at the emptiness gate after the freeze. Fails here instead."
    );
    eprintln!("  --declaration-inclusion records the block carrying the declaration votes (must");
    eprintln!("  predate H); --confirmation-inclusion records the block carrying the confirmation");
    eprintln!(
        "  quorum (must postdate H). --max-declaration-lag/--max-confirmation-lag record the"
    );
    eprintln!("  ceremony freshness bound K and deadline J. The vote-timing rule is enforced here");
    eprintln!("  at record time and re-verified at restore.");
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let (Some(manifest), Some(block), Some(output)) = (args.next(), args.next(), args.next())
    else {
        usage();
        return ExitCode::from(2);
    };
    let mut halt_key: Option<String> = None;
    let mut halt_key_v2: Option<String> = None;
    let mut halt_roster: Option<String> = None;
    let mut declaration: Option<String> = None;
    let mut confirmation: Option<String> = None;
    let mut timing = PairTiming::default();
    let mut schedule: Option<String> = None;
    let mut post_blocks: Vec<String> = Vec::new();
    let mut post_states: Vec<String> = Vec::new();
    let mut deferred_sidecar: Option<String> = None;
    while let Some(arg) = args.next() {
        if arg == "--halt-key" {
            let Some(wif) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            halt_key = Some(wif.to_string_lossy().into_owned());
        } else if arg == "--halt-key-v2" {
            let Some(wif) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            halt_key_v2 = Some(wif.to_string_lossy().into_owned());
        } else if arg == "--halt-roster" {
            let Some(path) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            halt_roster = Some(path.to_string_lossy().into_owned());
        } else if arg == "--declaration" {
            let Some(path) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            declaration = Some(path.to_string_lossy().into_owned());
        } else if arg == "--confirmation" {
            let Some(path) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            confirmation = Some(path.to_string_lossy().into_owned());
        } else if arg == "--declaration-inclusion" {
            let Some(value) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            let Ok(height) = value.to_string_lossy().parse::<u32>() else {
                eprintln!("--declaration-inclusion needs a block height");
                return ExitCode::from(2);
            };
            timing.declaration_inclusion = Some(height);
        } else if arg == "--confirmation-inclusion" {
            let Some(value) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            let Ok(height) = value.to_string_lossy().parse::<u32>() else {
                eprintln!("--confirmation-inclusion needs a block height");
                return ExitCode::from(2);
            };
            timing.confirmation_inclusion = Some(height);
        } else if arg == "--max-declaration-lag" {
            let Some(value) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            let Ok(lag) = value.to_string_lossy().parse::<u32>() else {
                eprintln!("--max-declaration-lag needs a block count");
                return ExitCode::from(2);
            };
            timing.max_declaration_lag = Some(lag);
        } else if arg == "--max-confirmation-lag" {
            let Some(value) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            let Ok(lag) = value.to_string_lossy().parse::<u32>() else {
                eprintln!("--max-confirmation-lag needs a block count");
                return ExitCode::from(2);
            };
            timing.max_confirmation_lag = Some(lag);
        } else if arg == "--contract-ceremony" {
            let Some(path) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            timing.contract_ceremony = Some(path.to_string_lossy().into_owned());
        } else if arg == "--schedule-version" {
            let Some(value) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            let Ok(version) = value.to_string_lossy().parse::<u32>() else {
                usage();
                return ExitCode::from(2);
            };
            timing.schedule_version = Some(version);
        } else if arg == "--proposed-schedule" {
            let Some(value) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            let flag = value.to_string_lossy();
            timing.proposed_schedule = Some(match flag.as_ref() {
                "true" => true,
                "false" => false,
                _ => {
                    eprintln!("--proposed-schedule needs true or false");
                    return ExitCode::from(2);
                }
            });
        } else if arg == "--schedule" {
            let Some(path) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            schedule = Some(path.to_string_lossy().into_owned());
        } else if arg == "--post-block" {
            let Some(path) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            post_blocks.push(path.to_string_lossy().into_owned());
        } else if arg == "--post-state" {
            let Some(path) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            post_states.push(path.to_string_lossy().into_owned());
        } else if arg == "--deferred-sidecar" {
            let Some(path) = args.next() else {
                usage();
                return ExitCode::from(2);
            };
            deferred_sidecar = Some(path.to_string_lossy().into_owned());
        } else {
            usage();
            return ExitCode::from(2);
        }
    }
    if halt_key.is_some() && halt_key_v2.is_some() {
        eprintln!("cannot attach migration source block: --halt-key and --halt-key-v2 conflict");
        return ExitCode::from(2);
    }
    if declaration.is_some() != confirmation.is_some() {
        eprintln!(
            "cannot attach migration source block: --declaration and --confirmation go together"
        );
        return ExitCode::from(2);
    }
    match attach(
        Path::new(&manifest),
        Path::new(&block),
        Path::new(&output),
        halt_key.as_deref(),
        halt_key_v2.as_deref(),
        halt_roster.as_deref(),
        declaration.as_deref(),
        confirmation.as_deref(),
        timing,
        schedule.as_deref(),
        &post_blocks,
        &post_states,
        deferred_sidecar.as_deref(),
    ) {
        Ok((height, id)) => {
            println!("attached migration source block {height} {id}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("cannot attach migration source block: {error}");
            ExitCode::from(1)
        }
    }
}

/// Vote-timing provenance recorded into the manifest: where each
/// commitment landed and which freshness/deadline bounds the ceremony
/// claims. The restore gate re-verifies all of it.
#[derive(Default)]
struct PairTiming {
    declaration_inclusion: Option<u32>,
    confirmation_inclusion: Option<u32>,
    max_declaration_lag: Option<u32>,
    max_confirmation_lag: Option<u32>,
    contract_ceremony: Option<String>,
    schedule_version: Option<u32>,
    /// Whether the checkpoint carries a proposed producer schedule in
    /// `global_property`, read from the live schedule at export time. Only
    /// `Some(false)` boots.
    proposed_schedule: Option<bool>,
}

#[allow(clippy::too_many_arguments)]
fn attach(
    manifest_path: &Path,
    block_path: &Path,
    output_path: &Path,
    halt_key: Option<&str>,
    halt_key_v2: Option<&str>,
    halt_roster: Option<&str>,
    declaration_path: Option<&str>,
    confirmation_path: Option<&str>,
    timing: PairTiming,
    schedule_path: Option<&str>,
    post_block_paths: &[String],
    post_state_paths: &[String],
    deferred_sidecar_path: Option<&str>,
) -> Result<(u32, Id), String> {
    let mut manifest: MigrationManifest = serde_json::from_slice(
        &fs::read(manifest_path).map_err(|error| format!("read manifest: {error}"))?,
    )
    .map_err(|error| format!("parse manifest: {error}"))?;
    let value: Value = serde_json::from_slice(
        &fs::read(block_path).map_err(|error| format!("read source block: {error}"))?,
    )
    .map_err(|error| format!("parse source block: {error}"))?;
    let value = value.get("result").unwrap_or(&value);

    let block = parse_boundary_block(&value)?;
    let id = block
        .id()
        .map_err(|error| format!("calculate source block id: {error}"))?;
    let response_id = required_str(value, "id")?;
    if id.to_string() != response_id {
        return Err(format!(
            "reconstructed source block id {id} does not match response {response_id}"
        ));
    }
    if id.to_string() != manifest.source_block_id {
        return Err(format!(
            "source block id {id} does not match manifest {}",
            manifest.source_block_id
        ));
    }
    let height = block.block_num();
    if i64::from(height) != manifest.checkpoint_revision {
        return Err(format!(
            "source block height {height} does not match checkpoint revision {}",
            manifest.checkpoint_revision
        ));
    }
    manifest.source_block = Some(hex::encode(
        block
            .pack()
            .map_err(|error| format!("pack source block: {error}"))?,
    ));
    // The halt ceremony signs the freeze over the boundary block: the new
    // network verifies this commitment against the old schedule before it
    // promotes the checkpoint.
    if let Some(wif) = halt_key {
        let signing = K1PrivateKey::from_string(wif)
            .map_err(|error| format!("halt key invalid: {error:?}"))?;
        let producer_key = signing.public_key().to_string();
        let digest = HaltCommitment::digest(height, &id.0.0);
        manifest.halt_commitment = Some(HaltCommitment {
            version: HaltCommitment::VERSION,
            halt_height: height,
            halt_block_id: hex::encode(id.as_bytes()),
            checkpoint_sha256: None,
            producer_keys: vec![producer_key.clone()],
            signatures: vec![HaltSignature {
                producer: block.signed_block_header.header.producer.to_string(),
                key: producer_key,
                signature: signing.sign(&digest).to_string(),
            }],
        });
    }
    // Version 2 binds the checkpoint hash into the signed digest so the
    // commitment cannot be replayed onto another export of the same block.
    if let Some(wif) = halt_key_v2 {
        let signing = K1PrivateKey::from_string(wif)
            .map_err(|error| format!("halt key invalid: {error:?}"))?;
        let producer_key = signing.public_key().to_string();
        let checkpoint: [u8; 32] = hex::decode(&manifest.checkpoint_sha256)
            .map_err(|error| format!("manifest checkpoint hash invalid: {error}"))?
            .try_into()
            .map_err(|_| "manifest checkpoint hash has the wrong length".to_string())?;
        let digest = HaltCommitment::digest_v2(height, &id.0.0, &checkpoint);
        manifest.halt_commitment = Some(HaltCommitment {
            version: HaltCommitment::VERSION_V2,
            halt_height: height,
            halt_block_id: hex::encode(id.as_bytes()),
            checkpoint_sha256: Some(manifest.checkpoint_sha256.clone()),
            producer_keys: vec![producer_key.clone()],
            signatures: vec![HaltSignature {
                producer: block.signed_block_header.header.producer.to_string(),
                key: producer_key,
                signature: signing.sign(&digest).to_string(),
            }],
        });
    }
    // The two-step cutover pair: the declaration commits the source
    // schedule to this exact terminal block before it exists, the
    // confirmation chains the checkpoint and the successor chain id to it.
    // The transport roster mirrors the declared set; an explicit
    // --halt-roster must agree with it instead of replacing it.
    if let (Some(declaration_path), Some(confirmation_path)) = (declaration_path, confirmation_path)
    {
        let declaration: HaltDeclaration = serde_json::from_slice(
            &fs::read(declaration_path)
                .map_err(|error| format!("read declaration {declaration_path}: {error}"))?,
        )
        .map_err(|error| format!("parse declaration {declaration_path}: {error}"))?;
        let confirmation: HaltConfirmation = serde_json::from_slice(
            &fs::read(confirmation_path)
                .map_err(|error| format!("read confirmation {confirmation_path}: {error}"))?,
        )
        .map_err(|error| format!("parse confirmation {confirmation_path}: {error}"))?;
        let declaration_digest = declaration
            .digest()
            .map_err(|error| format!("declaration digest: {error}"))?;
        if confirmation.declaration_digest != hex::encode(declaration_digest) {
            return Err("confirmation does not chain the attached declaration".into());
        }
        if declaration.last_height != height || confirmation.halt_height != height {
            return Err(format!(
                "cutover pair height does not match source block height {height}"
            ));
        }
        if confirmation.halt_block_id != id.to_string() {
            return Err("confirmation block id does not match the source block".into());
        }
        if confirmation.checkpoint_sha256 != manifest.checkpoint_sha256 {
            return Err("confirmation checkpoint does not match the manifest checkpoint".into());
        }
        let declared_roster: Vec<MigrationHaltRosterEntry> = declaration
            .validator_set
            .iter()
            .map(|member| MigrationHaltRosterEntry {
                producer: member.producer.clone(),
                key: member.key.clone(),
                weight: member.weight,
            })
            .collect();
        if let Some(roster_path) = halt_roster {
            let bytes = fs::read(roster_path)
                .map_err(|error| format!("read roster {roster_path}: {error}"))?;
            let roster: Vec<MigrationHaltRosterEntry> = serde_json::from_slice(&bytes)
                .map_err(|error| format!("parse roster {roster_path}: {error}"))?;
            if roster != declared_roster {
                return Err(format!(
                    "roster {roster_path} does not match the declared validator set"
                ));
            }
            manifest = manifest.with_halt_roster(roster);
        } else {
            manifest = manifest.with_halt_roster(declared_roster);
        }
        manifest.halt_declaration = Some(declaration);
        manifest.halt_confirmation = Some(confirmation);
        manifest.halt_declaration_inclusion = timing.declaration_inclusion;
        manifest.halt_confirmation_inclusion = timing.confirmation_inclusion;
        manifest.halt_max_declaration_lag = timing.max_declaration_lag;
        manifest.halt_max_confirmation_lag = timing.max_confirmation_lag;
        if let Some(fragment_path) = timing.contract_ceremony {
            let bytes = fs::read(&fragment_path)
                .map_err(|error| format!("read contract ceremony {fragment_path}: {error}"))?;
            let ceremony: pulsevm_database::HaltContractCeremony =
                serde_json::from_slice(&bytes)
                    .map_err(|error| format!("parse contract ceremony {fragment_path}: {error}"))?;
            let ceremony_digest = hex::decode(&ceremony.declaration_digest)
                .map_err(|error| format!("contract ceremony digest invalid: {error}"))?;
            if ceremony_digest.as_slice() != declaration_digest {
                return Err(
                    "contract ceremony digest does not match the attached declaration".into(),
                );
            }
            manifest.halt_contract_ceremony = Some(ceremony);
        }
        manifest.halt_schedule_version = timing.schedule_version;
        manifest.halt_proposed_schedule = timing.proposed_schedule;
        // Fail fast at record time with provenance errors; the restore gate
        // re-verifies the same rule from the manifest.
        pulsevm_database::check_halt_inclusion_window(
            height,
            manifest.halt_declaration_inclusion,
            manifest.halt_max_declaration_lag,
            manifest.halt_confirmation_inclusion,
            manifest.halt_max_confirmation_lag,
        )
        .map_err(|error| format!("cutover vote timing rejected: {error}"))?;
    } else if let Some(roster_path) = halt_roster {
        // A weighted roster moves the restore from the single-key path to the
        // two-thirds quorum path (version 1 and 2 commitments alike).
        let bytes =
            fs::read(roster_path).map_err(|error| format!("read roster {roster_path}: {error}"))?;
        let roster: Vec<MigrationHaltRosterEntry> = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse roster {roster_path}: {error}"))?;
        if roster.is_empty() {
            return Err(format!("roster {roster_path} carries no entries"));
        }
        manifest = manifest.with_halt_roster(roster);
    }
    // The frozen active schedule and the post-H emptiness proof are recorded
    // after the pair/roster so a declared set is already in place to sign
    // against; both are authenticated at record time and re-verified by the
    // restore gate straight from the manifest.
    let halt_version = block.signed_block_header.header.schedule_version;
    if let Some(schedule_path) = schedule_path {
        let bytes = fs::read(schedule_path)
            .map_err(|error| format!("read schedule {schedule_path}: {error}"))?;
        let schedule: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse schedule {schedule_path}: {error}"))?;
        let entries = record_halt_schedule(&mut manifest, &schedule, schedule_path, halt_version)?;
        eprintln!("recorded halt schedule from {schedule_path}: {entries} producers");
    }
    if !post_block_paths.is_empty() {
        if post_block_paths.len() != post_state_paths.len() {
            return Err(format!(
                "post-H evidence needs one --post-state per --post-block: {} blocks but {} states",
                post_block_paths.len(),
                post_state_paths.len()
            ));
        }
        let mut documents = Vec::with_capacity(post_block_paths.len());
        for post_path in post_block_paths {
            let bytes = fs::read(post_path)
                .map_err(|error| format!("read post-H block {post_path}: {error}"))?;
            let document: Value = serde_json::from_slice(&bytes)
                .map_err(|error| format!("parse post-H block {post_path}: {error}"))?;
            documents.push((post_path.as_str(), document));
        }
        let mut state_documents = Vec::with_capacity(post_state_paths.len());
        for state_path in post_state_paths {
            let bytes = fs::read(state_path)
                .map_err(|error| format!("read post-H header state {state_path}: {error}"))?;
            let document: Value = serde_json::from_slice(&bytes)
                .map_err(|error| format!("parse post-H header state {state_path}: {error}"))?;
            state_documents.push((state_path.as_str(), document));
        }
        let responses: Vec<(&str, &Value)> = documents
            .iter()
            .map(|(path, document)| (*path, document))
            .collect();
        let states: Vec<(&str, &Value)> = state_documents
            .iter()
            .map(|(path, document)| (*path, document))
            .collect();
        let count = record_post_blocks(
            &mut manifest,
            &id,
            height,
            halt_version,
            &responses,
            &states,
        )?;
        eprintln!("recorded {count} post-H headers anchored at {id}");
        if let Some(sidecar_path) = deferred_sidecar_path {
            check_deferred_inventory(&value, &responses, sidecar_path)?;
        }
    } else if let Some(sidecar_path) = deferred_sidecar_path {
        if !post_state_paths.is_empty() {
            return Err("--post-state without --post-block stages no evidence".to_string());
        }
        // The pause landed exactly on H: the window is the H instant
        // itself, and only a row due exactly then fails.
        check_deferred_inventory(&value, &[], sidecar_path)?;
    } else if !post_state_paths.is_empty() {
        return Err("--post-state without --post-block stages no evidence".to_string());
    }
    let bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serialize manifest: {error}"))?;
    let temporary = output_path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, bytes).map_err(|error| format!("write temporary manifest: {error}"))?;
    fs::rename(&temporary, output_path).map_err(|error| format!("publish manifest: {error}"))?;
    Ok((height, id))
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("source block field {field} is missing or not a string"))
}
