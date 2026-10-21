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
    collections::VecDeque,
    env,
    fs,
    path::Path,
    process::ExitCode,
    str::FromStr,
};

use chrono::NaiveDateTime;
use pulsevm_core::{
    block::{
        BlockHeader,
        SignedBlock,
        SignedBlockHeader,
    },
    crypto::Signature,
    id::Id,
    name::Name,
};
use pulsevm_crypto::{
    Digest,
    K1PrivateKey,
};
use pulsevm_database::{
    BlockTimestamp,
    HaltCommitment,
    HaltConfirmation,
    HaltDeclaration,
    HaltSignature,
    MigrationHaltRosterEntry,
    MigrationManifest,
};
use pulsevm_serialization::Write;
use serde_json::Value;

fn usage() {
    eprintln!(
        "Usage: xpr_attach_source_block <manifest.json> <get-block.json> <output-manifest.json> [--halt-key <wif>] [--halt-key-v2 <wif>] [--halt-roster <roster.json>] [--declaration <declaration.json> --confirmation <confirmation.json> [--declaration-inclusion <height>] [--confirmation-inclusion <height>] [--max-declaration-lag <K>] [--max-confirmation-lag <J>] [--contract-ceremony <fragment.json> --schedule-version <n>]]"
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
}

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

    let transactions = value
        .get("transactions")
        .and_then(Value::as_array)
        .ok_or_else(|| "source block has no transactions array".to_string())?;
    if !transactions.is_empty() {
        return Err("source block is not empty; select an empty snapshot boundary".into());
    }
    if value
        .get("new_producers")
        .is_some_and(|new_producers| !new_producers.is_null())
    {
        return Err("source block carries a producer schedule change".into());
    }
    let block_extensions = value.get("block_extensions");
    if block_extensions.is_some_and(|extensions| {
        !extensions.is_null() && extensions.as_array().is_none_or(|items| !items.is_empty())
    }) {
        return Err("source block carries unsupported block extensions".into());
    }

    let header_extensions = parse_extensions(value.get("header_extensions"))?;
    let block = SignedBlock {
        signed_block_header: SignedBlockHeader {
            header: BlockHeader {
                timestamp: BlockTimestamp::new(parse_slot(required_str(value, "timestamp")?)?),
                producer: Name::from_str(required_str(value, "producer")?)
                    .map_err(|error| format!("producer: {error}"))?,
                confirmed: required_u64(value, "confirmed")?
                    .try_into()
                    .map_err(|_| "confirmed does not fit u16".to_string())?,
                previous: Id::from_str(required_str(value, "previous")?)
                    .map_err(|error| format!("previous: {error}"))?,
                transaction_mroot: parse_digest(required_str(value, "transaction_mroot")?)?,
                action_mroot: parse_digest(required_str(value, "action_mroot")?)?,
                schedule_version: required_u64(value, "schedule_version")?
                    .try_into()
                    .map_err(|_| "schedule_version does not fit u32".to_string())?,
                new_producers: None,
                header_extensions,
            },
            signature: Signature::from_str(required_str(value, "producer_signature")?)
                .map_err(|error| format!("producer_signature: {error}"))?,
        },
        transactions: VecDeque::new(),
        block_extensions: Vec::new(),
    };
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

fn required_u64(value: &Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("source block field {field} is missing or not an integer"))
}

fn parse_digest(value: &str) -> Result<Digest, String> {
    let bytes =
        hex::decode(value).map_err(|error| format!("digest is not hexadecimal: {error}"))?;
    Ok(Digest(bytes.try_into().map_err(|_| {
        "digest must contain exactly 32 bytes".to_string()
    })?))
}

fn parse_extensions(value: Option<&Value>) -> Result<Vec<(u16, Vec<u8>)>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let entries = value
        .as_array()
        .ok_or_else(|| "header_extensions is not an array".to_string())?;
    entries
        .iter()
        .map(|entry| {
            let pair = entry
                .as_array()
                .filter(|pair| pair.len() == 2)
                .ok_or_else(|| "header extension is not an [id, hex] pair".to_string())?;
            let id = pair[0]
                .as_u64()
                .ok_or_else(|| "header extension id is not an integer".to_string())?
                .try_into()
                .map_err(|_| "header extension id does not fit u16".to_string())?;
            let payload = pair[1]
                .as_str()
                .ok_or_else(|| "header extension payload is not a string".to_string())?;
            Ok((
                id,
                hex::decode(payload)
                    .map_err(|error| format!("header extension is not hexadecimal: {error}"))?,
            ))
        })
        .collect()
}

fn parse_slot(value: &str) -> Result<u32, String> {
    let format = if value.contains('.') {
        "%Y-%m-%dT%H:%M:%S%.f"
    } else {
        "%Y-%m-%dT%H:%M:%S"
    };
    let timestamp = NaiveDateTime::parse_from_str(value.trim_end_matches('Z'), format)
        .map_err(|error| format!("timestamp: {error}"))?;
    let epoch = chrono::NaiveDate::from_ymd_opt(2000, 1, 1)
        .expect("valid Antelope epoch")
        .and_hms_opt(0, 0, 0)
        .expect("valid Antelope epoch time");
    let milliseconds = (timestamp - epoch).num_milliseconds();
    if milliseconds < 0 || milliseconds % 500 != 0 {
        return Err("timestamp is before the Antelope epoch or not slot-aligned".into());
    }
    (milliseconds / 500)
        .try_into()
        .map_err(|_| "timestamp slot does not fit u32".to_string())
}
