//! Two-step cutover ceremony: declare the last block, then confirm it.
//!
//! Step one (`declare`) runs K blocks before the cutover, while block H is
//! still in the future: the source schedule signs that H is the last block
//! its validator set will author on the source chain id. The declaration's
//! digest is what the operators record on the source chain (a memo
//! transaction) before H arrives.
//!
//! Step two (`confirm`) runs once block H exists: the same quorum chains the
//! verified declaration to the terminal block id, the migration checkpoint,
//! and the successor chain id. The migration manifest carries both, and the
//! restore verifies the pair before promoting the checkpoint.
//!
//! Quorum is two thirds of the declared set's weight for both steps; each
//! `--key` must belong to the declared set or the tool refuses to sign.

use std::{
    env,
    fs,
    path::Path,
    process::ExitCode,
};

use pulsevm_crypto::K1PrivateKey;
use pulsevm_database::{
    HaltConfirmation,
    HaltDeclaration,
    HaltDeclarationMember,
    HaltSignature,
    MigrationHaltRosterEntry,
};

fn usage() {
    eprintln!(
        "Usage: xpr_halt_ceremony declare --height H --source-chain HEX --roster roster.json --key WIF [--key WIF...] --out declaration.json"
    );
    eprintln!(
        "       xpr_halt_ceremony confirm --declaration declaration.json --height H --pause-height P --block-id HEX --checkpoint HEX --genesis migration-genesis.json --platform-chain-id HEX-or-base58 --key WIF [--key WIF...] [--pause-height P...] --out confirmation.json"
    );
    eprintln!(
        "  --pause-height is each signer's observed frozen head (repeat once per --key, or pass once"
    );
    eprintln!(
        "  for all keys of one operator): all signers must attest the same head — a frozen network"
    );
    eprintln!(
        "  observes one head, so disagreement means the network is not frozen and the tool refuses."
    );
    eprintln!("  The successor chain id is derived from the migration genesis (the same");
    eprintln!("  bytes the new network boots from), never typed by hand.");
    eprintln!("  --platform-chain-id (the MetalGo blockchain id wallets sign under) is bound");
    eprintln!("  into the confirmation digest; the restore gate fails closed without it.");
    eprintln!("       xpr_halt_ceremony chain-id --genesis migration-genesis.json");
    eprintln!("  Prints the genesis-derived successor chain id (the rehearsal platform id).");
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(command) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let result = if command == "declare" {
        let request = DeclareRequest::parse(args);
        request.and_then(|request| declare(&request))
    } else if command == "confirm" {
        let request = ConfirmRequest::parse(args);
        request.and_then(|request| confirm(&request))
    } else if command == "chain-id" {
        let mut genesis = None;
        while let Some(arg) = args.next() {
            if arg == "--genesis" {
                genesis = args
                    .next()
                    .map(|value| value.to_string_lossy().into_owned());
            } else {
                usage();
                return ExitCode::from(2);
            }
        }
        let Some(genesis) = genesis else {
            usage();
            return ExitCode::from(2);
        };
        successor_chain_id(&genesis)
    } else {
        usage();
        return ExitCode::from(2);
    };
    match result {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("xpr_halt_ceremony: {error}");
            ExitCode::from(1)
        }
    }
}

struct DeclareRequest {
    height: u32,
    source_chain: String,
    roster: String,
    keys: Vec<String>,
    out: String,
}

struct ConfirmRequest {
    declaration: String,
    height: u32,
    pause_heads: Vec<u32>,
    block_id: String,
    checkpoint: String,
    genesis: String,
    platform_chain_id: String,
    keys: Vec<String>,
    out: String,
}

fn take_value(args: &mut env::ArgsOs, flag: &str) -> Result<String, String> {
    args.next()
        .map(|value| value.to_string_lossy().into_owned())
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn parse_height(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("height {value} is not a positive integer"))
}

impl DeclareRequest {
    fn parse(mut args: env::ArgsOs) -> Result<Self, String> {
        let mut height = None;
        let mut source_chain = None;
        let mut roster = None;
        let mut keys = Vec::new();
        let mut out = None;
        while let Some(arg) = args.next() {
            if arg == "--height" {
                height = Some(parse_height(&take_value(&mut args, "--height")?)?);
            } else if arg == "--source-chain" {
                source_chain = Some(take_value(&mut args, "--source-chain")?);
            } else if arg == "--roster" {
                roster = Some(take_value(&mut args, "--roster")?);
            } else if arg == "--key" {
                keys.push(take_value(&mut args, "--key")?);
            } else if arg == "--out" {
                out = Some(take_value(&mut args, "--out")?);
            } else {
                return Err(format!("unknown declare flag {}", arg.to_string_lossy()));
            }
        }
        Ok(Self {
            height: height.ok_or_else(|| "declare needs --height".to_string())?,
            source_chain: source_chain.ok_or_else(|| "declare needs --source-chain".to_string())?,
            roster: roster.ok_or_else(|| "declare needs --roster".to_string())?,
            keys,
            out: out.ok_or_else(|| "declare needs --out".to_string())?,
        })
    }
}

impl ConfirmRequest {
    fn parse(mut args: env::ArgsOs) -> Result<Self, String> {
        let mut declaration = None;
        let mut height = None;
        let mut pause_heads = Vec::new();
        let mut block_id = None;
        let mut checkpoint = None;
        let mut genesis = None;
        let mut platform_chain_id = None;
        let mut keys = Vec::new();
        let mut out = None;
        while let Some(arg) = args.next() {
            if arg == "--declaration" {
                declaration = Some(take_value(&mut args, "--declaration")?);
            } else if arg == "--height" {
                height = Some(parse_height(&take_value(&mut args, "--height")?)?);
            } else if arg == "--pause-height" {
                pause_heads.push(parse_height(&take_value(&mut args, "--pause-height")?)?);
            } else if arg == "--block-id" {
                block_id = Some(take_value(&mut args, "--block-id")?);
            } else if arg == "--checkpoint" {
                checkpoint = Some(take_value(&mut args, "--checkpoint")?);
            } else if arg == "--genesis" {
                genesis = Some(take_value(&mut args, "--genesis")?);
            } else if arg == "--platform-chain-id" {
                platform_chain_id = Some(take_value(&mut args, "--platform-chain-id")?);
            } else if arg == "--key" {
                keys.push(take_value(&mut args, "--key")?);
            } else if arg == "--out" {
                out = Some(take_value(&mut args, "--out")?);
            } else {
                return Err(format!("unknown confirm flag {}", arg.to_string_lossy()));
            }
        }
        if pause_heads.is_empty() {
            return Err(
                "confirm needs --pause-height: each signer's observed frozen head".to_string(),
            );
        }
        Ok(Self {
            declaration: declaration.ok_or_else(|| "confirm needs --declaration".to_string())?,
            height: height.ok_or_else(|| "confirm needs --height".to_string())?,
            pause_heads,
            block_id: block_id.ok_or_else(|| "confirm needs --block-id".to_string())?,
            checkpoint: checkpoint.ok_or_else(|| "confirm needs --checkpoint".to_string())?,
            genesis: genesis.ok_or_else(|| "confirm needs --genesis".to_string())?,
            platform_chain_id: platform_chain_id
                .ok_or_else(|| "confirm needs --platform-chain-id".to_string())?,
            keys,
            out: out.ok_or_else(|| "confirm needs --out".to_string())?,
        })
    }
}

fn read_roster(path: &str) -> Result<Vec<MigrationHaltRosterEntry>, String> {
    let bytes = fs::read(path).map_err(|error| format!("read roster {path}: {error}"))?;
    let roster: Vec<MigrationHaltRosterEntry> =
        serde_json::from_slice(&bytes).map_err(|error| format!("parse roster {path}: {error}"))?;
    if roster.is_empty() {
        return Err(format!("roster {path} carries no entries"));
    }
    Ok(roster)
}

fn signing_keys(keys: &[String]) -> Result<Vec<K1PrivateKey>, String> {
    if keys.is_empty() {
        return Err("at least one --key is required to sign".into());
    }
    keys.iter()
        .map(|wif| {
            K1PrivateKey::from_string(wif)
                .map_err(|error| format!("signing key invalid: {error:?}"))
        })
        .collect::<Result<_, _>>()
}

/// Find the declared member a signing key belongs to. Keys outside the set
/// cannot sign either step of the ceremony.
fn member_for_key<'a>(
    members: &'a [HaltDeclarationMember],
    signing: &K1PrivateKey,
) -> Result<&'a HaltDeclarationMember, String> {
    let public = signing.public_key();
    members
        .iter()
        .find(|member| {
            pulsevm_crypto::k1::K1PublicKey::from_string(&member.key).is_ok_and(|key| key == public)
        })
        .ok_or_else(|| format!("signing key {} is not in the declared set", public))
}

fn write_json<T: serde::Serialize>(path: &str, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| format!("serialize: {error}"))?;
    let temporary = Path::new(path).with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, bytes).map_err(|error| format!("write temporary file: {error}"))?;
    fs::rename(&temporary, path).map_err(|error| format!("publish {path}: {error}"))?;
    Ok(())
}

fn declare(request: &DeclareRequest) -> Result<String, String> {
    let roster = read_roster(&request.roster)?;
    let mut members: Vec<HaltDeclarationMember> = roster
        .into_iter()
        .map(|entry| HaltDeclarationMember {
            producer: entry.producer,
            key: entry.key,
            weight: entry.weight,
        })
        .collect();
    HaltDeclaration::sort_members(&mut members);
    let unsigned = HaltDeclaration {
        version: HaltDeclaration::VERSION,
        source_chain_id: request.source_chain.clone(),
        last_height: request.height,
        validator_set: members,
        signatures: Vec::new(),
    };
    let digest = unsigned
        .digest()
        .map_err(|error| format!("declaration digest: {error}"))?;
    let mut signatures = Vec::new();
    for signing in signing_keys(&request.keys)? {
        let member = member_for_key(&unsigned.validator_set, &signing)?;
        signatures.push(HaltSignature {
            producer: member.producer.clone(),
            key: signing.public_key().to_string(),
            signature: signing.sign(&digest).to_string(),
        });
    }
    let declaration = HaltDeclaration {
        signatures,
        ..unsigned
    };
    // The declaration must verify on its own before it leaves the ceremony:
    // a malformed set here would only surface at restore.
    let verified = declaration
        .verify(request.height)
        .map_err(|error| format!("fresh declaration rejected: {error}"))?;
    if verified != digest {
        return Err("declaration digest moved during signing".into());
    }
    write_json(&request.out, &declaration)?;
    Ok(format!(
        "declaration {} height {} signers {}",
        hex::encode(verified),
        request.height,
        declaration.signatures.len()
    ))
}

fn successor_chain_id(genesis_path: &str) -> Result<String, String> {
    let bytes = fs::read(genesis_path)
        .map_err(|error| format!("read migration genesis {genesis_path}: {error}"))?;
    let genesis = pulsevm_database::GenesisState::from_bytes(&bytes)
        .map_err(|error| format!("parse migration genesis {genesis_path}: {error}"))?;
    if genesis.migration_checkpoint_sha256.is_none() {
        return Err(format!(
            "migration genesis {genesis_path} carries no migration checkpoint binding"
        ));
    }
    Ok(hex::encode(genesis.compute_chain_id()))
}

fn confirm(request: &ConfirmRequest) -> Result<String, String> {
    let raw = fs::read(&request.declaration)
        .map_err(|error| format!("read declaration {}: {error}", request.declaration))?;
    let declaration: HaltDeclaration =
        serde_json::from_slice(&raw).map_err(|error| format!("parse declaration: {error}"))?;
    if declaration.last_height != request.height {
        return Err(format!(
            "declaration height {} does not match --height {}",
            declaration.last_height, request.height
        ));
    }
    // Refuse to confirm a declaration that does not verify on its own: the
    // confirmation would chain a quorum nobody actually reached.
    let declaration_digest = declaration
        .verify(request.height)
        .map_err(|error| format!("declaration rejected: {error}"))?;
    // Every signer attests the same frozen head: one --pause-height applies
    // to every --key of one operator, or repeat it once per key. A frozen
    // network observes one head, so signers who disagree are not looking at
    // a frozen network — the tool refuses instead of minting a quorum over
    // an unobserved tail. The unanimous head is the highest attested head
    // the restore gate requires the post-H proof to cover.
    let pause_height = if request.pause_heads.len() == 1 {
        request.pause_heads[0]
    } else {
        if request.pause_heads.len() != request.keys.len() {
            return Err(format!(
                "got {} --pause-height values for {} --key values: pass one head for all keys, or one per key",
                request.pause_heads.len(),
                request.keys.len()
            ));
        }
        let first = request.pause_heads[0];
        if request.pause_heads.iter().any(|head| *head != first) {
            return Err(
                "signers disagree on the observed pause head: the network is not frozen, refusing to confirm"
                    .into(),
            );
        }
        first
    };
    if pause_height < request.height {
        return Err(format!(
            "observed pause head {pause_height} predates cutover height {}",
            request.height
        ));
    }
    // The successor id is derived from the migration genesis the new network
    // boots from, so the ceremony can never bind a hand-typed id.
    let new_chain_id = successor_chain_id(&request.genesis)?;
    // The platform id is the one value the tool takes on trust: it must
    // come from the ceremony config (the MetalGo blockchain id, hex or the
    // base58 log rendering), and the restore gate fails closed if it does
    // not match boot config. Stored as canonical hex either way.
    let platform_id = pulsevm_crypto::parse_chain_id(&request.platform_chain_id)
        .map_err(|error| format!("--platform-chain-id: {error}"))?;
    let platform_hex = pulsevm_crypto::chain_id_hex(&platform_id);
    // One shared library constructor builds every agent's template, so the
    // coordinator tool and the voter sign the same bytes by construction.
    let (template, digest) = HaltConfirmation::unsigned(
        &hex::encode(declaration_digest),
        request.height,
        pause_height,
        &request.block_id,
        &request.checkpoint,
        &new_chain_id,
        &platform_hex,
    )
    .map_err(|error| format!("confirmation template: {error}"))?;
    let mut signatures = Vec::new();
    for signing in signing_keys(&request.keys)? {
        let member = member_for_key(&declaration.validator_set, &signing)?;
        signatures.push(HaltSignature {
            producer: member.producer.clone(),
            key: signing.public_key().to_string(),
            signature: signing.sign(&digest).to_string(),
        });
    }
    let confirmation = HaltConfirmation {
        signatures,
        ..template
    };
    write_json(&request.out, &confirmation)?;
    Ok(format!(
        "confirmation {} height {} declaration {} new-chain {} signers {}",
        hex::encode(digest),
        request.height,
        hex::encode(declaration_digest),
        confirmation.new_chain_id,
        confirmation.signatures.len()
    ))
}
