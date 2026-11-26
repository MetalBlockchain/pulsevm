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
        "Usage: xpr_halt_ceremony declare --height H --source-chain HEX --roster roster.json [--contract ACCOUNT] (--key-file PATH | --key WIF)... --out declaration.json"
    );
    eprintln!(
        "       xpr_halt_ceremony confirm --declaration declaration.json --height H --pause-height P --pause-block-id HEX --block-id HEX --checkpoint HEX --genesis migration-genesis.json --platform-chain-id HEX-or-base58 (--key-file PATH | --key WIF)... [--pause-height P...] --out confirmation.json"
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
    /// Account of the on-chain ceremony contract, for contract-vehicle
    /// declarations: bound into the digest the BPs sign. Unset for the memo
    /// vehicle.
    contract: Option<String>,
    keys: Vec<String>,
    out: String,
}

struct ConfirmRequest {
    declaration: String,
    height: u32,
    pause_heads: Vec<u32>,
    /// Id of block P itself: the quorum attests one specific branch.
    pause_block_id: String,
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

/// Read one private key from a file only its owner can read. The file holds the
/// key and a newline; anything readable by group or others is refused, as the
/// voter refuses it, so a key is never exposed through the process list or a
/// permissive file.
fn read_key_file(path: &str) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|error| format!("read key file {path}: {error}"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "key file {path} is readable by group or others (mode {:o}): chmod 600 it",
                mode & 0o777
            ));
        }
    }
    let text =
        fs::read_to_string(path).map_err(|error| format!("read key file {path}: {error}"))?;
    let key = text.trim();
    if key.is_empty() {
        return Err(format!("key file {path} is empty"));
    }
    Ok(key.to_owned())
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
        let mut contract = None;
        let mut keys = Vec::new();
        let mut out = None;
        while let Some(arg) = args.next() {
            if arg == "--height" {
                height = Some(parse_height(&take_value(&mut args, "--height")?)?);
            } else if arg == "--source-chain" {
                source_chain = Some(take_value(&mut args, "--source-chain")?);
            } else if arg == "--roster" {
                roster = Some(take_value(&mut args, "--roster")?);
            } else if arg == "--contract" {
                contract = Some(take_value(&mut args, "--contract")?);
            } else if arg == "--key" {
                // A key on the command line is visible to every user of the host
                // in the process list, and stays in shell history.
                eprintln!(
                    "WARNING: --key puts a private key on the command line (visible in `ps` and shell history); use --key-file with an owner-only file"
                );
                keys.push(take_value(&mut args, "--key")?);
            } else if arg == "--key-file" {
                keys.push(read_key_file(&take_value(&mut args, "--key-file")?)?);
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
            contract,
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
        let mut pause_block_id = None;
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
            } else if arg == "--pause-block-id" {
                pause_block_id = Some(take_value(&mut args, "--pause-block-id")?);
            } else if arg == "--block-id" {
                block_id = Some(take_value(&mut args, "--block-id")?);
            } else if arg == "--checkpoint" {
                checkpoint = Some(take_value(&mut args, "--checkpoint")?);
            } else if arg == "--genesis" {
                genesis = Some(take_value(&mut args, "--genesis")?);
            } else if arg == "--platform-chain-id" {
                platform_chain_id = Some(take_value(&mut args, "--platform-chain-id")?);
            } else if arg == "--key" {
                // A key on the command line is visible to every user of the host
                // in the process list, and stays in shell history.
                eprintln!(
                    "WARNING: --key puts a private key on the command line (visible in `ps` and shell history); use --key-file with an owner-only file"
                );
                keys.push(take_value(&mut args, "--key")?);
            } else if arg == "--key-file" {
                keys.push(read_key_file(&take_value(&mut args, "--key-file")?)?);
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
            pause_block_id: pause_block_id
                .ok_or_else(|| "confirm needs --pause-block-id: the id of block P".to_string())?,
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
        ceremony_contract: request.contract.clone(),
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

fn genesis_checkpoint_pin(genesis_path: &str) -> Result<String, String> {
    let bytes = fs::read(genesis_path)
        .map_err(|error| format!("read migration genesis {genesis_path}: {error}"))?;
    let genesis = pulsevm_database::GenesisState::from_bytes(&bytes)
        .map_err(|error| format!("parse migration genesis {genesis_path}: {error}"))?;
    genesis
        .migration_checkpoint_sha256
        .map(hex::encode)
        .ok_or_else(|| format!("migration genesis {genesis_path} carries no checkpoint pin"))
}

/// Strict two-thirds of the declared weight, counted once per member: the rule
/// the restore gate applies, so a confirmation this tool writes is never one
/// that cannot reach it.
fn quorum_reached(members: &[HaltDeclarationMember], signers: &[HaltSignature]) -> bool {
    let mut total: u128 = 0;
    for member in members {
        match total.checked_add(member.weight.0) {
            Some(sum) => total = sum,
            None => return false,
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut signed: u128 = 0;
    for signature in signers {
        if let Some(member) = members.iter().find(|m| m.producer == signature.producer)
            && seen.insert(member.producer.clone())
        {
            // Bounded by `total`, which fit.
            signed += member.weight.0;
        }
    }
    match (signed.checked_mul(3), total.checked_mul(2)) {
        (Some(left), Some(right)) => total > 0 && left > right,
        _ => false,
    }
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
    Ok(hex::encode(genesis.compute_ceremony_chain_id()))
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
    // Every signer attests the agreed pause head: one --pause-height applies
    // to every --key of one operator, or repeat it once per key, but all
    // values must agree. The ceremony agrees P up front (a fixed H+k the
    // producers stop at); each signer confirms that agreed head, never its
    // own observed tip, so a quorum over 15 divergent heads is unformable
    // by construction. The agreed head is the highest attested head the
    // restore gate requires the post-H proof to cover.
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
                "signers disagree on the agreed pause head: every key must confirm the same P, refusing to confirm"
                    .into(),
            );
        }
        first
    };
    // The pause head must sit strictly past H: a pause exactly on H stages
    // no proof, so the gate (and the confirmation digest itself, which
    // binds P positionally) fails it closed.
    if pause_height <= request.height {
        return Err(format!(
            "agreed pause head {pause_height} does not sit past cutover height {}",
            request.height
        ));
    }
    // The successor id is derived from the migration genesis the new network
    // boots from, so the ceremony can never bind a hand-typed id.
    let new_chain_id = successor_chain_id(&request.genesis)?;
    // The checkpoint being confirmed must be the one the genesis pins. A mismatch
    // here is signed, written, and refused only at the restore gate, and the
    // ceremony has no retry: it is burned. Check it before anyone signs.
    let pinned = genesis_checkpoint_pin(&request.genesis)?;
    if !pinned.eq_ignore_ascii_case(request.checkpoint.trim()) {
        return Err(format!(
            "--checkpoint {} is not the checkpoint the genesis pins ({pinned}): confirming it would burn the ceremony",
            request.checkpoint
        ));
    }
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
        &request.pause_block_id,
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
    if !quorum_reached(&declaration.validator_set, &signatures) {
        return Err(format!(
            "{} signature(s) do not reach two thirds of the declared weight: refusing to write a confirmation the restore gate cannot accept",
            signatures.len()
        ));
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

#[cfg(test)]
mod tests {
    use super::{
        HaltDeclarationMember,
        HaltSignature,
        quorum_reached,
        read_key_file,
    };
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ceremony-key-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_key_file_only_its_owner_can_read_is_accepted() {
        let dir = scratch("ok");
        let path = dir.join("key");
        std::fs::write(
            &path,
            "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_key_file(path.to_str().unwrap()).unwrap(),
            "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_key_file_others_can_read_is_refused_without_reading_it() {
        let dir = scratch("open");
        let path = dir.join("key");
        std::fs::write(&path, "secret\n").unwrap();
        for mode in [0o644, 0o640, 0o604] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let error = read_key_file(path.to_str().unwrap()).unwrap_err();
            assert!(error.contains("readable by group or others"), "{error}");
            assert!(!error.contains("secret"), "the key must never be echoed");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_empty_or_missing_key_file_is_an_error() {
        let dir = scratch("empty");
        let path = dir.join("key");
        std::fs::write(&path, "  \n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            read_key_file(path.to_str().unwrap())
                .unwrap_err()
                .contains("empty")
        );
        assert!(read_key_file(dir.join("absent").to_str().unwrap()).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn member(producer: &str, weight: u128) -> HaltDeclarationMember {
        HaltDeclarationMember {
            producer: producer.to_owned(),
            key: String::new(),
            weight: pulsevm_database::HaltWeight(weight),
        }
    }

    fn signed(producer: &str) -> HaltSignature {
        HaltSignature {
            producer: producer.to_owned(),
            key: String::new(),
            signature: String::new(),
        }
    }

    // The gate's rule is a STRICT two thirds, counted once per member.
    #[test]
    fn the_quorum_is_strictly_more_than_two_thirds_counted_once_per_member() {
        let members = vec![member("a", 1), member("b", 1), member("c", 1)];
        assert!(
            !quorum_reached(&members, &[signed("a"), signed("b")]),
            "exactly two thirds is not enough"
        );
        assert!(quorum_reached(
            &members,
            &[signed("a"), signed("b"), signed("c")]
        ));
        assert!(
            !quorum_reached(&members, &[signed("a"), signed("a"), signed("a")]),
            "one member three times is one member"
        );
        assert!(
            !quorum_reached(&members, &[signed("x"), signed("y"), signed("z")]),
            "strangers do not count"
        );
        let four = vec![
            member("a", 1),
            member("b", 1),
            member("c", 1),
            member("d", 1),
        ];
        assert!(quorum_reached(
            &four,
            &[signed("a"), signed("b"), signed("c")]
        ));
        assert!(!quorum_reached(&[], &[]));
    }
}
