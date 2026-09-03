//! Derive a disposable write-test checkpoint from an imported XPR checkpoint.
//!
//! This intentionally does not alter the canonical migration artifact. It
//! replaces only the selected producer account's owner/active authorities in a
//! copy so a local test key can exercise the imported chain's write path
//! without ever requiring an XPR production private key.
//!
//! Usage:
//!   xpr_test_authority <input.snapshot> <input.manifest.json> \
//!                      <output.snapshot> <PVT_K1_...> [producer_account]

use std::{
    env,
    fs,
    process::ExitCode,
    str::FromStr,
};

use pulsevm_chain_types::{
    Authority,
    TimePoint,
};
use pulsevm_crypto::{
    AuthorityPublicKey,
    Digest,
    K1PrivateKey,
};
use pulsevm_database::{
    Database,
    MigrationManifest,
};
use pulsevm_name::Name;

const DB_SIZE: u64 = 64 * 1024 * 1024;

fn usage() {
    eprintln!("Usage: xpr_test_authority <input.snapshot> <input.manifest.json> \\");
    eprintln!("                         <output.snapshot> <PVT_K1_...> [producer_account]");
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(input_path) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let Some(input_manifest_path) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let Some(output_path) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let Some(private_key) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let producer_account = args
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "pulse".to_string());
    if args.next().is_some() {
        usage();
        return ExitCode::from(2);
    }

    match derive(
        &input_path.to_string_lossy(),
        &input_manifest_path.to_string_lossy(),
        &output_path.to_string_lossy(),
        &private_key.to_string_lossy(),
        &producer_account,
    ) {
        Ok(public_key) => {
            println!(
                "wrote test-authority checkpoint: {}",
                output_path.to_string_lossy()
            );
            println!(
                "wrote test-authority manifest: {}.manifest.json",
                output_path.to_string_lossy()
            );
            println!("test authority public key: {public_key}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("cannot derive test-authority checkpoint: {error}");
            ExitCode::from(1)
        }
    }
}

fn derive(
    input_path: &str,
    input_manifest_path: &str,
    output_path: &str,
    private_key: &str,
    producer_account: &str,
) -> Result<String, String> {
    let input = fs::read(input_path).map_err(|e| format!("read checkpoint: {e}"))?;
    let manifest_bytes =
        fs::read(input_manifest_path).map_err(|e| format!("read manifest: {e}"))?;
    let mut manifest: MigrationManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| format!("parse manifest: {e}"))?;
    manifest
        .verify_checkpoint(&input)
        .map_err(|e| format!("input manifest rejected checkpoint: {e}"))?;

    let temp = tempfile::tempdir().map_err(|e| format!("create temporary database: {e}"))?;
    let mut database = Database::new(&temp.path().to_string_lossy(), DB_SIZE)
        .map_err(|e| format!("open temporary database: {e}"))?;
    database
        .restore_from_bytes(&input)
        .map_err(|e| format!("restore input checkpoint: {e}"))?;

    let key = K1PrivateKey::from_string(private_key)
        .map_err(|e| format!("parse development private key: {e}"))?;
    let public = key.public_key();
    let authority = Authority::new_from_public_key(public);
    let producer = Name::from_str(producer_account)
        .map_err(|e| format!("encode producer account {producer_account}: {e}"))?
        .as_u64();
    let owner = Name::from_str("owner")
        .map_err(|e| format!("encode owner permission: {e}"))?
        .as_u64();
    let active = Name::from_str("active")
        .map_err(|e| format!("encode active permission: {e}"))?
        .as_u64();
    if database
        .arena_permission_authority(producer, owner)
        .is_none()
        || database
            .arena_permission_authority(producer, active)
            .is_none()
    {
        return Err(format!(
            "imported checkpoint has no {producer_account}@owner/active permissions"
        ));
    }
    let now = TimePoint::now();
    database
        .modify_permission(producer, owner, &authority, &now)
        .map_err(|e| format!("replace {producer_account}@owner authority: {e}"))?;
    database
        .modify_permission(producer, active, &authority, &now)
        .map_err(|e| format!("replace {producer_account}@active authority: {e}"))?;
    for (name, permission) in [("owner", owner), ("active", active)] {
        let Some(updated) = database.arena_permission_authority(producer, permission) else {
            return Err(format!(
                "updated {producer_account}@{name} authority is missing"
            ));
        };
        if updated != authority {
            return Err(format!(
                "updated {producer_account}@{name} authority did not match test key"
            ));
        }
    }

    let output = database
        .snapshot_bytes()
        .map_err(|e| format!("serialize derived checkpoint: {e}"))?;
    fs::write(output_path, &output).map_err(|e| format!("write derived checkpoint: {e}"))?;

    manifest.checkpoint_sha256 = hex::encode(Digest::hash(&output).as_bytes());
    manifest.checkpoint_revision = pulsevm_database::peek_snapshot_header(&output)
        .map_err(|e| format!("read derived checkpoint header: {e}"))?
        .revision;
    let manifest_output = format!("{output_path}.manifest.json");
    let manifest_json = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| format!("serialize derived manifest: {e}"))?;
    fs::write(&manifest_output, manifest_json)
        .map_err(|e| format!("write derived manifest: {e}"))?;
    manifest
        .verify_checkpoint(&output)
        .map_err(|e| format!("verify derived manifest: {e}"))?;

    Ok(AuthorityPublicKey::from(public).to_string())
}
