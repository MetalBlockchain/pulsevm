//! Attach an id-exact XPR checkpoint-boundary block to a migration manifest.
//!
//! The source JSON is the response from `v1/chain/get_block`. Snapshot
//! boundaries with transactions or schedule changes are deliberately rejected;
//! choose an empty boundary block so the migration anchor can be independently
//! reconstructed and checked without trusting pruned transaction JSON.

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
use pulsevm_crypto::Digest;
use pulsevm_database::{
    BlockTimestamp,
    MigrationManifest,
};
use pulsevm_serialization::Write;
use serde_json::Value;

fn usage() {
    eprintln!(
        "Usage: xpr_attach_source_block <manifest.json> <get-block.json> <output-manifest.json>"
    );
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let (Some(manifest), Some(block), Some(output)) = (args.next(), args.next(), args.next())
    else {
        usage();
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        usage();
        return ExitCode::from(2);
    }
    match attach(Path::new(&manifest), Path::new(&block), Path::new(&output)) {
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

fn attach(
    manifest_path: &Path,
    block_path: &Path,
    output_path: &Path,
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
