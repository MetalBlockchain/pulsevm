//! Independently audit the chainbase fields omitted by SHiP's public row
//! projection. The source sidecar is compared with the nodeos full-state log;
//! this catches stale RPC queries, missing code objects, and refcount drift.
//!
//! Usage:
//! xpr_code_object_audit <nodeos-chain-state-history.log> <deferred-sidecar.json>

use std::{
    collections::{
        BTreeMap,
        BTreeSet,
    },
    env,
    fs,
    process::ExitCode,
};

use pulsevm_database::{
    DeferredTransactionSidecar,
    parse_initial_state_history_log,
};
use sha2::{
    Digest,
    Sha256,
};

fn usage() {
    eprintln!("Usage: xpr_code_object_audit <nodeos-log> <deferred-sidecar.json>");
}

fn uvar(bytes: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = *bytes
            .get(*pos)
            .ok_or_else(|| "truncated varuint".to_owned())?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err("varuint overflows u64".into());
        }
    }
}

fn take<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], String> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| "field length overflows".to_owned())?;
    let value = bytes
        .get(*pos..end)
        .ok_or_else(|| "truncated row field".to_owned())?;
    *pos = end;
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CodeKey {
    hash: [u8; 32],
    vm_type: u8,
    vm_version: u8,
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(log_path) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let Some(sidecar_path) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        usage();
        return ExitCode::from(2);
    }

    let log = match fs::read(&log_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read nodeos log: {error}");
            return ExitCode::from(1);
        }
    };
    let entry = match parse_initial_state_history_log(&log) {
        Ok(entry) => entry,
        Err(error) => {
            eprintln!("cannot parse nodeos full-state record: {error}");
            return ExitCode::from(1);
        }
    };
    let sidecar_bytes = match fs::read(&sidecar_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read sidecar: {error}");
            return ExitCode::from(1);
        }
    };
    let sidecar = match DeferredTransactionSidecar::from_json_bytes(&sidecar_bytes) {
        Ok(sidecar) => sidecar,
        Err(error) => {
            eprintln!("cannot parse sidecar: {error}");
            return ExitCode::from(1);
        }
    };
    let block_id = hex::encode(entry.block_id);
    if sidecar.source_block_id != block_id {
        eprintln!(
            "sidecar source_block_id {} does not match nodeos {}",
            sidecar.source_block_id, block_id
        );
        return ExitCode::from(1);
    }
    if let Some(chain_id) = &sidecar.source_chain_id {
        if chain_id.len() != 64 || hex::decode(chain_id).is_err() {
            eprintln!("sidecar source_chain_id is not 32-byte hexadecimal");
            return ExitCode::from(1);
        }
    } else {
        eprintln!("sidecar is missing source_chain_id");
        return ExitCode::from(1);
    }

    let mut codes = BTreeMap::<CodeKey, Vec<u8>>::new();
    let mut metadata_names = BTreeSet::new();
    let mut metadata_refs = BTreeMap::<CodeKey, u64>::new();
    let mut permission_names = BTreeSet::new();
    let mut generated = BTreeSet::<[u8; 32]>::new();
    for delta in &entry.deltas {
        for row in &delta.rows {
            if !row.present {
                eprintln!("full-state row {} is marked removed", delta.name);
                return ExitCode::from(1);
            }
            let mut pos = 0;
            let result = match delta.name.as_str() {
                "code" => uvar(&row.data, &mut pos).and_then(|_| {
                    let vm_type = *take(&row.data, &mut pos, 1)?.first().unwrap();
                    let vm_version = *take(&row.data, &mut pos, 1)?.first().unwrap();
                    let hash: [u8; 32] = take(&row.data, &mut pos, 32)?.try_into().unwrap();
                    let len = uvar(&row.data, &mut pos)? as usize;
                    let code = take(&row.data, &mut pos, len)?.to_vec();
                    if pos != row.data.len() {
                        return Err("code row has trailing bytes".into());
                    }
                    let computed_hash: [u8; 32] = Sha256::digest(&code).into();
                    if computed_hash != hash {
                        return Err("code hash does not match code bytes".into());
                    }
                    let key = CodeKey {
                        hash,
                        vm_type,
                        vm_version,
                    };
                    if codes.insert(key, code).is_some() {
                        return Err("duplicate code object".into());
                    }
                    Ok(())
                }),
                "account_metadata" => uvar(&row.data, &mut pos).and_then(|_| {
                    let name =
                        u64::from_le_bytes(take(&row.data, &mut pos, 8)?.try_into().unwrap());
                    metadata_names.insert(name);
                    let _privileged = take(&row.data, &mut pos, 1)?;
                    let _last_updated = take(&row.data, &mut pos, 8)?;
                    let has_code = take(&row.data, &mut pos, 1)?[0] != 0;
                    if has_code {
                        let vm_type = take(&row.data, &mut pos, 1)?[0];
                        let vm_version = take(&row.data, &mut pos, 1)?[0];
                        let hash = take(&row.data, &mut pos, 32)?.try_into().unwrap();
                        *metadata_refs
                            .entry(CodeKey {
                                hash,
                                vm_type,
                                vm_version,
                            })
                            .or_default() += 1;
                    }
                    if pos != row.data.len() {
                        return Err("account_metadata row has trailing bytes".into());
                    }
                    Ok(())
                }),
                "permission" => uvar(&row.data, &mut pos).and_then(|_| {
                    let owner =
                        u64::from_le_bytes(take(&row.data, &mut pos, 8)?.try_into().unwrap());
                    let name =
                        u64::from_le_bytes(take(&row.data, &mut pos, 8)?.try_into().unwrap());
                    permission_names.insert((owner, name));
                    Ok(())
                }),
                "generated_transaction" => uvar(&row.data, &mut pos).and_then(|_| {
                    let _sender = take(&row.data, &mut pos, 8)?;
                    let _sender_id = take(&row.data, &mut pos, 16)?;
                    let _payer = take(&row.data, &mut pos, 8)?;
                    let trx_id: [u8; 32] = take(&row.data, &mut pos, 32)?.try_into().unwrap();
                    generated.insert(trx_id);
                    Ok(())
                }),
                _ => Ok(()),
            };
            if let Err(error) = result {
                eprintln!("{} row decode failed: {error}", delta.name);
                return ExitCode::from(1);
            }
        }
    }

    let mut sidecar_codes = BTreeMap::new();
    for row in &sidecar.code {
        let hash = match hex::decode(&row.code_hash) {
            Ok(bytes) if bytes.len() == 32 => <[u8; 32]>::try_from(bytes).unwrap(),
            _ => {
                eprintln!("invalid code hash in sidecar: {}", row.code_hash);
                return ExitCode::from(1);
            }
        };
        let key = CodeKey {
            hash,
            vm_type: row.vm_type,
            vm_version: row.vm_version,
        };
        if sidecar_codes.insert(key, row).is_some() {
            eprintln!("duplicate code sidecar row");
            return ExitCode::from(1);
        }
        if row.first_block_used > u32::from_be_bytes(entry.block_id[..4].try_into().unwrap()) {
            eprintln!("invalid first_block_used for {}", row.code_hash);
            return ExitCode::from(1);
        }
    }
    if sidecar_codes.keys().collect::<BTreeSet<_>>() != codes.keys().collect::<BTreeSet<_>>() {
        eprintln!("code-object sidecar keys do not exactly match nodeos code table");
        return ExitCode::from(1);
    }
    for (key, refs) in &metadata_refs {
        let Some(row) = sidecar_codes.get(key) else {
            eprintln!("account metadata references missing code object");
            return ExitCode::from(1);
        };
        if row.code_ref_count != *refs {
            eprintln!("code refcount mismatch for {}", row.code_hash);
            return ExitCode::from(1);
        }
    }
    let sidecar_names = sidecar
        .account_metadata
        .iter()
        .map(|row| row.name)
        .collect::<BTreeSet<_>>();
    if sidecar_names != metadata_names {
        eprintln!("account_metadata sidecar names do not match nodeos");
        return ExitCode::from(1);
    }
    let sidecar_permissions = sidecar
        .permissions
        .iter()
        .map(|row| (row.owner, row.name))
        .collect::<BTreeSet<_>>();
    if sidecar_permissions != permission_names {
        eprintln!("permission sidecar keys do not match nodeos");
        return ExitCode::from(1);
    }
    let sidecar_transactions = sidecar
        .transactions
        .iter()
        .map(|row| match hex::decode(&row.trx_id) {
            Ok(bytes) if bytes.len() == 32 => Ok(<[u8; 32]>::try_from(bytes).unwrap()),
            _ => Err(()),
        })
        .collect::<Result<BTreeSet<_>, _>>();
    let Ok(sidecar_transactions) = sidecar_transactions else {
        eprintln!("invalid deferred transaction id");
        return ExitCode::from(1);
    };
    if sidecar_transactions != generated {
        eprintln!("deferred sidecar transactions do not match nodeos");
        return ExitCode::from(1);
    }
    println!(
        "code-object audit passed: code={} metadata={} permissions={} deferred={}",
        codes.len(),
        metadata_names.len(),
        permission_names.len(),
        generated.len()
    );
    ExitCode::SUCCESS
}
