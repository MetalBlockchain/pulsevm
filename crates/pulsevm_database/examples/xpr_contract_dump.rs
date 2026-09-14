//! Extract deployed contract artifacts directly from an Arena checkpoint.
//!
//! This deliberately opens only the state database. Unlike the full replay
//! controller it does not scan accepted block history, so it is suitable for
//! inspecting large migration checkpoints while another replay is stopped.

use std::{
    env,
    fs,
    io,
    path::PathBuf,
    str::FromStr,
};

use pulsevm_database::Database;
use pulsevm_name::Name;
use sha2::{
    Digest,
    Sha256,
};

fn usage(program: &str) {
    eprintln!("Usage: {program} <arena-dir> <output-dir> <account> [account ...]");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "xpr_contract_dump".into());
    let Some(arena_dir) = args.next() else {
        usage(&program);
        return Err("missing arena directory".into());
    };
    let Some(output_dir) = args.next() else {
        usage(&program);
        return Err("missing output directory".into());
    };
    let accounts: Vec<String> = args.collect();
    if accounts.is_empty() {
        usage(&program);
        return Err("at least one account is required".into());
    }

    let database = Database::new(&arena_dir, 0).map_err(io::Error::other)?;
    let output_dir = PathBuf::from(output_dir);
    fs::create_dir_all(&output_dir)?;
    println!(
        "revision={} state_root={}",
        database.revision(),
        database
            .arena_state_root()
            .map(hex::encode)
            .unwrap_or_else(|| "unavailable".into())
    );

    if let Some(path) = env::var_os("XPR_DUMP_SHIP_SNAPSHOT") {
        let bytes = database.pack_deltas(true, &[0; 32]);
        fs::write(&path, &bytes)?;
        println!(
            "ship_snapshot bytes={} sha256={} output={}",
            bytes.len(),
            hex::encode(Sha256::digest(&bytes)),
            PathBuf::from(path).display(),
        );
    }

    if let Ok(spec) = env::var("XPR_DUMP_ROW") {
        let names = spec
            .split(',')
            .map(str::trim)
            .map(Name::from_str)
            .collect::<Result<Vec<_>, _>>()?;
        if names.len() != 4 {
            return Err("XPR_DUMP_ROW must be code,scope,table,primary".into());
        }
        let value = database
            .arena_kv_get(
                names[0].as_u64(),
                names[1].as_u64(),
                names[2].as_u64(),
                names[3].as_u64(),
            )
            .ok_or("requested contract row is absent")?;
        println!(
            "row code={} scope={} table={} primary={} bytes={} hex={}",
            names[0],
            names[1],
            names[2],
            names[3],
            value.len(),
            hex::encode(value)
        );
        return Ok(());
    }
    if let Ok(spec) = env::var("XPR_DUMP_TABLE") {
        let names = spec
            .split(',')
            .map(str::trim)
            .map(Name::from_str)
            .collect::<Result<Vec<_>, _>>()?;
        if names.len() != 3 {
            return Err("XPR_DUMP_TABLE must be code,scope,table".into());
        }
        let (code, scope, table) = (names[0].as_u64(), names[1].as_u64(), names[2].as_u64());
        let mut primary = database.arena_kv_lower_bound(code, scope, table, 0);
        while let Some(key) = primary {
            let value = database
                .arena_kv_get(code, scope, table, key)
                .ok_or("table iterator returned an absent row")?;
            println!(
                "row primary={key} bytes={} hex={}",
                value.len(),
                hex::encode(value)
            );
            primary = database.arena_kv_upper_bound(code, scope, table, key);
        }
        return Ok(());
    }
    if env::var_os("XPR_DUMP_SKIP_STATE_TABLES").is_none() {
        for (table, bytes) in database.arena_state_table_bytes() {
            fs::write(output_dir.join(format!("state-{table}.bin")), &bytes)?;
            println!(
                "table={table} bytes={} sha256={}",
                bytes.len(),
                hex::encode(Sha256::digest(&bytes))
            );
        }
    }

    for account_text in accounts {
        let account = Name::from_str(&account_text)?;
        let (code_hash, vm_type, vm_version) = database.account_code_hash_vm(account.as_u64())?;
        let code = database.get_code_bytes_by_hash(&code_hash, vm_type, vm_version)?;
        let abi = database
            .arena_account_abi_bytes(account.as_u64())
            .ok_or_else(|| io::Error::other(format!("account {account} has no ABI row")))?;

        let wasm_path = output_dir.join(format!("{account}.wasm"));
        let abi_path = output_dir.join(format!("{account}.abi.bin"));
        fs::write(&wasm_path, &code)?;
        fs::write(&abi_path, &abi)?;
        println!(
            "account={account} code_hash={} vm_type={vm_type} vm_version={vm_version} wasm_bytes={} abi_bytes={} wasm={} abi={}",
            hex::encode(code_hash),
            code.len(),
            abi.len(),
            wasm_path.display(),
            abi_path.display()
        );
    }

    Ok(())
}
