//! Dump the section table and a chainstate summary of a portable snapshot.
//!
//! ```sh
//! cargo run -p pulsevm_snapshot --release --example dump -- /path/to/snapshot.bin
//! ```

use pulsevm_snapshot::SnapshotReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: dump <snapshot.bin>")?;
    let bytes = std::fs::read(&path)?;
    let snapshot = SnapshotReader::new(&bytes)?;

    println!("chain snapshot version {}", snapshot.chain_version());
    println!("\n{:<58} {:>12} {:>14}", "section", "rows", "bytes");
    for s in snapshot.sections() {
        println!("{:<58} {:>12} {:>14}", s.name, s.row_count, s.len);
    }

    let head = snapshot.block_header_state()?;
    println!(
        "\nhead block {} (id {}, from-id {}), timestamp slot {}, producer {}, schedule v{} with \
         {} producers",
        head.block_num,
        head.id,
        head.block_num_from_id(),
        head.header.timestamp.slot(),
        head.header.producer,
        head.active_schedule.version,
        head.active_schedule.producers.len(),
    );

    let gpo = snapshot.global_property()?;
    println!("chain id {}", gpo.chain_id);
    println!(
        "max_block_cpu_usage {} max_transaction_cpu_usage {}",
        gpo.configuration.base.max_block_cpu_usage,
        gpo.configuration.base.max_transaction_cpu_usage
    );

    let mut accounts = 0u64;
    let mut with_abi = 0u64;
    for account in snapshot.accounts()? {
        let account = account?;
        accounts += 1;
        if !account.abi.0.is_empty() {
            with_abi += 1;
        }
    }
    println!("accounts {accounts} ({with_abi} with abi)");

    let mut with_code = 0u64;
    let mut privileged = Vec::new();
    for meta in snapshot.account_metadata()? {
        let meta = meta?;
        if meta.has_code() {
            with_code += 1;
        }
        if meta.is_privileged() {
            privileged.push(meta.name.to_string());
        }
    }
    println!("accounts with code {with_code}, privileged: {privileged:?}");

    let mut code_rows = 0u64;
    let mut code_bytes = 0usize;
    for code in snapshot.code()? {
        let code = code?;
        code_rows += 1;
        code_bytes += code.code.0.len();
    }
    println!("code objects {code_rows} ({code_bytes} wasm bytes)");

    let mut permissions = 0u64;
    let mut key_kinds = [0u64; 3];
    for permission in snapshot.permissions()? {
        let permission = permission?;
        permissions += 1;
        for kw in &permission.auth.keys {
            match kw.key {
                pulsevm_snapshot::SnapshotPublicKey::K1(_) => key_kinds[0] += 1,
                pulsevm_snapshot::SnapshotPublicKey::R1(_) => key_kinds[1] += 1,
                pulsevm_snapshot::SnapshotPublicKey::WebAuthn(_) => key_kinds[2] += 1,
            }
        }
    }
    println!(
        "permissions {permissions} (keys: {} K1, {} R1, {} WebAuthn)",
        key_kinds[0], key_kinds[1], key_kinds[2]
    );

    let links = snapshot.permission_links()?.count();
    println!("permission links {links}");

    let mut tables = 0u64;
    let mut kv_rows = 0u64;
    let mut idx = [0u64; 5];
    for table in snapshot.contract_tables()? {
        let table = table?;
        tables += 1;
        kv_rows += table.key_values.len() as u64;
        idx[0] += table.idx64.len() as u64;
        idx[1] += table.idx128.len() as u64;
        idx[2] += table.idx256.len() as u64;
        idx[3] += table.idx_double.len() as u64;
        idx[4] += table.idx_long_double.len() as u64;
    }
    println!(
        "contract tables {tables}: {kv_rows} kv rows, idx64 {} idx128 {} idx256 {} double {} \
         long-double {}",
        idx[0], idx[1], idx[2], idx[3], idx[4]
    );

    let limits = snapshot.resource_limits()?.count();
    let usage = snapshot.resource_usage()?.count();
    let state = snapshot.resource_limits_state()?;
    println!(
        "resource limits {limits}, usage {usage}, virtual cpu {} net {}",
        state.virtual_cpu_limit, state.virtual_net_limit
    );

    let generated = snapshot.generated_transactions()?.count();
    let transactions = snapshot.transactions()?.count();
    let summaries = snapshot.block_summaries()?.count();
    println!("transactions {transactions}, generated {generated}, block summaries {summaries}");

    Ok(())
}
