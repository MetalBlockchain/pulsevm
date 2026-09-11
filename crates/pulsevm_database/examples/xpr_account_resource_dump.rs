//! Print one account's resource limits and RAM usage from an Arena checkpoint.

use std::{
    env,
    io,
    str::FromStr,
};

use pulsevm_database::Database;
use pulsevm_name::Name;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "xpr_account_resource_dump".into());
    let values: Vec<String> = args.collect();
    if values.len() != 2 && values.len() != 4 {
        return Err(format!(
            "Usage: {program} <arena-dir> <account> [--repair-expect <stored-bytes>]"
        )
        .into());
    }
    let repair_expected = if values.len() == 4 {
        if values[2] != "--repair-expect" {
            return Err("third argument must be --repair-expect".into());
        }
        Some(values[3].parse::<i64>()?)
    } else {
        None
    };

    let database = Database::new(&values[0], 0).map_err(io::Error::other)?;
    let account = Name::from_str(&values[1])?;
    let mut ram_bytes = 0;
    let mut net_weight = 0;
    let mut cpu_weight = 0;
    database.get_account_limits(
        account.as_u64(),
        &mut ram_bytes,
        &mut net_weight,
        &mut cpu_weight,
    )?;
    let ram_usage = database.get_account_ram_usage(account.as_u64())?;

    println!(
        "revision={} account={} ram_usage={} ram_bytes={} ram_available={} net_weight={} cpu_weight={}",
        database.revision(),
        account,
        ram_usage,
        ram_bytes,
        ram_bytes.saturating_sub(ram_usage),
        net_weight,
        cpu_weight,
    );
    let billing = database.account_ram_billing_breakdown(account.as_u64())?;
    let represented = billing.total()?;
    println!(
        "ram_inventory total={} residual={} account={} abi={} code={} permissions={} permission_links={} contract_tables={} contract_kv={} idx64={} idx128={} idx256={} idx_double={} idx_long_double={} deferred={}",
        represented,
        ram_usage - represented,
        billing.account,
        billing.abi,
        billing.code,
        billing.permissions,
        billing.permission_links,
        billing.contract_tables,
        billing.contract_kv,
        billing.contract_idx64,
        billing.contract_idx128,
        billing.contract_idx256,
        billing.contract_idx_double,
        billing.contract_idx_long_double,
        billing.deferred,
    );
    let deferred: Vec<_> = database
        .arena_deferred_transactions()
        .into_iter()
        .filter(|transaction| transaction.payer == account.as_u64())
        .collect();
    println!("deferred_paid={}", deferred.len());
    for transaction in deferred {
        println!(
            "deferred trx_id={} sender={} sender_id={} packed_bytes={} delay_until={} expiration={} published={}",
            hex::encode(transaction.trx_id),
            Name::new(transaction.sender),
            transaction.sender_id,
            transaction.packed_trx.len(),
            transaction.delay_until,
            transaction.expiration,
            transaction.published,
        );
    }
    if let Some(expected) = repair_expected {
        let repaired =
            database.repair_xpr_replay_ram_usage_from_inventory(account.as_u64(), expected)?;
        database.close()?;
        println!(
            "ram_repair account={} expected={} repaired={} residual=0",
            account, expected, repaired
        );
    }
    Ok(())
}
