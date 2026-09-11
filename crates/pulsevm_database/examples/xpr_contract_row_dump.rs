//! Extract a raw contract row directly from an Arena migration checkpoint.

use std::{
    env,
    fs,
    io,
    path::PathBuf,
    str::FromStr,
};

use pulsevm_database::Database;
use pulsevm_name::Name;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "xpr_contract_row_dump".into());
    let values: Vec<String> = args.collect();
    if values.len() != 6 {
        return Err(format!(
            "Usage: {program} <arena-dir> <output-file> <code> <scope> <table> <primary-key>"
        )
        .into());
    }

    let database = Database::new(&values[0], 0).map_err(io::Error::other)?;
    let code = Name::from_str(&values[2])?;
    let scope = Name::from_str(&values[3])?;
    let table = Name::from_str(&values[4])?;
    let primary = values[5].parse::<u64>()?;
    let (payer, row) = database
        .arena_kv_row(code.as_u64(), scope.as_u64(), table.as_u64(), primary)
        .ok_or_else(|| io::Error::other("contract row not found"))?;
    let output = PathBuf::from(&values[1]);
    fs::write(&output, &row)?;
    println!(
        "code={code} scope={scope} table={table} primary={primary} payer={} bytes={} hex={} output={}",
        Name::new(payer),
        row.len(),
        hex::encode(&row),
        output.display()
    );
    Ok(())
}
