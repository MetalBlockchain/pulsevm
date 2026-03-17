use std::path::PathBuf;

use pulsevm_keosd_client::KeosdClient;

use crate::cli::{Cli, Commands, create, wallet};

pub async fn execute(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Resolve data directory
    let data_dir = dirs_or_default();
    let wallet_url = match cli.wallet_url {
        Some(url) => url,
        None => data_dir
            .join("pulse-keosd.sock")
            .to_str()
            .unwrap()
            .to_string(),
    };
    let keosd_client = match wallet_url.strip_prefix("http://") {
        Some(url) => KeosdClient::tcp(url),
        None => KeosdClient::unix(&wallet_url),
    };

    match cli.command {
        Commands::Create { subcmd } => create::handle(&keosd_client, subcmd).await?,
        Commands::Wallet { subcmd } => wallet::handle(&keosd_client, subcmd).await?,
    }

    Ok(())
}

/// Default wallet directory: ~/pulse-wallet
fn dirs_or_default() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join("pulse-wallet")
    } else {
        PathBuf::from("./pulse-wallet")
    }
}
