use pulsevm_keosd_client::KeosdClient;

use crate::cli::{CreateSubcommand, WalletSubcommand};

pub async fn handle(
    client: &KeosdClient,
    subcmd: WalletSubcommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        WalletSubcommand::Create {
            name,
            to_console,
            file,
        } => {
            let password = client.create(&name).await?;
            println!("Creating wallet: {}", name);
            println!("Save password to use in the future to unlock this wallet.");
            println!("Without password imported keys will not be retrievable.");
            if to_console || file.is_none() {
                println!("\"{}\"", password);
            }
            if let Some(path) = file {
                std::fs::write(&path, &password)?;
                println!("Password saved to {}", path);
            }
        }

        WalletSubcommand::Open { name } => {
            client.open(&name).await?;
            println!("Opened: {}", name);
        }

        WalletSubcommand::Lock { name } => {
            client.lock(&name).await?;
            println!("Locked: {}", name);
        }

        WalletSubcommand::LockAll => {
            client.lock_all().await?;
            println!("Locked All Wallets");
        }

        WalletSubcommand::Unlock { name, password } => {
            let pw = match password {
                Some(p) => p,
                None => {
                    eprint!("password: ");
                    rpassword::read_password()
                        .map_err(|e| format!("failed to read password from terminal: {}", e))?
                }
            };
            if pw.is_empty() {
                return Err("password must not be empty".into());
            }
            client.unlock(&name, &pw).await?;
            println!("Unlocked: {}", name);
        }

        WalletSubcommand::Import { name, private_key } => {
            let key = match private_key {
                Some(k) => k,
                None => {
                    eprint!("private key: ");
                    rpassword::read_password()
                        .map_err(|e| format!("failed to read private key from terminal: {}", e))?
                }
            };
            if key.is_empty() {
                return Err("private key must not be empty".into());
            }
            client.import_key(&name, &key).await?;
            println!(
                "imported private key for: EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
            );
        }

        WalletSubcommand::List => {
            let wallets = client.list_wallets().await?;
            println!("Wallets:");
            for w in wallets {
                println!("[\"{}\" ]", w);
            }
        }

        WalletSubcommand::Keys { name, password } => {
            let pw = match password {
                Some(p) => p,
                None => {
                    eprint!("password: ");
                    rpassword::read_password()
                        .map_err(|e| format!("failed to read password from terminal: {}", e))?
                }
            };
            if pw.is_empty() {
                return Err("password must not be empty".into());
            }
            let keys = client.list_keys(&name, &pw).await?;
            println!("[");
            for (i, k) in keys.iter().enumerate() {
                let comma = if i < keys.len() - 1 { "," } else { "" };
                println!("  \"{}\"{}", k[0], comma);
            }
            println!("]");
        }

        WalletSubcommand::RemoveKey {
            key,
            name,
            password,
        } => {
            let pw = match password {
                Some(p) => p,
                None => {
                    eprint!("password: ");
                    rpassword::read_password()
                        .map_err(|e| format!("failed to read password from terminal: {}", e))?
                }
            };
            if pw.is_empty() {
                return Err("password must not be empty".into());
            }
            client.remove_key(&name, &pw, &key).await?;
            println!("removed: {}", key);
        }

        WalletSubcommand::CreateKey { name, key_type } => {
            let res = client.create_key(&name, &key_type).await?;
            println!("Created new private key with a public key of: {}", res);
        }

        WalletSubcommand::Stop => {
            client.stop().await?;
            println!("OK");
        }
    }

    Ok(())
}
