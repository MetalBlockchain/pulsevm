use std::str::FromStr;

use pulsevm_api_client::PulseVmClient;
use pulsevm_core::{
    PULSE_NAME,
    authority::{Authority, KeyWeight, PermissionLevel},
    config::NEWACCOUNT_NAME,
    crypto::{PrivateKey, PublicKey},
    name::Name,
    pulse_contract::NewAccount,
    transaction::{Action, Transaction},
};
use pulsevm_keosd_client::KeosdClient;

use crate::cli::CreateSubcommand;

pub async fn handle(
    api_client: &PulseVmClient,
    keosd_client: &KeosdClient,
    subcmd: CreateSubcommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        CreateSubcommand::Account {
            creator,
            name,
            owner_key,
            active_key,
        } => {
            let active_key = if let Some(k) = active_key {
                k
            } else {
                owner_key.clone()
            };
            let mut txn = Transaction::default();
            txn.actions.push(Action {
                account: PULSE_NAME,
                name: NEWACCOUNT_NAME,
                authorization: vec![PermissionLevel {
                    actor: Name::from_str(&creator)?.into(),
                    permission: Name::from_str("active")?.into(),
                }],
                data: NewAccount {
                    creator: Name::from_str(&creator)?.into(),
                    name: Name::from_str(&name)?.into(),
                    owner: Authority {
                        threshold: 1,
                        keys: vec![KeyWeight {
                            key: PublicKey::from_str(&owner_key)?.into(),
                            weight: 1,
                        }],
                        accounts: vec![],
                        waits: vec![],
                    },
                    active: Authority {
                        threshold: 1,
                        keys: vec![KeyWeight {
                            key: PublicKey::from_str(&active_key)?.into(),
                            weight: 1,
                        }],
                        accounts: vec![],
                        waits: vec![],
                    },
                }
                .try_into()?,
            });
            let candidate_keys = keosd_client.get_public_keys().await?;
            let required_keys = api_client
                .get_required_keys(&txn, &candidate_keys)
                .await?;
            let signed = keosd_client.sign_transaction(&txn, &required_keys).await?;
            todo!("sign and push transaction to create account");
        }
        CreateSubcommand::Key {
            file,
            to_console,
            r1,
        } => {
            let private_key = if r1 {
                PrivateKey::random_r1()
            } else {
                PrivateKey::random()
            };

            match file {
                Some(path) => {
                    let content = format!(
                        "Private Key: {}\nPublic Key: {}",
                        private_key,
                        private_key.get_public_key()
                    );
                    std::fs::write(&path, content)?;
                    println!("Public key saved to {}", path);
                }
                None if !to_console => {
                    return Err("Must specify --file or --to-console to output keys".into());
                }
                _ => {}
            }

            if to_console {
                println!("Private Key: {}", private_key.get_public_key());
                println!("Public Key: {}", private_key.get_public_key());
            }
        }
    }
    Ok(())
}
