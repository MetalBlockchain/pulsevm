use std::str::FromStr;

use pulsevm_api_client::PulseVmClient;
use pulsevm_core::{
    ACTIVE_NAME,
    PULSE_NAME,
    authority::{
        Authority,
        KeyWeight,
        PermissionLevel,
    },
    config::NEWACCOUNT_NAME,
    crypto::{
        PrivateKey,
        PublicKey,
    },
    name::Name,
    pulse_contract::NewAccount,
    transaction::Action,
};
use pulsevm_keosd_client::KeosdClient;
use spdlog::info;

use crate::{
    cli::CreateSubcommand,
    utils::push_actions,
};

/// Render a freshly generated keypair for display or for writing to a file.
///
/// Both output paths go through this so they cannot disagree about which key is
/// which -- the reason they must is that they previously did.
fn render_keypair(private_key: &PrivateKey) -> String {
    format!(
        "Private Key: {}\nPublic Key: {}",
        private_key,
        private_key.get_public_key()
    )
}

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
            let response = push_actions(
                api_client,
                keosd_client,
                vec![Action {
                    account: PULSE_NAME,
                    name: NEWACCOUNT_NAME,
                    authorization: vec![PermissionLevel {
                        actor: Name::from_str(&creator)?.into(),
                        permission: ACTIVE_NAME.into(),
                    }],
                    data: NewAccount {
                        creator: Name::from_str(&creator)?.into(),
                        name: Name::from_str(&name)?.into(),
                        owner: Authority {
                            threshold: 1,
                            keys: vec![KeyWeight::new(
                                PublicKey::from_str(&owner_key)?.into_k1(),
                                1,
                            )],
                            accounts: vec![],
                            waits: vec![],
                        },
                        active: Authority {
                            threshold: 1,
                            keys: vec![KeyWeight::new(
                                PublicKey::from_str(&active_key)?.into_k1(),
                                1,
                            )],
                            accounts: vec![],
                            waits: vec![],
                        },
                    }
                    .try_into()?,
                }],
            )
            .await?;
            info!("Account creation transaction issued: {}", response);
        }
        CreateSubcommand::Key {
            file,
            to_console,
            r1,
        } => {
            if r1 {
                return Err(
                    "R1 (secp256r1) keys are not supported by the pure-Rust build; use a K1 key"
                        .into(),
                );
            }
            let private_key = PrivateKey::random();
            // One renderer for both sinks. These were two separate `format!`
            // sites, and they drifted: the console one printed the *public* key
            // under the "Private Key:" label, so a key generated with
            // --to-console was unrecoverable the moment the process exited.
            let rendered = render_keypair(&private_key);

            match file {
                Some(path) => {
                    std::fs::write(&path, &rendered)?;
                    println!(
                        "Keys saved to {} -- this file contains the private key",
                        path
                    );
                }
                None if !to_console => {
                    return Err("Must specify --file or --to-console to output keys".into());
                }
                _ => {}
            }

            if to_console {
                println!("{}", rendered);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `create key --to-console` printed `get_public_key()` on *both* lines, so
    /// the line labelled "Private Key" carried the public key. Nothing failed --
    /// both lines are well-formed key strings -- and the private key was dropped
    /// at end of scope. Anyone who funded the resulting account lost it.
    #[test]
    fn rendered_keypair_does_not_print_the_public_key_twice() {
        let private_key = PrivateKey::random();
        let rendered = render_keypair(&private_key);

        let mut lines = rendered.lines();
        let private_line = lines.next().expect("a private key line");
        let public_line = lines.next().expect("a public key line");
        assert!(lines.next().is_none(), "expected exactly two lines");

        let private_value = private_line
            .strip_prefix("Private Key: ")
            .expect("private line is labelled");
        let public_value = public_line
            .strip_prefix("Public Key: ")
            .expect("public line is labelled");

        assert_ne!(
            private_value, public_value,
            "the two lines must not carry the same key"
        );
    }

    /// The labels must match the values, not merely differ from each other:
    /// swapping the two would also satisfy the check above.
    #[test]
    fn rendered_keypair_labels_match_their_values() {
        let private_key = PrivateKey::random();
        let rendered = render_keypair(&private_key);

        assert!(
            rendered.contains(&format!("Private Key: {}", private_key)),
            "the private line must carry the private key"
        );
        assert!(
            rendered.contains(&format!("Public Key: {}", private_key.get_public_key())),
            "the public line must carry the public key"
        );
    }

    /// The private key must round-trip out of what we printed -- the property a
    /// user actually depends on when they paste it into `wallet import`.
    #[test]
    fn printed_private_key_round_trips() {
        let private_key = PrivateKey::random();
        let rendered = render_keypair(&private_key);

        let printed = rendered
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("Private Key: "))
            .expect("private line");

        let recovered = PrivateKey::from_str(printed).expect("printed key must parse back");
        assert_eq!(
            recovered.get_public_key(),
            private_key.get_public_key(),
            "the printed key must be the one that was generated"
        );
    }
}
