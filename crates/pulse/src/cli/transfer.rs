use std::{str::FromStr, sync::Arc};

use pulsevm_api_client::PulseVmClient;
use pulsevm_core::{
    ACTIVE_NAME, asset::Asset, authority::PermissionLevel, name::Name, transaction::Action,
};
use pulsevm_crypto::Bytes;
use pulsevm_keosd_client::KeosdClient;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;

use crate::{config::Config, utils::push_actions};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct Transfer {
    pub from: Name,
    pub to: Name,
    pub quantity: Asset,
    pub memo: String,
}

impl TryFrom<Transfer> for Arc<[u8]> {
    type Error = String;

    fn try_from(value: Transfer) -> Result<Self, Self::Error> {
        value.pack().map(Arc::from).map_err(|e| e.to_string())
    }
}

pub async fn handle(
    api_client: &PulseVmClient,
    config: &mut Config,
    keosd_client: &KeosdClient,
    sender: String,
    recipient: String,
    amount: String,
    memo: String,
    contract: String,
    permission: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sender = sender.parse::<Name>()?;
    let recipient = recipient.parse::<Name>()?;
    let permission = if let Some(permission) = permission {
        PermissionLevel::from_str(&permission)?
    } else {
        PermissionLevel::new(sender.as_u64(), ACTIVE_NAME.into())
    };
    let amount = amount.parse::<Asset>()?;
    let contract = contract.parse::<Name>()?;
    let response = push_actions(
        api_client,
        keosd_client,
        vec![Action {
            account: contract.clone(),
            name: "transfer".parse::<Name>()?,
            authorization: vec![permission],
            data: Transfer {
                from: sender,
                to: recipient,
                quantity: amount.clone(),
                memo,
            }
            .try_into()?,
        }],
    )
    .await?;
    println!(
        "Transferred {} from {} to {}: {}",
        amount, sender, recipient, response
    );
    Ok(())
}
