use pulsevm_api_client::PulseVmClient;
use pulsevm_core::{
    id::Id,
    transaction::{Action, PackedTransaction, SignedTransaction, Transaction},
};
use pulsevm_keosd_client::KeosdClient;
use pulsevm_time::TimePointSec;

pub async fn push_actions(
    api_client: &PulseVmClient,
    keosd_client: &KeosdClient,
    actions: Vec<Action>,
) -> Result<Id, Box<dyn std::error::Error>> {
    let chain_info = api_client.get_info().await?;
    let mut txn = Transaction::default();
    txn.header.expiration = TimePointSec::now() + 300; // 5 minutes from now
    txn.actions = actions;
    let candidate_keys = keosd_client.get_public_keys().await?;
    let required_keys = api_client.get_required_keys(&txn, &candidate_keys).await?;
    let txn_json = serde_json::to_value(&txn)?;
    let signed = keosd_client
        .sign_transaction(&txn_json, &required_keys, &chain_info.chain_id)
        .await?;
    let signed_tx = SignedTransaction::new(txn, signed.signatures, vec![]);
    let packed_tx = PackedTransaction::from_signed_transaction(signed_tx)?;
    let response = api_client.issue_tx(&packed_tx).await?;
    Ok(response.tx_id)
}
