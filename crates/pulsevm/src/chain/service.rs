use std::sync::Arc;

use jsonrpsee::{
    proc_macros::rpc,
    types::{ErrorObjectOwned, Response, ResponseSuccess},
};
use pulsevm_serialization::Read;
use tokio::sync::RwLock;
use tonic::async_trait;

use crate::{
    api::{GetAccountResponse, IssueTxResponse, PermissionResponse},
    chain::{
        Account, AccountMetadata, BlockTimestamp, Name, Permission, PermissionByOwnerIndex,
        Transaction,
    },
    mempool::Mempool,
};

use super::{Controller, NetworkManager};

#[rpc(server)]
pub trait Rpc {
    #[method(name = "pulsevm.getAccount")]
    async fn get_account(&self, name: Name) -> Result<GetAccountResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.issueTx")]
    async fn issue_tx(&self, tx: &str, encoding: &str)
    -> Result<IssueTxResponse, ErrorObjectOwned>;
}

#[derive(Clone)]
pub struct RpcService {
    mempool: Arc<RwLock<Mempool>>,
    controller: Arc<RwLock<Controller>>,
    network_manager: Arc<RwLock<NetworkManager>>,
}

impl RpcService {
    pub fn new(
        mempool: Arc<RwLock<Mempool>>,
        controller: Arc<RwLock<Controller>>,
        network_manager: Arc<RwLock<NetworkManager>>,
    ) -> Self {
        RpcService {
            mempool,
            controller,
            network_manager,
        }
    }

    pub async fn handle_api_request(
        &self,
        request_body: &str,
    ) -> Result<String, serde_json::Error> {
        println!("Handling API request: {}", request_body);
        // Make sure `RpcService` implements your API trait
        let module = self.clone().into_rpc();

        // Run the request and return the response
        let (resp, mut _stream) = module.raw_json_request(request_body, 1).await?;
        //let resp: ResponseSuccess<u64> = serde_json::from_str::<Response<u64>>(&resp).unwrap().try_into().unwrap();

        Ok(resp)
    }
}

#[async_trait]
impl RpcServer for RpcService {
    async fn get_account(&self, name: Name) -> Result<GetAccountResponse, ErrorObjectOwned> {
        println!("Getting account: {}", name);
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let database = controller.database();
        let mut session = database
            .session()
            .map_err(|e| ErrorObjectOwned::owned(500, "database_error", Some(format!("{}", e))))?;
        let accnt_obj = session.get::<Account>(name.clone()).map_err(|e| {
            ErrorObjectOwned::owned(404, "account_not_found", Some(format!("{}", e)))
        })?;
        let accnt_metadata_obj = session.get::<AccountMetadata>(name.clone()).map_err(|e| {
            ErrorObjectOwned::owned(404, "account_not_found", Some(format!("{}", e)))
        })?;
        let mut result = GetAccountResponse::default();
        result.account_name = name.clone();
        result.privileged = accnt_metadata_obj.is_privileged();
        result.last_code_update = accnt_metadata_obj.last_code_update;
        result.created = accnt_obj.creation_date;

        let mut permissions = session.get_index::<Permission, PermissionByOwnerIndex>();
        let mut perm_iter = permissions.lower_bound((name.clone(), Name::default()))?;
        while let Some(perm) = perm_iter.next()? {
            if perm.owner != name {
                break; // Stop if we reach a different owner
            }

            let mut parent = Name::default();

            if perm.parent_id() > 0 {
                let parent_perm = session.get::<Permission>(perm.parent_id())?;
                parent = parent_perm.name.clone();
            }

            result.permissions.push(PermissionResponse::new(
                perm.name.clone(),
                parent,
                perm.authority.clone(),
            ));
        }

        Ok(result)
    }

    async fn issue_tx(
        &self,
        tx_hex: &str,
        encoding: &str,
    ) -> Result<IssueTxResponse, ErrorObjectOwned> {
        let tx_bytes = hex::decode(tx_hex.strip_prefix("0x").unwrap_or(tx_hex)).map_err(|_| {
            ErrorObjectOwned::owned(
                400,
                "decode_error",
                Some("Invalid transaction encoding".to_string()),
            )
        })?;
        let mut pos = 0 as usize;
        let tx = Transaction::read(&tx_bytes, &mut pos).map_err(|_| {
            ErrorObjectOwned::owned(
                400,
                "deserialize_error",
                Some("Invalid transaction encoding".to_string()),
            )
        })?;

        // Run transaction and revert it
        let controller = self.controller.clone();
        let mut controller = controller.write().await;
        let pending_block_timestamp = BlockTimestamp::now();
        controller
            .push_transaction(&tx, pending_block_timestamp)
            .map_err(|e| {
                ErrorObjectOwned::owned(500, "transaction_error", Some(format!("{}", e)))
            })?;

        // Add to mempool
        let mempool_clone = self.mempool.clone();
        let mut mempool = mempool_clone.write().await;
        mempool.add_transaction(tx.clone());

        // Gossip
        let nm_clone = self.network_manager.clone();
        let nm = nm_clone.read().await;
        nm.gossip(tx_bytes)
            .await
            .map_err(|e| ErrorObjectOwned::owned(500, "gossip_error", Some(format!("{}", e))))?;

        // Return a simple response
        Ok(IssueTxResponse {
            tx_id: tx.id().to_string(),
        })
    }
}
