use std::sync::Arc;

use jsonrpsee::{
    RpcModule,
    proc_macros::rpc,
    server::{
        BatchRequestConfig,
        http::{self, call_with_service},
    },
    types::{ErrorObjectOwned, Response, ResponseSuccess},
};
use pulsevm_serialization::Deserialize;
use serde::Serialize;
use tokio::sync::RwLock;
use tonic::async_trait;

use crate::mempool::Mempool;

use super::{Controller, NetworkManager, Transaction};

#[rpc(server)]
pub trait Rpc {
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
        println!("Received request: {}", request_body);
        // Make sure `RpcService` implements your API trait
        let module = self.clone().into_rpc();

        // Run the request and return the response
        let (resp, mut _stream) = module.raw_json_request(request_body, 1).await?;
        //let resp: ResponseSuccess<u64> = serde_json::from_str::<Response<u64>>(&resp).unwrap().try_into().unwrap();

        Ok(resp)
    }
}

#[derive(Serialize, Clone)]
pub struct IssueTxResponse {
    #[serde(rename(serialize = "txID"))]
    pub tx_id: String,
}

#[async_trait]
impl RpcServer for RpcService {
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
        let tx = Transaction::deserialize(&tx_bytes, &mut pos).map_err(|_| {
            ErrorObjectOwned::owned(
                400,
                "deserialize_error",
                Some("Invalid transaction encoding".to_string()),
            )
        })?;

        // Run transaction and revert it
        let controller = self.controller.clone();
        let controller = controller.read().await;
        controller.push_transaction(&tx).map_err(|e| {
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
