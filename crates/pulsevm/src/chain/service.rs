use std::sync::Arc;

use jsonrpsee::{proc_macros::rpc, server::{http::{self, call_with_service}, BatchRequestConfig}, types::{ErrorObjectOwned, Response, ResponseSuccess}, RpcModule};
use pulsevm_serialization::Deserialize;
use tokio::sync::Mutex;
use tonic::async_trait;

use crate::mempool::Mempool;

use super::Transaction;

#[rpc(server)]
pub trait Rpc {
	#[method(name = "pulsevm.issueTx")]
	async fn issue_tx(&self, tx: &str, encoding: &str) -> Result<String, ErrorObjectOwned>;
}

#[derive(Clone)]
pub struct RpcService {
    mempool: Arc<Mutex<Mempool>>,
}

impl RpcService {
    pub fn new(mempool: Arc<Mutex<Mempool>>) -> Self {
        RpcService {
            mempool,
        }
    }

    pub async fn handle_api_request(&self, request_body: &str) -> Result<String, serde_json::Error> {
        println!("Received request: {}", request_body);
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
    async fn issue_tx(&self, tx: &str, encoding: &str) -> Result<String, ErrorObjectOwned> {
        let tx_hex = tx.clone();
        let tx_bytes = hex::decode(tx.strip_prefix("0x").unwrap_or(tx)).map_err(|_| {
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

        // Add to mempool
        let mempool_clone = self.mempool.clone();
        let mut mempool = mempool_clone.lock().await;
        mempool.add_transaction(tx.clone());

        // Return a simple response
        Ok(tx_hex.to_string())
    }
}