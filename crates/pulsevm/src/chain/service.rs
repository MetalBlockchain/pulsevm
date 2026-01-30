use std::{collections::HashSet, str::FromStr, sync::Arc};

use jsonrpsee::{proc_macros::rpc, types::ErrorObjectOwned};
use pulsevm_core::{
    ChainError,
    abi::AbiDefinition,
    block::{BlockTimestamp, SignedBlock},
    controller::Controller,
    crypto::Signature,
    id::Id,
    mempool::Mempool,
    name::Name,
    resource_limits::ResourceLimitsManager,
    transaction::{PackedTransaction, TransactionCompression},
    utils::{Base64Bytes, I32Flex, pulse_assert},
};
use pulsevm_crypto::{Bytes, Digest};
use pulsevm_name_macro::name;
use pulsevm_serialization::Read;
use serde_json::Value;
use tokio::sync::RwLock;
use tonic::async_trait;

use crate::{
    api::{GetAccountResponse, GetCodeHashResponse, GetInfoResponse, GetRawABIResponse, GetTableRowsResponse, IssueTxResponse},
    chain::{Gossipable, NetworkManager},
};

#[rpc(server)]
pub trait Rpc {
    #[method(name = "pulsevm.issueTx")]
    async fn issue_tx(
        &self,
        signatures: HashSet<Signature>,
        compression: TransactionCompression,
        packed_context_free_data: Bytes,
        packed_trx: Bytes,
    ) -> Result<IssueTxResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getABI")]
    async fn get_abi(&self, account_name: Name) -> Result<AbiDefinition, ErrorObjectOwned>;

    #[method(name = "pulsevm.getAccount")]
    async fn get_account(&self, account_name: Name) -> Result<GetAccountResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getBlock")]
    async fn get_block(&self, block_num_or_id: String) -> Result<SignedBlock, ErrorObjectOwned>;

    #[method(name = "pulsevm.getCodeHash")]
    async fn get_code_hash(&self, account_name: Name) -> Result<GetCodeHashResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getCurrencyBalance")]
    async fn get_currency_balance(&self, code: Name, account: Name, symbol: Option<String>) -> Result<Value, ErrorObjectOwned>;

    #[method(name = "pulsevm.getCurrencyStats")]
    async fn get_currency_stats(&self, code: Name, symbol: String) -> Result<Value, ErrorObjectOwned>;

    #[method(name = "pulsevm.getInfo")]
    async fn get_info(&self) -> Result<GetInfoResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getRawABI")]
    async fn get_raw_abi(&self, account_name: Name) -> Result<GetRawABIResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getRawBlock")]
    async fn get_raw_block(&self, block_num_or_id: String) -> Result<SignedBlock, ErrorObjectOwned>;

    #[method(name = "pulsevm.getTableRows")]
    async fn get_table_rows(
        &self,
        code: Name,
        scope: String,
        table: Name,
        json: bool,
        limit: I32Flex,
        lower_bound: Option<String>,
        upper_bound: Option<String>,
        key_type: String,
        index_position: u16,
        reverse: Option<bool>,
        show_payer: Option<bool>,
    ) -> Result<GetTableRowsResponse, ErrorObjectOwned>;
}

#[derive(Clone)]
pub struct RpcService {
    mempool: Arc<RwLock<Mempool>>,
    controller: Arc<RwLock<Controller>>,
    network_manager: Arc<RwLock<NetworkManager>>,
}

impl RpcService {
    pub fn new(mempool: Arc<RwLock<Mempool>>, controller: Arc<RwLock<Controller>>, network_manager: Arc<RwLock<NetworkManager>>) -> Self {
        RpcService {
            mempool,
            controller,
            network_manager,
        }
    }

    pub async fn handle_api_request(&self, request_body: &str) -> Result<String, serde_json::Error> {
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
    async fn get_abi(&self, account_name: Name) -> Result<AbiDefinition, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let code_account = db.get_account(account_name.as_u64())?;
        let abi = AbiDefinition::read(code_account.get_abi().as_slice(), &mut 0)
            .map_err(|e| ErrorObjectOwned::owned(400, "abi_error", Some(format!("failed to read ABI: {}", e))))?;
        Ok(abi)
    }

    async fn get_account(&self, name: Name) -> Result<GetAccountResponse, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let accnt_obj = db.get_account(name.as_u64())?;
        let accnt_metadata_obj = db.get_account_metadata(name.as_u64())?;
        let mut result = GetAccountResponse::default();
        result.head_block_time = controller.last_accepted_block().timestamp().clone();
        result.head_block_num = controller.last_accepted_block().block_num();
        result.account_name = name.clone();
        result.privileged = accnt_metadata_obj.is_privileged();
        result.last_code_update = accnt_metadata_obj.get_last_code_update().into();
        result.created = accnt_obj.get_creation_date().into();
        result.net_limit = ResourceLimitsManager::get_account_net_limit_ex(&db, &name, None)?;
        result.cpu_limit = ResourceLimitsManager::get_account_cpu_limit_ex(&db, &name, None)?;

        ResourceLimitsManager::get_account_limits(&db, &name, &mut result.ram_quota, &mut result.net_weight, &mut result.cpu_weight)?;

        result.ram_usage = ResourceLimitsManager::get_account_ram_usage(&db, &name)?;

        // TODO: Push permissions

        Ok(result)
    }

    async fn get_block(&self, block_num_or_id: String) -> Result<SignedBlock, ErrorObjectOwned> {
        return self.get_raw_block(block_num_or_id).await;
    }

    async fn get_code_hash(&self, account_name: Name) -> Result<GetCodeHashResponse, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let accnt_obj = db.get_account_metadata(account_name.as_u64())?;
        let code_hash = accnt_obj.get_code_hash();
        Ok(GetCodeHashResponse {
            account_name,
            code_hash: code_hash.into(),
        })
    }

    async fn get_currency_balance(&self, code: Name, account: Name, symbol: Option<String>) -> Result<Value, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let mut results: Vec<String> = Vec::new();
        let table = db.find_table(code.as_u64(), account.as_u64(), name!("accounts"))?;

        // TODO: Finalize symbol handling

        serde_json::to_value(results).map_err(|e| ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e))))
    }

    async fn get_currency_stats(&self, code: Name, symbol: String) -> Result<Value, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let database = controller.database();

        Err(ErrorObjectOwned::owned(
            404,
            "currency_stats_not_found",
            Some(format!("Currency stats for {} not found", symbol)),
        ))
    }

    async fn get_info(&self) -> Result<GetInfoResponse, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let head_block = controller.last_accepted_block();
        let db = controller.database();
        let total_cpu_weight = ResourceLimitsManager::get_total_cpu_weight(&db)?;
        let total_net_weight = ResourceLimitsManager::get_total_net_weight(&db)?;
        Ok(GetInfoResponse {
            server_version: "d133c641".to_owned(),
            chain_id: controller.chain_id(),
            head_block_num: head_block.block_num(),
            last_irreversible_block_num: head_block.block_num(),
            last_irreversible_block_id: head_block.id(),
            head_block_id: head_block.id(),
            head_block_time: head_block.timestamp().clone(),
            head_block_producer: head_block.signed_block_header.block.producer,
            virtual_block_cpu_limit: 100, // Placeholder, adjust as needed
            virtual_block_net_limit: 100, // Placeholder, adjust as needed
            block_cpu_limit: 100,         // Placeholder, adjust as needed
            block_net_limit: 100,         // Placeholder, adjust as needed
            server_version_string: "v5.0.3".to_owned(),
            fork_db_head_block_id: head_block.id(),
            fork_db_head_block_num: head_block.block_num(),
            server_full_version_string: "v5.0.3-d133c6413ce8ce2e96096a0513ec25b4a8dbe837".to_owned(), // Mimic EOS here
            total_cpu_weight: total_cpu_weight,
            total_net_weight: total_net_weight,
            earliest_available_block_num: 1,
            last_irreversible_block_time: head_block.timestamp().clone(),
        })
    }

    async fn get_raw_abi(&self, account_name: Name) -> Result<GetRawABIResponse, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let account = db.get_account(account_name.as_u64())?;
        let account_metadata = db.get_account_metadata(account_name.as_u64())?;

        let mut abi_hash = Digest::default();

        if account.get_abi().size() > 0 {
            abi_hash = Digest::hash(account.get_abi().as_slice());
        }

        Ok(GetRawABIResponse {
            account_name,
            code_hash: account_metadata.get_code_hash().into(),
            abi_hash,
            abi: Base64Bytes::new(account.get_abi().as_slice().to_vec()),
        })
    }

    async fn get_raw_block(&self, block_num_or_id: String) -> Result<SignedBlock, ErrorObjectOwned> {
        let controller = self.controller.clone();
        let controller = controller.read().await;

        if let Ok(n) = block_num_or_id.parse::<u32>() {
            let block = controller.get_block_by_height(n)?;

            match block {
                Some(b) => return Ok(b),
                None => {
                    return Err(ErrorObjectOwned::owned(404, "block_not_found", Some(format!("block {} not found", n))));
                }
            }
        } else if let Ok(id) = Id::from_str(block_num_or_id.as_str()) {
            let block = controller.get_block(id)?;

            match block {
                Some(b) => return Ok(b),
                None => {
                    return Err(ErrorObjectOwned::owned(404, "block_not_found", Some(format!("block {} not found", id))));
                }
            }
        }

        return Err(ErrorObjectOwned::owned(
            400,
            "invalid_block_identifier",
            Some("block number or ID is invalid".to_string()),
        ));
    }

    async fn issue_tx(
        &self,
        signatures: HashSet<Signature>,
        compression: TransactionCompression,
        packed_context_free_data: Bytes,
        packed_trx: Bytes,
    ) -> Result<IssueTxResponse, ErrorObjectOwned> {
        let packed_trx = PackedTransaction::new(signatures, compression, packed_context_free_data, packed_trx)?;

        // Run transaction and revert it
        let mut controller = self.controller.write().await;
        let pending_block_timestamp = BlockTimestamp::now();
        controller.push_transaction(&packed_trx, &pending_block_timestamp, &pulsevm_core::block::BlockStatus::Verifying)?;

        // Add to mempool
        let mut mempool = self.mempool.write().await;
        mempool.add_transaction(&packed_trx);

        // Gossip
        let nm = self.network_manager.read().await;
        let gossipable_msg = Gossipable::new(0, packed_trx.clone())?;
        nm.gossip(gossipable_msg).await?;

        // Return a simple response
        Ok(IssueTxResponse {
            tx_id: packed_trx.id().clone(),
        })
    }

    async fn get_table_rows(
        &self,
        code: Name,
        scope: String,
        table: Name,
        json: bool,
        limit: I32Flex,
        lower_bound: Option<String>,
        upper_bound: Option<String>,
        key_type: String,
        index_position: u16,
        reverse: Option<bool>,
        show_payer: Option<bool>,
    ) -> Result<GetTableRowsResponse, ErrorObjectOwned> {
        return Err(ErrorObjectOwned::owned(
            400,
            "secondary_index_not_supported",
            Some(format!("secondary index not supported for table: {}", table)),
        ));
    }
}

fn get_table_index_name(table: Name, index_position: u16, primary: &mut bool) -> Result<u64, ChainError> {
    let table = table.as_u64();
    let mut index = table & 0xFFFFFFFFFFFFFFF0u64;
    pulse_assert(index == table, ChainError::TransactionError(format!("unsupported table name: {}", table)))?;

    *primary = true; // TODO: handle primary vs secondary index
    let pos = 0u64;

    index |= pos & 0x000000000000000Fu64;

    Ok(index)
}
