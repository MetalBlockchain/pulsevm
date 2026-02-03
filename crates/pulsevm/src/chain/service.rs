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
    api::{
        GetAccountResponse, GetCodeHashResponse, GetInfoResponse, GetRawABIResponse,
        GetTableRowsResponse, IssueTxResponse,
    },
    chain::{GossipType, Gossipable, NetworkManager},
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
    async fn get_account(&self, account_name: Name, expected_core_symbol: Option<String>)
    -> Result<Value, ErrorObjectOwned>;

    #[method(name = "pulsevm.getBlock")]
    async fn get_block(&self, block_num_or_id: String) -> Result<SignedBlock, ErrorObjectOwned>;

    #[method(name = "pulsevm.getCodeHash")]
    async fn get_code_hash(
        &self,
        account_name: Name,
    ) -> Result<GetCodeHashResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getCurrencyBalance")]
    async fn get_currency_balance(
        &self,
        code: Name,
        account: Name,
        symbol: Option<String>,
    ) -> Result<Value, ErrorObjectOwned>;

    #[method(name = "pulsevm.getCurrencyStats")]
    async fn get_currency_stats(
        &self,
        code: Name,
        symbol: String,
    ) -> Result<Value, ErrorObjectOwned>;

    #[method(name = "pulsevm.getInfo")]
    async fn get_info(&self) -> Result<GetInfoResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getRawABI")]
    async fn get_raw_abi(&self, account_name: Name) -> Result<GetRawABIResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getRawBlock")]
    async fn get_raw_block(&self, block_num_or_id: String)
    -> Result<SignedBlock, ErrorObjectOwned>;

    #[method(name = "pulsevm.getTableRows")]
    async fn get_table_rows(
        &self,
        json: Option<bool>,
        code: Name,
        scope: String,
        table: Name,
        table_key: Option<String>,
        lower_bound: Option<String>,
        upper_bound: Option<String>,
        limit: Option<I32Flex>,
        key_type: String,
        index_position: Option<I32Flex>,
        encode_type: Option<String>, //dec, hex , default=dec
        reverse: Option<bool>,
        show_payer: Option<bool>,
    ) -> Result<Value, ErrorObjectOwned>;
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
        let abi = AbiDefinition::read(code_account.get_abi().as_slice(), &mut 0).map_err(|e| {
            ErrorObjectOwned::owned(400, "abi_error", Some(format!("failed to read ABI: {}", e)))
        })?;
        Ok(abi)
    }

    async fn get_account(&self, name: Name, expected_core_symbol: Option<String>) -> Result<Value, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let head_block_time = controller.last_accepted_block().timestamp().to_time_point();
        let head_block_num = controller.last_accepted_block().block_num();
        
        match expected_core_symbol {
            Some(symbol) => {
                let account_info_json = db.get_account_info_with_core_symbol(
                    name.as_u64(),
                    &symbol,
                    head_block_num,
                    &head_block_time,
                )?;
                let account_info: Value = serde_json::from_str(&account_info_json).map_err(|e| {
                    ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
                })?;
                Ok(account_info)
            },
            None => {
                let account_info_json = db.get_account_info_without_core_symbol(
                    name.as_u64(),
                    head_block_num,
                    &head_block_time,
                )?;
                let account_info: Value = serde_json::from_str(&account_info_json).map_err(|e| {
                    ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
                })?;
                Ok(account_info)
            }
        }
    }

    async fn get_block(&self, block_num_or_id: String) -> Result<SignedBlock, ErrorObjectOwned> {
        return self.get_raw_block(block_num_or_id).await;
    }

    async fn get_code_hash(
        &self,
        account_name: Name,
    ) -> Result<GetCodeHashResponse, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let accnt_obj = db.get_account_metadata(account_name.as_u64())?;
        let code_hash = accnt_obj.get_code_hash();
        Ok(GetCodeHashResponse {
            account_name,
            code_hash: code_hash.into(),
        })
    }

    async fn get_currency_balance(
        &self,
        code: Name,
        account: Name,
        symbol: Option<String>,
    ) -> Result<Value, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let response = match symbol {
            Some(s) => {
                let balance_str = db
                    .get_currency_balance_with_symbol(code.as_u64(), account.as_u64(), &s)
                    .map_err(|e| {
                        ErrorObjectOwned::owned(500, "internal_error", Some(format!("{}", e)))
                    })?;
                let balance: Value = serde_json::from_str(&balance_str).map_err(|e| {
                    ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
                })?;
                Ok(balance)
            }
            None => {
                let balance_str = db
                    .get_currency_balance_without_symbol(code.as_u64(), account.as_u64())
                    .map_err(|e| {
                        ErrorObjectOwned::owned(500, "internal_error", Some(format!("{}", e)))
                    })?;
                let balance: Value = serde_json::from_str(&balance_str).map_err(|e| {
                    ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
                })?;
                Ok(balance)
            }
        };

        return response;
    }

    async fn get_currency_stats(
        &self,
        code: Name,
        symbol: String,
    ) -> Result<Value, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let database = controller.database();
        let response = database.get_currency_stats(code.as_u64(), symbol.as_str())?;
        let stats: Value = serde_json::from_str(&response).map_err(|e| {
            ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
        })?;
        Ok(stats)
    }

    async fn get_info(&self) -> Result<GetInfoResponse, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let head_block = controller.last_accepted_block();
        let db = controller.database();
        Ok(GetInfoResponse {
            server_version: "d133c641".to_owned(),
            chain_id: controller.chain_id().clone(),
            head_block_num: head_block.block_num(),
            last_irreversible_block_num: head_block.block_num(),
            last_irreversible_block_id: head_block.id(),
            head_block_id: head_block.id(),
            head_block_time: head_block.timestamp().clone(),
            head_block_producer: head_block.signed_block_header.block.producer,
            virtual_block_cpu_limit: db.get_virtual_block_cpu_limit()?,
            virtual_block_net_limit: db.get_virtual_block_net_limit()?,
            block_cpu_limit: db.get_block_cpu_limit()?,
            block_net_limit: db.get_block_net_limit()?,
            server_version_string: "v5.0.3".to_owned(),
            fork_db_head_block_id: head_block.id(),
            fork_db_head_block_num: head_block.block_num(),
            server_full_version_string: "v5.0.3-d133c6413ce8ce2e96096a0513ec25b4a8dbe837"
                .to_owned(), // Mimic EOS here
            total_cpu_weight: db.get_total_cpu_weight()?,
            total_net_weight: db.get_total_net_weight()?,
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

    async fn get_raw_block(
        &self,
        block_num_or_id: String,
    ) -> Result<SignedBlock, ErrorObjectOwned> {
        let controller = self.controller.clone();
        let controller = controller.read().await;

        if let Ok(n) = block_num_or_id.parse::<u32>() {
            let block = controller.get_block_by_height(n)?;

            match block {
                Some(b) => return Ok(b),
                None => {
                    return Err(ErrorObjectOwned::owned(
                        404,
                        "block_not_found",
                        Some(format!("block {} not found", n)),
                    ));
                }
            }
        } else if let Ok(id) = Id::from_str(block_num_or_id.as_str()) {
            let block = controller.get_block(id)?;

            match block {
                Some(b) => return Ok(b),
                None => {
                    return Err(ErrorObjectOwned::owned(
                        404,
                        "block_not_found",
                        Some(format!("block {} not found", id)),
                    ));
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
        let packed_trx = PackedTransaction::new(
            signatures,
            compression,
            packed_context_free_data,
            packed_trx,
        )?;

        // Run transaction and revert it
        let mut controller = self.controller.write().await;
        let pending_block_timestamp = BlockTimestamp::now();
        controller.push_transaction(
            &packed_trx,
            &pending_block_timestamp,
            &pulsevm_core::block::BlockStatus::Verifying,
        )?;

        // Add to mempool
        let mut mempool = self.mempool.write().await;
        mempool.add_transaction(&packed_trx);

        // Gossip
        let nm = self.network_manager.read().await;
        let gossipable_msg = Gossipable::new(GossipType::Transaction, packed_trx.clone())?;
        nm.gossip(gossipable_msg).await?;

        // Return a simple response
        Ok(IssueTxResponse {
            tx_id: packed_trx.id().clone(),
        })
    }

    async fn get_table_rows(
        &self,
        json: Option<bool>,
        code: Name,
        scope: String,
        table: Name,
        table_key: Option<String>,
        lower_bound: Option<String>,
        upper_bound: Option<String>,
        limit: Option<I32Flex>,
        key_type: String,
        index_position: Option<I32Flex>,
        encode_type: Option<String>, //dec, hex , default=dec
        reverse: Option<bool>,
        show_payer: Option<bool>,
    ) -> Result<Value, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let response = db.get_table_rows(
            json.unwrap_or(false),
            code.as_u64(),
            &scope,
            table.as_u64(),
            &table_key.unwrap_or_default(),
            &lower_bound.unwrap_or_default(),
            &upper_bound.unwrap_or_default(),
            limit.unwrap_or(I32Flex(10)).0 as u32,
            &key_type,
            &index_position.unwrap_or(I32Flex(1)).0.to_string(),
            &encode_type.unwrap_or_else(|| "dec".to_string()),
            reverse.unwrap_or(false),
            show_payer.unwrap_or(false),
        )?;

        let rows: Value = serde_json::from_str(&response).map_err(|e| {
            ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
        })?;

        Ok(rows)
    }
}

fn get_table_index_name(
    table: Name,
    index_position: u16,
    primary: &mut bool,
) -> Result<u64, ChainError> {
    let table = table.as_u64();
    let mut index = table & 0xFFFFFFFFFFFFFFF0u64;
    pulse_assert(
        index == table,
        ChainError::TransactionError(format!("unsupported table name: {}", table)),
    )?;

    *primary = true; // TODO: handle primary vs secondary index
    let pos = 0u64;

    index |= pos & 0x000000000000000Fu64;

    Ok(index)
}
