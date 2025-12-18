use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
};

use jsonrpsee::{proc_macros::rpc, types::ErrorObjectOwned};
use pulsevm_chainbase::{Session, UndoSession};
use pulsevm_core::{
    PULSE_NAME,
    abi::{AbiDefinition, AbiSerializer},
    account::{Account, AccountMetadata},
    asset::{Asset, string_to_symbol},
    authority::{Permission, PermissionByOwnerIndex},
    block::{BlockHeader, BlockTimestamp, SignedBlock},
    controller::Controller,
    error::ChainError,
    id::Id,
    mempool::Mempool,
    name::Name,
    resource_limits::ResourceLimitsManager,
    secp256k1::Signature,
    table::{KeyValue, KeyValueByScopePrimaryIndex, Table, TableByCodeScopeTableIndex},
    transaction::{PackedTransaction, TransactionCompression},
    utils::{Base64Bytes, I32Flex, pulse_assert},
};
use pulsevm_crypto::{Bytes, Digest};
use pulsevm_proc_macros::name;
use pulsevm_serialization::Read;
use serde_json::{Map, Value, json};
use tokio::sync::RwLock;
use tonic::async_trait;

use crate::{
    api::{
        GetAccountResponse, GetCodeHashResponse, GetInfoResponse, GetRawABIResponse,
        GetTableRowsResponse, IssueTxResponse, PermissionResponse,
    },
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
    async fn get_account(&self, account_name: Name)
    -> Result<GetAccountResponse, ErrorObjectOwned>;

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
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let database = controller.database();
        let session = database
            .undo_session() // TODO: use read only session
            .map_err(|e| ErrorObjectOwned::owned(500, "database_error", Some(format!("{}", e))))?;
        let code_account = session.get::<Account>(account_name.clone()).map_err(|e| {
            ErrorObjectOwned::owned(404, "account_not_found", Some(format!("{}", e)))
        })?;
        let abi = AbiDefinition::read(&code_account.abi, &mut 0).map_err(|e| {
            ErrorObjectOwned::owned(400, "abi_error", Some(format!("failed to read ABI: {}", e)))
        })?;
        Ok(abi)
    }

    async fn get_account(&self, name: Name) -> Result<GetAccountResponse, ErrorObjectOwned> {
        let controller = self.controller.clone();
        let mut controller = controller.write().await;
        let mut session = controller
            .create_undo_session()
            .map_err(|e| ErrorObjectOwned::owned(500, "database_error", Some(format!("{}", e))))?;
        let accnt_obj = session.get::<Account>(name.clone()).map_err(|e| {
            ErrorObjectOwned::owned(404, "account_not_found", Some(format!("{}", e)))
        })?;
        let accnt_metadata_obj = session.get::<AccountMetadata>(name.clone()).map_err(|e| {
            ErrorObjectOwned::owned(404, "account_not_found", Some(format!("{}", e)))
        })?;
        let mut result = GetAccountResponse::default();
        result.head_block_time = controller.last_accepted_block().timestamp();
        result.head_block_num = controller.last_accepted_block().block_num();

        result.account_name = name.clone();
        result.privileged = accnt_metadata_obj.is_privileged();
        result.last_code_update = accnt_metadata_obj.last_code_update;
        result.created = accnt_obj.creation_date;

        let current_usage_time = result.head_block_time;
        result.net_limit = ResourceLimitsManager::get_account_net_limit(
            &mut session,
            &name,
            Some(current_usage_time),
        )
        .map_err(|e| {
            ErrorObjectOwned::owned(500, "resource_limits_error", Some(format!("{}", e)))
        })?;
        result.cpu_limit = ResourceLimitsManager::get_account_cpu_limit(
            &mut session,
            &name,
            Some(current_usage_time),
        )
        .map_err(|e| {
            ErrorObjectOwned::owned(500, "resource_limits_error", Some(format!("{}", e)))
        })?;

        ResourceLimitsManager::get_account_limits(
            &mut session,
            &name,
            &mut result.ram_quota,
            &mut result.net_weight,
            &mut result.cpu_weight,
        )
        .map_err(|e| {
            ErrorObjectOwned::owned(500, "resource_limits_error", Some(format!("{}", e)))
        })?;

        result.ram_usage = ResourceLimitsManager::get_account_ram_usage(&mut session, &name)
            .map_err(|e| {
                ErrorObjectOwned::owned(500, "resource_limits_error", Some(format!("{}", e)))
            })?;

        let mut permissions = session.get_index::<Permission, PermissionByOwnerIndex>();
        let mut perm_iter = permissions.lower_bound((name.clone(), Name::default()))?;
        while let Some(perm) = perm_iter.next()? {
            if perm.owner != name {
                break; // Stop if we reach a different owner
            }

            let mut parent = Name::default();

            if perm.parent > 0 {
                let parent_perm = session.get::<Permission>(perm.parent)?;
                parent = parent_perm.name;
            }

            result.permissions.push(PermissionResponse::new(
                perm.name,
                parent,
                perm.authority.clone(),
            ));
        }

        Ok(result)
    }

    async fn get_block(&self, block_num_or_id: String) -> Result<SignedBlock, ErrorObjectOwned> {
        return self.get_raw_block(block_num_or_id).await;
    }

    async fn get_code_hash(
        &self,
        account_name: Name,
    ) -> Result<GetCodeHashResponse, ErrorObjectOwned> {
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let database = controller.database();
        let session = database
            .undo_session() // TODO: use read only session
            .map_err(|e| ErrorObjectOwned::owned(500, "database_error", Some(format!("{}", e))))?;
        let accnt_obj = session
            .get::<AccountMetadata>(account_name.clone())
            .map_err(|e| {
                ErrorObjectOwned::owned(404, "account_not_found", Some(format!("{}", e)))
            })?;
        let code_hash = accnt_obj.code_hash;
        Ok(GetCodeHashResponse {
            account_name,
            code_hash,
        })
    }

    async fn get_currency_balance(
        &self,
        code: Name,
        account: Name,
        symbol: Option<String>,
    ) -> Result<Value, ErrorObjectOwned> {
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let database = controller.database();
        let session = database
            .undo_session() // TODO: use read only session
            .map_err(|e| ErrorObjectOwned::owned(500, "database_error", Some(format!("{}", e))))?;
        let mut results: Vec<String> = Vec::new();
        let table = session.find_by_secondary::<Table, TableByCodeScopeTableIndex>((
            code,
            account,
            Name::new(name!("accounts")),
        ))?;

        if let Some(table) = table {
            let mut idx = session.get_index::<KeyValue, KeyValueByScopePrimaryIndex>();
            let lower_bound_lookup_tuple = (table.id, u64::MIN);
            let upper_bound_lookup_tuple = (table.id, u64::MAX);
            let mut itr = idx.range(lower_bound_lookup_tuple, upper_bound_lookup_tuple)?;

            while let Some(kv) = itr.next()? {
                if kv.table_id != table.id {
                    break;
                }

                let balance = Asset::read(kv.value.as_slice(), &mut 0).map_err(|e| {
                    ErrorObjectOwned::owned(400, "balance_read_error", Some(format!("{}", e)))
                })?;

                if let Some(symbol) = &symbol {
                    if balance.symbol().code().to_string().eq(symbol) {
                        results.push(balance.to_string());
                    }
                } else {
                    results.push(balance.to_string());
                }
            }
        }

        serde_json::to_value(results).map_err(|e| {
            ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
        })
    }

    async fn get_currency_stats(
        &self,
        code: Name,
        symbol: String,
    ) -> Result<Value, ErrorObjectOwned> {
        let symbol = symbol.to_uppercase();
        let scope = string_to_symbol(0, &symbol.as_str())
            .map_err(|e| ErrorObjectOwned::owned(400, "invalid_symbol", Some(format!("{}", e))))?
            >> 8;
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let database = controller.database();
        let session = database
            .undo_session() // TODO: use read only session
            .map_err(|e| ErrorObjectOwned::owned(500, "database_error", Some(format!("{}", e))))?;

        let table = session.find_by_secondary::<Table, TableByCodeScopeTableIndex>((
            code,
            Name::new(scope),
            Name::new(name!("stats")),
        ))?;

        if let Some(table) = table {
            let mut idx = session.get_index::<KeyValue, KeyValueByScopePrimaryIndex>();
            let lower_bound_lookup_tuple = (table.id, u64::MIN);
            let upper_bound_lookup_tuple = (table.id, u64::MAX);
            let mut itr = idx.range(lower_bound_lookup_tuple, upper_bound_lookup_tuple)?;
            let next = itr.next()?;

            if let Some(kv) = next {
                let abi = self.get_abi(code.clone()).await?;
                let table_type = abi
                    .get_table_type(&Name::new(name!("stats")))
                    .map_err(|e| {
                        ErrorObjectOwned::owned(400, "invalid_table_name", Some(format!("{}", e)))
                    })?;
                let serializer = AbiSerializer::from_abi(abi).map_err(|e| {
                    ErrorObjectOwned::owned(500, "abi_error", Some(format!("{}", e)))
                })?;
                let stats = serializer
                    .binary_to_variant(&table_type, kv.value.as_slice(), &mut 0)
                    .map_err(|e| {
                        ErrorObjectOwned::owned(
                            400,
                            "get_currency_stats_error",
                            Some(format!("{}", e)),
                        )
                    })?;
                let mut map = Map::new();
                map.insert(symbol, stats);
                return Ok(Value::Object(map));
            }
        }

        Err(ErrorObjectOwned::owned(
            404,
            "currency_stats_not_found",
            Some(format!("Currency stats for {} not found", symbol)),
        ))
    }

    async fn get_info(&self) -> Result<GetInfoResponse, ErrorObjectOwned> {
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let head_block = controller.last_accepted_block();
        let session = controller
            .database()
            .undo_session()
            .map_err(|e| ErrorObjectOwned::owned(500, "database_error", Some(format!("{}", e))))?;
        let total_cpu_weight = ResourceLimitsManager::get_total_cpu_weight(&mut session.clone())
            .map_err(|e| {
                ErrorObjectOwned::owned(500, "resource_limits_error", Some(format!("{}", e)))
            })?;
        let total_net_weight = ResourceLimitsManager::get_total_net_weight(&mut session.clone())
            .map_err(|e| {
                ErrorObjectOwned::owned(500, "resource_limits_error", Some(format!("{}", e)))
            })?;

        Ok(GetInfoResponse {
            server_version: "d133c641".to_owned(),
            chain_id: controller.chain_id(),
            head_block_num: head_block.block_num(),
            last_irreversible_block_num: head_block.block_num(),
            last_irreversible_block_id: head_block.id(),
            head_block_id: head_block.id(),
            head_block_time: head_block.timestamp(),
            head_block_producer: PULSE_NAME,
            virtual_block_cpu_limit: 100, // Placeholder, adjust as needed
            virtual_block_net_limit: 100, // Placeholder, adjust as needed
            block_cpu_limit: 100,         // Placeholder, adjust as needed
            block_net_limit: 100,         // Placeholder, adjust as needed
            server_version_string: "v5.0.3".to_owned(),
            fork_db_head_block_id: head_block.id(),
            fork_db_head_block_num: head_block.block_num(),
            server_full_version_string: "v5.0.3-d133c6413ce8ce2e96096a0513ec25b4a8dbe837"
                .to_owned(), // Mimic EOS here
            total_cpu_weight: total_cpu_weight,
            total_net_weight: total_net_weight,
            earliest_available_block_num: 1,
            last_irreversible_block_time: head_block.timestamp(),
        })
    }

    async fn get_raw_abi(&self, account_name: Name) -> Result<GetRawABIResponse, ErrorObjectOwned> {
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let session = controller
            .database()
            .undo_session() // TODO: use read only session
            .map_err(|e| ErrorObjectOwned::owned(500, "database_error", Some(format!("{}", e))))?;
        let account = session.get::<Account>(account_name.clone()).map_err(|e| {
            ErrorObjectOwned::owned(404, "account_not_found", Some(format!("{}", e)))
        })?;
        let account_metadata = session
            .get::<AccountMetadata>(account_name.clone())
            .map_err(|e| {
                ErrorObjectOwned::owned(404, "account_metadata_not_found", Some(format!("{}", e)))
            })?;

        let mut abi_hash = Digest::default();

        if account.abi.len() > 0 {
            abi_hash = Digest::hash(&account.abi);
        }

        Ok(GetRawABIResponse {
            account_name,
            code_hash: account_metadata.code_hash,
            abi_hash,
            abi: Base64Bytes::new(account.abi.clone()),
        })
    }

    async fn get_raw_block(
        &self,
        block_num_or_id: String,
    ) -> Result<SignedBlock, ErrorObjectOwned> {
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let session = controller
            .database()
            .undo_session() // TODO: use read only session
            .map_err(|e| ErrorObjectOwned::owned(500, "database_error", Some(format!("{}", e))))?;

        if let Ok(n) = block_num_or_id.parse::<u32>() {
            let block = session.get::<SignedBlock>(n).map_err(|e| {
                ErrorObjectOwned::owned(404, "block_not_found", Some(format!("{}", e)))
            })?;
            return Ok(block);
        } else if let Ok(id) = Id::from_str(block_num_or_id.as_str()) {
            let block = session
                .get::<SignedBlock>(BlockHeader::num_from_id(&id))
                .map_err(|e| {
                    ErrorObjectOwned::owned(404, "block_not_found", Some(format!("{}", e)))
                })?;
            return Ok(block);
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
        )
        .map_err(|e| {
            println!("Failed to push transaction: {}", e);
            ErrorObjectOwned::owned(500, "transaction_error", Some(format!("{}", e)))
        })?;

        // Run transaction and revert it
        let controller = self.controller.clone();
        let mut controller = controller.write().await;
        let pending_block_timestamp = BlockTimestamp::now();
        controller
            .push_transaction(&packed_trx, &pending_block_timestamp)
            .map_err(|e| {
                println!("Failed to push transaction: {}", e);
                ErrorObjectOwned::owned(500, "transaction_error", Some(format!("{}", e)))
            })?;

        // Add to mempool
        let mempool_clone = self.mempool.clone();
        let mut mempool = mempool_clone.write().await;
        mempool.add_transaction(&packed_trx);

        // Gossip
        let nm_clone = self.network_manager.clone();
        let nm = nm_clone.read().await;
        let gossipable_msg = Gossipable::new(0, packed_trx.clone())
            .map_err(|e| ErrorObjectOwned::owned(500, "gossip_error", Some(format!("{}", e))))?;
        nm.gossip(gossipable_msg)
            .await
            .map_err(|e| ErrorObjectOwned::owned(500, "gossip_error", Some(format!("{}", e))))?;

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
        let abi = self.get_abi(code.clone()).await?;
        let mut primary = false;
        let table_with_index =
            get_table_index_name(table, index_position, &mut primary).map_err(|e| {
                ErrorObjectOwned::owned(400, "invalid_table_name", Some(format!("{}", e)))
            })?;
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let session = controller
            .database()
            .undo_session() // TODO: use read only session
            .map_err(|e| ErrorObjectOwned::owned(500, "database_error", Some(format!("{}", e))))?;

        if primary {
            pulse_assert(
                table == table_with_index,
                ErrorObjectOwned::owned(
                    400,
                    "invalid_table_name",
                    Some(format!("invalid table name {}", table)),
                ),
            )?;
            let table_index_type = get_table_index_type(&abi, &table).map_err(|e| {
                ErrorObjectOwned::owned(400, "invalid_table_name", Some(format!("{}", e)))
            })?;
            if table_index_type == "i64" || key_type == "i64" || key_type == "name" {
                return get_table_rows_ex(
                    &session,
                    &abi,
                    code,
                    scope,
                    table,
                    limit.0,
                    json,
                    show_payer,
                    lower_bound,
                    upper_bound,
                )
                .map_err(|e| {
                    ErrorObjectOwned::owned(400, "get_table_rows_error", Some(format!("{}", e)))
                });
            }
            return Err(ErrorObjectOwned::owned(
                400,
                "invalid_table_type",
                Some(format!("invalid table index type: {}", table_index_type)),
            ));
        } else {
            return Err(ErrorObjectOwned::owned(
                400,
                "secondary_index_not_supported",
                Some(format!(
                    "secondary index not supported for table: {}",
                    table
                )),
            ));
        }
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

fn get_table_rows_ex(
    session: &UndoSession,
    abi: &AbiDefinition,
    code: Name,
    scope: String,
    table_name: Name,
    limit: i32,
    json: bool,
    show_payer: Option<bool>,
    lower_bound: Option<String>,
    upper_bound: Option<String>,
) -> Result<GetTableRowsResponse, ChainError> {
    let mut response = GetTableRowsResponse::default();
    let scope = Name::from_str(scope.as_str())
        .map_err(|_| ChainError::InvalidArgument(format!("invalid scope name: {}", scope)))?;
    let table = session
        .find_by_secondary::<Table, TableByCodeScopeTableIndex>((code, scope, table_name))?;
    let serializer = AbiSerializer::from_abi(abi.clone()).map_err(|e| {
        ChainError::InvalidArgument(format!("failed to create ABI serializer: {}", e))
    })?;

    if let Some(table) = table {
        let mut idx = session.get_index::<KeyValue, KeyValueByScopePrimaryIndex>();
        let lower_bound_lookup_tuple = (table.id, u64::MIN);
        let upper_bound_lookup_tuple = (table.id, u64::MAX);

        if upper_bound_lookup_tuple < lower_bound_lookup_tuple {
            return Ok(response);
        }

        let mut limit = limit;

        if limit <= 0 || limit > 100 {
            limit = 100;
        }

        let mut itr = idx.range(lower_bound_lookup_tuple, upper_bound_lookup_tuple)?;
        let mut count = 0;
        let table_type = abi.get_table_type(&table_name)?;

        while let Some(kv) = itr.next()? {
            count += 1;

            if count > limit {
                response.more = true;
                break;
            }

            let variant = if json {
                serializer
                    .binary_to_variant(&table_type, kv.value.as_slice(), &mut 0)
                    .map_err(|e| {
                        println!("Failed to convert binary to variant: {}", e);
                        ChainError::InvalidArgument(format!(
                            "failed to convert binary to variant: {}",
                            e
                        ))
                    })?
            } else {
                Value::String(hex::encode(&kv.value))
            };

            if show_payer.is_some() && show_payer.unwrap() {
                response.rows.push(serde_json::json!({
                    "payer": kv.payer,
                    "data": variant,
                }));
            } else {
                response.rows.push(variant);
            }
        }
    }

    Ok(response)
}

fn get_table_index_type(abi: &AbiDefinition, table_name: &Name) -> Result<String, ChainError> {
    for table in abi.tables.iter() {
        if &table.name == table_name {
            return Ok(table.index_type.clone());
        }
    }

    Err(ChainError::InvalidArgument(format!(
        "table '{}' not found in ABI",
        table_name
    )))
}