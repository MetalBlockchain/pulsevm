use std::{str::FromStr, sync::Arc};

use anyhow::Chain;
use jsonrpsee::{
    proc_macros::rpc,
    types::{ErrorObjectOwned, Response, ResponseSuccess},
};
use pulsevm_chainbase::Session;
use pulsevm_serialization::Read;
use serde_json::Value;
use tokio::sync::RwLock;
use tonic::async_trait;

use crate::{
    api::{
        GetAccountResponse, GetTableRowsParams, GetTableRowsResponse, IssueTxResponse,
        PermissionResponse,
    },
    chain::{
        error::ChainError, pulse_assert, AbiDefinition, Account, AccountMetadata, BlockTimestamp, Gossipable, KeyValue, KeyValueByScopePrimaryIndex, Name, Permission, PermissionByOwnerIndex, Table, TableByCodeScopeTableIndex, Transaction
    },
    mempool::Mempool,
};

use super::{Controller, NetworkManager};

#[rpc(server)]
pub trait Rpc {
    #[method(name = "pulsevm.issueTx")]
    async fn issue_tx(&self, tx: &str, encoding: &str)
    -> Result<IssueTxResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getABI")]
    async fn get_abi(&self, account: Name) -> Result<AbiDefinition, ErrorObjectOwned>;

    #[method(name = "pulsevm.getAccount")]
    async fn get_account(&self, name: Name) -> Result<GetAccountResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getTableRows")]
    async fn get_table_rows(
        &self,
        code: Name,
        scope: String,
        table: Name,
        json: bool,
        limit: u32,
        lower_bound: String,
        upper_bound: String,
        key_type: String,
        index_position: String,
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
    async fn get_abi(&self, account: Name) -> Result<AbiDefinition, ErrorObjectOwned> {
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let database = controller.database();
        let session = database
            .session()
            .map_err(|e| ErrorObjectOwned::owned(500, "database_error", Some(format!("{}", e))))?;
        let code_account = session.get::<Account>(account.clone()).map_err(|e| {
            ErrorObjectOwned::owned(404, "account_not_found", Some(format!("{}", e)))
        })?;
        let abi = AbiDefinition::read(&code_account.abi, &mut 0).map_err(|e| {
            ErrorObjectOwned::owned(400, "abi_error", Some(format!("failed to read ABI: {}", e)))
        })?;
        Ok(abi)
    }

    async fn get_account(&self, name: Name) -> Result<GetAccountResponse, ErrorObjectOwned> {
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let database = controller.database();
        let session = database
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
                println!("Failed to push transaction: {}", e);
                ErrorObjectOwned::owned(500, "transaction_error", Some(format!("{}", e)))
            })?;

        // Add to mempool
        let mempool_clone = self.mempool.clone();
        let mut mempool = mempool_clone.write().await;
        mempool.add_transaction(tx.clone());

        // Gossip
        let nm_clone = self.network_manager.clone();
        let nm = nm_clone.read().await;
        let gossipable_msg = Gossipable::new(0, tx.clone()).map_err(|e| {
            ErrorObjectOwned::owned(500, "gossip_error", Some(format!("{}", e)))
        })?;
        nm.gossip(gossipable_msg)
            .await
            .map_err(|e| ErrorObjectOwned::owned(500, "gossip_error", Some(format!("{}", e))))?;

        // Return a simple response
        Ok(IssueTxResponse {
            tx_id: tx.id().to_string(),
        })
    }

    async fn get_table_rows(
        &self,
        code: Name,
        scope: String,
        table: Name,
        json: bool,
        limit: u32,
        lower_bound: String,
        upper_bound: String,
        key_type: String,
        index_position: String,
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
            .session()
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
                    limit,
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
    index_position: String,
    primary: &mut bool,
) -> Result<u64, ChainError> {
    let table = table.as_u64();
    let mut index = table & 0xFFFFFFFFFFFFFFF0u64;
    pulse_assert(
        index == table,
        ChainError::TransactionError(format!("unsupported table name: {}", table)),
    )?;

    *primary = false;
    let mut pos = 0u64;

    if index_position.is_empty()
        || index_position == "first"
        || index_position == "primary"
        || index_position == "one"
    {
        *primary = true;
    } else if index_position.starts_with("sec") || index_position == "two" {
        // second, secondary
    } else if index_position.starts_with("ter") || index_position.starts_with("th") {
        // tertiary, ternary, third, three
        pos = 1;
    } else if index_position.starts_with("fou") {
        // four, fourth
        pos = 2;
    } else if index_position.starts_with("fi") {
        // five, fifth
        pos = 3;
    } else if index_position.starts_with("six") {
        // six, sixth
        pos = 4;
    } else if index_position.starts_with("sev") {
        // seven, seventh
        pos = 5;
    } else if index_position.starts_with("eig") {
        // eight, eighth
        pos = 6;
    } else if index_position.starts_with("nin") {
        // nine, ninth
        pos = 7;
    } else if index_position.starts_with("ten") {
        // ten, tenth
        pos = 8;
    } else {
        pos = index_position.parse::<u64>().map_err(|_| {
            ChainError::TransactionError(format!("invalid index position: {}", index_position))
        })?;

        if pos < 2 {
            *primary = true;
            pos = 0;
        } else {
            pos -= 2;
        }
    }

    index |= pos & 0x000000000000000Fu64;

    Ok(index)
}

fn get_table_rows_ex(
    session: &Session,
    abi: &AbiDefinition,
    code: Name,
    scope: String,
    table_name: Name,
    limit: u32,
    json: bool,
    show_payer: Option<bool>,
    lower_bound: String,
    upper_bound: String,
) -> Result<GetTableRowsResponse, ChainError> {
    let mut response = GetTableRowsResponse::default();
    let scope = Name::from_str(scope.as_str())
        .map_err(|_| ChainError::InvalidArgument(format!("invalid scope name: {}", scope)))?;
    let table = session
        .find_by_secondary::<Table, TableByCodeScopeTableIndex>((code, scope, table_name))?;

    if let Some(table) = table {
        let mut idx = session.get_index::<KeyValue, KeyValueByScopePrimaryIndex>();
        let lower_bound_lookup_tuple = (table.id, u64::MIN);
        let upper_bound_lookup_tuple = (table.id, u64::MAX);

        if upper_bound_lookup_tuple < lower_bound_lookup_tuple {
            return Ok(response);
        }

        let mut limit = limit;

        if limit > 100 {
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
                abi.binary_to_variant(&table_type, &kv.value)?
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
