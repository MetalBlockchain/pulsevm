use pulsevm_core::{
    Name,
    crypto::Signature,
    transaction::TransactionCompression,
};
use pulsevm_crypto::{
    AuthorityPublicKey,
    Bytes,
};
use pulsevm_grpc::http::{
    self,
    Element,
};
use serde_json::{
    Value,
    json,
};
use tonic::{
    Response,
    Status,
};

use crate::chain::RpcService;

pub async fn handle_nodeos_request(
    rpc_service: &RpcService,
    url: &str,
    body: &str,
) -> Result<Response<http::HandleSimpleHttpResponse>, Status> {
    let method = extract_method(url).ok_or_else(|| Status::not_found("unknown chain endpoint"))?;

    let (code, body) = match method.as_str() {
        "get_info" => handle_get_info(rpc_service).await,
        "get_account" => handle_get_account(rpc_service, body).await,
        "get_block" => handle_get_block(rpc_service, body).await,
        "get_block_info" => handle_get_block_info(rpc_service, body).await,
        "get_abi" => handle_get_abi(rpc_service, body).await,
        "get_raw_abi" => handle_get_raw_abi(rpc_service, body).await,
        "get_table_rows" => handle_get_table_rows(rpc_service, body).await,
        "get_table_by_scope" => handle_get_table_by_scope(rpc_service, body).await,
        "get_currency_balance" => handle_get_currency_balance(rpc_service, body).await,
        "get_currency_stats" => handle_get_currency_stats(rpc_service, body).await,
        "get_code_hash" => handle_get_code_hash(rpc_service, body).await,
        "get_required_keys" => handle_get_required_keys(rpc_service, body).await,
        "push_transaction" | "send_transaction" => handle_push_transaction(rpc_service, body).await,
        _ => (404, error_body("Not found", "unknown_method")),
    };

    Ok(Response::new(http::HandleSimpleHttpResponse {
        code,
        headers: vec![Element {
            key: "Content-Type".to_string(),
            values: vec!["application/json".to_string()],
        }],
        body: body.into_bytes(),
    }))
}

fn extract_method(url: &str) -> Option<String> {
    url.split("/v1/chain/")
        .nth(1)
        .and_then(|rest| rest.split('?').next())
        .map(|s| s.to_string())
}

fn error_body(message: &str, error_name: &str) -> String {
    json!({
        "code": 500,
        "message": message,
        "error": {
            "code": 0,
            "name": error_name,
            "what": message,
            "details": [{
                "message": message,
                "file": "",
                "line_number": 0,
                "method": ""
            }]
        }
    })
    .to_string()
}

fn get_error_message(e: &jsonrpsee::types::ErrorObjectOwned) -> &str {
    e.message()
}

async fn handle_get_info(rpc_service: &RpcService) -> (i32, String) {
    match rpc_service.get_info_compat().await {
        Ok(info) => (200, serde_json::to_value(info).unwrap().to_string()),
        Err(e) => (500, error_body(get_error_message(&e), "internal_error")),
    }
}

async fn handle_get_account(rpc_service: &RpcService, body: &str) -> (i32, String) {
    let req: AccountRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return (400, error_body("Invalid JSON", "parse_error")),
    };

    match rpc_service
        .get_account_compat(req.account_name, req.expected_core_symbol)
        .await
    {
        Ok(account_info) => (200, account_info.to_string()),
        Err(e) => (500, error_body(get_error_message(&e), "internal_error")),
    }
}

async fn handle_get_block(rpc_service: &RpcService, body: &str) -> (i32, String) {
    let req: BlockRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return (400, error_body("Invalid JSON", "parse_error")),
    };

    match rpc_service.get_block_compat(req.block_num_or_id).await {
        Ok(block) => (200, serde_json::to_value(block).unwrap().to_string()),
        Err(e) => (500, error_body(get_error_message(&e), "internal_error")),
    }
}

async fn handle_get_block_info(rpc_service: &RpcService, body: &str) -> (i32, String) {
    let req: BlockInfoRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return (400, error_body("Invalid JSON", "parse_error")),
    };

    let block = match rpc_service
        .get_block_compat(req.block_num.to_string())
        .await
    {
        Ok(b) => b,
        Err(e) => return (500, error_body(get_error_message(&e), "internal_error")),
    };

    let block_id = match block.id() {
        Ok(id) => id,
        Err(_) => return (500, error_body("Failed to get block ID", "internal_error")),
    };

    let ref_block_prefix_bytes: [u8; 4] = match block_id.as_bytes()[8..12].try_into() {
        Ok(b) => b,
        Err(_) => return (500, error_body("Invalid block ID", "internal_error")),
    };
    let ref_block_prefix = u32::from_le_bytes(ref_block_prefix_bytes);

    let producer = &block.signed_block_header.header.producer;
    let transaction_mroot = &block.signed_block_header.header.transaction_mroot;
    let action_mroot = &block.signed_block_header.header.action_mroot;
    let timestamp_str = format!("{:?}", block.timestamp().to_time_point());

    let block_info = json!({
        "block_num": req.block_num,
        "ref_block_num": (req.block_num & 0xffff) as u16,
        "id": block_id.to_string(),
        "timestamp": timestamp_str,
        "producer": producer.to_string(),
        "confirmed": 0,
        "previous": block.previous_id().to_string(),
        "transaction_mroot": transaction_mroot.to_string(),
        "action_mroot": action_mroot.to_string(),
        "schedule_version": 0,
        "producer_signature": "SIG_K1_",
        "ref_block_prefix": ref_block_prefix,
        "header_extensions": [],
        "new_producers": Value::Null,
    });

    (200, block_info.to_string())
}

async fn handle_get_abi(rpc_service: &RpcService, body: &str) -> (i32, String) {
    let req: AccountRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return (400, error_body("Invalid JSON", "parse_error")),
    };

    let abi = match rpc_service.get_abi_compat(req.account_name).await {
        Ok(a) => a,
        Err(e) => return (500, error_body(get_error_message(&e), "internal_error")),
    };

    let response = json!({
        "account_name": req.account_name.to_string(),
        "abi": abi
    });

    (200, response.to_string())
}

async fn handle_get_raw_abi(rpc_service: &RpcService, body: &str) -> (i32, String) {
    let req: AccountRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return (400, error_body("Invalid JSON", "parse_error")),
    };

    let raw_abi = match rpc_service.get_raw_abi_compat(req.account_name).await {
        Ok(a) => a,
        Err(e) => return (500, error_body(get_error_message(&e), "internal_error")),
    };

    (200, serde_json::to_value(raw_abi).unwrap().to_string())
}

async fn handle_get_table_rows(rpc_service: &RpcService, body: &str) -> (i32, String) {
    let req: TableRowsRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return (400, error_body("Invalid JSON", "parse_error")),
    };

    let key_type = req.key_type.unwrap_or_default();

    let rows = match rpc_service
        .get_table_rows_compat(
            req.json.or(Some(true)),
            req.code,
            req.scope,
            req.table,
            req.table_key,
            req.lower_bound.and_then(|s| {
                if s.is_empty() {
                    None
                } else {
                    Some(pulsevm_core::utils::StringFlex(s))
                }
            }),
            req.upper_bound.and_then(|s| {
                if s.is_empty() {
                    None
                } else {
                    Some(pulsevm_core::utils::StringFlex(s))
                }
            }),
            req.limit.and_then(|l| {
                if l == 0 {
                    None
                } else {
                    Some(pulsevm_core::utils::I32Flex(l as i32))
                }
            }),
            key_type,
            req.index_position.and_then(|i| {
                if i == 0 {
                    None
                } else {
                    Some(pulsevm_core::utils::I32Flex(i as i32))
                }
            }),
            req.encode_type,
            req.reverse.or(Some(false)),
            req.show_payer.or(Some(false)),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return (500, error_body(get_error_message(&e), "internal_error")),
    };

    (200, rows.to_string())
}

async fn handle_get_table_by_scope(rpc_service: &RpcService, body: &str) -> (i32, String) {
    let req: TableByScopeRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return (400, error_body("Invalid JSON", "parse_error")),
    };

    let tables = match rpc_service
        .get_table_by_scope_compat(
            req.code,
            req.table,
            req.lower_bound.and_then(|s| {
                if s.is_empty() {
                    None
                } else {
                    Some(pulsevm_core::utils::StringFlex(s))
                }
            }),
            req.upper_bound.and_then(|s| {
                if s.is_empty() {
                    None
                } else {
                    Some(pulsevm_core::utils::StringFlex(s))
                }
            }),
            req.limit.and_then(|l| {
                if l == 0 {
                    None
                } else {
                    Some(pulsevm_core::utils::I32Flex(l as i32))
                }
            }),
            req.reverse.or(Some(false)),
        )
        .await
    {
        Ok(t) => t,
        Err(e) => return (500, error_body(get_error_message(&e), "internal_error")),
    };

    (200, tables.to_string())
}

async fn handle_get_currency_balance(rpc_service: &RpcService, body: &str) -> (i32, String) {
    let req: CurrencyBalanceRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return (400, error_body("Invalid JSON", "parse_error")),
    };

    let balance = match rpc_service
        .get_currency_balance_compat(req.code, req.account, req.symbol)
        .await
    {
        Ok(b) => b,
        Err(e) => return (500, error_body(get_error_message(&e), "internal_error")),
    };

    (200, balance.to_string())
}

async fn handle_get_currency_stats(rpc_service: &RpcService, body: &str) -> (i32, String) {
    let req: CurrencyStatsRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return (400, error_body("Invalid JSON", "parse_error")),
    };

    let stats = match rpc_service
        .get_currency_stats_compat(req.code, req.symbol)
        .await
    {
        Ok(s) => s,
        Err(e) => return (500, error_body(get_error_message(&e), "internal_error")),
    };

    (200, stats.to_string())
}

async fn handle_get_code_hash(rpc_service: &RpcService, body: &str) -> (i32, String) {
    let req: AccountRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return (400, error_body("Invalid JSON", "parse_error")),
    };

    let code_hash = match rpc_service.get_code_hash_compat(req.account_name).await {
        Ok(c) => c,
        Err(e) => return (500, error_body(get_error_message(&e), "internal_error")),
    };

    (200, serde_json::to_value(code_hash).unwrap().to_string())
}

async fn handle_get_required_keys(rpc_service: &RpcService, body: &str) -> (i32, String) {
    let req: RequiredKeysRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return (400, error_body("Invalid JSON", "parse_error")),
    };

    let keys = match rpc_service
        .get_required_keys_compat(req.transaction, req.available_keys)
        .await
    {
        Ok(k) => k,
        Err(e) => return (500, error_body(get_error_message(&e), "internal_error")),
    };

    let response = json!({
        "required_keys": keys
    });

    (200, response.to_string())
}

async fn handle_push_transaction(rpc_service: &RpcService, body: &str) -> (i32, String) {
    let req: PushTransactionRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return (400, error_body("Invalid JSON", "parse_error")),
    };

    let result = match rpc_service
        .issue_tx_compat(
            req.signatures,
            req.compression,
            req.packed_context_free_data,
            req.packed_trx,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return (500, error_body(get_error_message(&e), "transaction_error")),
    };

    let response = json!({
        "transaction_id": result.tx_id.to_string()
    });

    (200, response.to_string())
}

// Request/Response types for nodeos compatibility

#[derive(serde::Deserialize)]
struct AccountRequest {
    account_name: Name,
    #[serde(default)]
    expected_core_symbol: Option<String>,
}

#[derive(serde::Deserialize)]
struct BlockRequest {
    block_num_or_id: String,
}

#[derive(serde::Deserialize)]
struct BlockInfoRequest {
    block_num: u32,
}

#[derive(serde::Deserialize)]
struct TableRowsRequest {
    #[serde(default)]
    json: Option<bool>,
    code: Name,
    scope: String,
    table: Name,
    #[serde(default)]
    table_key: Option<String>,
    #[serde(default)]
    lower_bound: Option<String>,
    #[serde(default)]
    upper_bound: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    key_type: Option<String>,
    #[serde(default)]
    index_position: Option<u32>,
    #[serde(default)]
    encode_type: Option<String>,
    #[serde(default)]
    reverse: Option<bool>,
    #[serde(default)]
    show_payer: Option<bool>,
}

#[derive(serde::Deserialize)]
struct TableByScopeRequest {
    code: Name,
    table: Name,
    #[serde(default)]
    lower_bound: Option<String>,
    #[serde(default)]
    upper_bound: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    reverse: Option<bool>,
}

#[derive(serde::Deserialize)]
struct CurrencyBalanceRequest {
    code: Name,
    account: Name,
    #[serde(default)]
    symbol: Option<String>,
}

#[derive(serde::Deserialize)]
struct CurrencyStatsRequest {
    code: Name,
    symbol: String,
}

#[derive(serde::Deserialize)]
struct RequiredKeysRequest {
    transaction: pulsevm_core::transaction::Transaction,
    #[serde(rename = "available_keys")]
    available_keys: std::collections::BTreeSet<AuthorityPublicKey>,
}

#[derive(serde::Deserialize)]
struct PushTransactionRequest {
    signatures: Vec<Signature>,
    #[serde(default = "default_compression")]
    compression: TransactionCompression,
    #[serde(default)]
    packed_context_free_data: Bytes,
    packed_trx: Bytes,
}

fn default_compression() -> TransactionCompression {
    TransactionCompression::None
}
