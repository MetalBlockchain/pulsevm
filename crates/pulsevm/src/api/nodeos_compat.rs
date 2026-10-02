use pulsevm_core::{
    Name,
    crypto::Signature,
    transaction::TransactionCompression,
    utils::StringFlex,
};
use pulsevm_crypto::{
    AuthorityPublicKey,
    Bytes,
};
use pulsevm_grpc::http::{
    self,
    Element,
};
use serde::{
    Deserialize,
    Deserializer,
    de::Error as _,
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

    match rpc_service.get_block_compat(req.block_num_or_id.0).await {
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

    let block_info = json!({
        "block_num": req.block_num,
        "ref_block_num": (req.block_num & 0xffff) as u16,
        "id": block_id.to_string(),
        "timestamp": block.timestamp(),
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
            req.scope.0,
            req.table,
            req.table_key,
            req.lower_bound.filter(|s| !s.0.is_empty()),
            req.upper_bound.filter(|s| !s.0.is_empty()),
            req.limit.and_then(|l| {
                if l == 0 {
                    None
                } else {
                    Some(pulsevm_core::utils::I32Flex(l as i32))
                }
            }),
            key_type,
            req.index_position.filter(|s| !s.0.is_empty()),
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
            req.lower_bound.filter(|s| !s.0.is_empty()),
            req.upper_bound.filter(|s| !s.0.is_empty()),
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

// nodeos parses request bodies through fc::variant, which converts scalars
// between JSON types: string fields also accept numbers, integer fields also
// accept numeric strings, and bool fields also accept "true"/"false" or an
// integer. eosjs sends `block_num_or_id` as a number and wharfkit sends
// `index_position` as a name such as "secondary", so the compat layer has to
// accept the same forms.

#[derive(serde::Deserialize)]
struct BlockRequest {
    block_num_or_id: StringFlex,
}

#[derive(serde::Deserialize)]
struct BlockInfoRequest {
    #[serde(deserialize_with = "u32_flex")]
    block_num: u32,
}

#[derive(serde::Deserialize)]
struct TableRowsRequest {
    #[serde(default, deserialize_with = "opt_bool_flex")]
    json: Option<bool>,
    code: Name,
    scope: StringFlex,
    table: Name,
    #[serde(default)]
    table_key: Option<String>,
    #[serde(default)]
    lower_bound: Option<StringFlex>,
    #[serde(default)]
    upper_bound: Option<StringFlex>,
    #[serde(default, deserialize_with = "opt_u32_flex")]
    limit: Option<u32>,
    #[serde(default)]
    key_type: Option<String>,
    /// A position ("2") or a name ("secondary"); resolved like nodeos's
    /// get_table_index_name by the table reader.
    #[serde(default)]
    index_position: Option<StringFlex>,
    #[serde(default)]
    encode_type: Option<String>,
    #[serde(default, deserialize_with = "opt_bool_flex")]
    reverse: Option<bool>,
    #[serde(default, deserialize_with = "opt_bool_flex")]
    show_payer: Option<bool>,
}

#[derive(serde::Deserialize)]
struct TableByScopeRequest {
    code: Name,
    table: Name,
    #[serde(default)]
    lower_bound: Option<StringFlex>,
    #[serde(default)]
    upper_bound: Option<StringFlex>,
    #[serde(default, deserialize_with = "opt_u32_flex")]
    limit: Option<u32>,
    #[serde(default, deserialize_with = "opt_bool_flex")]
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

fn u32_flex<'de, D: Deserializer<'de>>(de: D) -> Result<u32, D::Error> {
    opt_u32_flex(de)?.ok_or_else(|| D::Error::custom("expected an unsigned integer"))
}

fn opt_u32_flex<'de, D: Deserializer<'de>>(de: D) -> Result<Option<u32>, D::Error> {
    let value = match Option::<Value>::deserialize(de)? {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
        Some(Value::String(s)) => s.parse::<u32>().ok(),
        Some(_) => None,
    };
    value
        .map(Some)
        .ok_or_else(|| D::Error::custom("expected a uint32 as a number or a numeric string"))
}

fn opt_bool_flex<'de, D: Deserializer<'de>>(de: D) -> Result<Option<bool>, D::Error> {
    match Option::<Value>::deserialize(de)? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(b)),
        Some(Value::String(s)) if s == "true" => Ok(Some(true)),
        Some(Value::String(s)) if s == "false" => Ok(Some(false)),
        Some(Value::Number(n)) => Ok(Some(n.as_f64() != Some(0.0))),
        Some(_) => Err(D::Error::custom(
            r#"expected a bool, "true"/"false", or a number"#,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, serde_json::Error> {
        serde_json::from_str(body)
    }

    #[test]
    fn block_num_or_id_accepts_number_string_and_id() {
        for (body, expected) in [
            (r#"{"block_num_or_id":1}"#, "1"),
            (r#"{"block_num_or_id":"1"}"#, "1"),
            (
                r#"{"block_num_or_id":"0000000164b0f0ba1d6e7c3a35b2b3c62e5f1bdc6e8b8c06a0d3cab5a0f1e6d1"}"#,
                "0000000164b0f0ba1d6e7c3a35b2b3c62e5f1bdc6e8b8c06a0d3cab5a0f1e6d1",
            ),
        ] {
            let req: BlockRequest = parse(body).unwrap();
            assert_eq!(req.block_num_or_id.0, expected, "{body}");
        }
    }

    #[test]
    fn block_info_block_num_accepts_number_and_numeric_string() {
        for body in [r#"{"block_num":403625033}"#, r#"{"block_num":"403625033"}"#] {
            let req: BlockInfoRequest = parse(body).unwrap();
            assert_eq!(req.block_num, 403_625_033, "{body}");
        }
        // nodeos's get_block_info_params.block_num is a uint32: no block ids,
        // negatives or out-of-range values.
        for body in [
            r#"{"block_num":"0000000164b0f0ba1d6e7c3a35b2b3c62e5f1bdc6e8b8c06a0d3cab5a0f1e6d1"}"#,
            r#"{"block_num":"abc"}"#,
            r#"{"block_num":-1}"#,
            r#"{"block_num":4294967296}"#,
            r#"{}"#,
        ] {
            assert!(parse::<BlockInfoRequest>(body).is_err(), "{body}");
        }
    }

    #[test]
    fn table_rows_accepts_nodeos_scalar_forms() {
        let req: TableRowsRequest = parse(
            r#"{
                "json":"true",
                "code":"eosio.token",
                "scope":1234,
                "table":"accounts",
                "lower_bound":5,
                "upper_bound":"18446744073709551615",
                "limit":"100",
                "key_type":"name",
                "index_position":"secondary",
                "reverse":"false",
                "show_payer":1,
                "time_limit_ms":10
            }"#,
        )
        .unwrap();
        assert_eq!(req.json, Some(true));
        assert_eq!(req.scope.0, "1234");
        assert_eq!(req.lower_bound.unwrap().0, "5");
        assert_eq!(req.upper_bound.unwrap().0, "18446744073709551615");
        assert_eq!(req.limit, Some(100));
        assert_eq!(req.key_type.as_deref(), Some("name"));
        assert_eq!(req.index_position.unwrap().0, "secondary");
        assert_eq!(req.reverse, Some(false));
        assert_eq!(req.show_payer, Some(true));

        let req: TableRowsRequest = parse(
            r#"{"json":false,"code":"eosio","scope":"eosio","table":"global","limit":1,"index_position":2,"reverse":true}"#,
        )
        .unwrap();
        assert_eq!(req.json, Some(false));
        assert_eq!(req.limit, Some(1));
        assert_eq!(req.index_position.unwrap().0, "2");
        assert_eq!(req.reverse, Some(true));

        for position in [
            "primary",
            "secondary",
            "tertiary",
            "fourth",
            "fifth",
            "sixth",
            "seventh",
            "eighth",
            "ninth",
            "tenth",
        ] {
            let body = format!(
                r#"{{"code":"eosio","scope":"eosio","table":"global","index_position":"{position}"}}"#
            );
            let req: TableRowsRequest = parse(&body).unwrap();
            assert_eq!(req.index_position.unwrap().0, position);
        }

        for body in [
            r#"{"code":"eosio","scope":"eosio","table":"global","json":"yes"}"#,
            r#"{"code":"eosio","scope":"eosio","table":"global","limit":"ten"}"#,
            r#"{"code":"eosio","scope":"eosio","table":"global","limit":-1}"#,
        ] {
            assert!(parse::<TableRowsRequest>(body).is_err(), "{body}");
        }
    }

    #[test]
    fn table_by_scope_accepts_nodeos_scalar_forms() {
        let req: TableByScopeRequest = parse(
            r#"{"code":"eosio.token","table":"accounts","lower_bound":0,"upper_bound":"","limit":"25","reverse":"true"}"#,
        )
        .unwrap();
        assert_eq!(req.lower_bound.unwrap().0, "0");
        assert_eq!(req.upper_bound.unwrap().0, "");
        assert_eq!(req.limit, Some(25));
        assert_eq!(req.reverse, Some(true));
    }

    #[test]
    fn required_keys_accepts_legacy_and_modern_key_spellings() {
        let legacy = "EOS5XPRJt1zUiLH98rtDLj9TnPi52DLQ7gTZbkRvBGJXLv6ak6Cdq";
        let modern = AuthorityPublicKey::from_string(legacy).unwrap().to_string();
        assert!(modern.starts_with("PUB_K1_"));
        let body = format!(
            r#"{{
                "transaction": {{
                    "expiration":"2023-01-01T00:00:00",
                    "ref_block_num":0,
                    "ref_block_prefix":0,
                    "max_net_usage_words":0,
                    "max_cpu_usage_ms":0,
                    "delay_sec":0,
                    "context_free_actions":[],
                    "actions":[],
                    "transaction_extensions":[]
                }},
                "available_keys":["{legacy}","{modern}"]
            }}"#
        );
        let req: RequiredKeysRequest = parse(&body).unwrap();
        // Both spellings name the same key.
        assert_eq!(req.available_keys.len(), 1);
        assert_eq!(
            req.available_keys.iter().next().unwrap().to_string(),
            modern
        );
    }
}
