use std::{iter::chain, sync::Mutex};

use actix_web::{HttpResponse, get, post, web};
use pulsevm_core::{id::Id, transaction::Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use spdlog::info;

use crate::manager::{ManagerError, WalletManager};

/// Shared state for the HTTP server.
pub struct AppState {
    pub manager: Mutex<WalletManager>,
}

// ---------- Error response format (matches EOSIO error format) ----------

#[derive(Serialize)]
struct ErrorDetail {
    message: String,
    file: String,
    line_number: u32,
    method: String,
}

#[derive(Serialize)]
struct ErrorBody {
    code: u32,
    name: String,
    what: String,
    details: Vec<ErrorDetail>,
}

#[derive(Serialize)]
struct ErrorResponse {
    code: u16,
    message: String,
    error: ErrorBody,
}

fn error_response(
    status: u16,
    code: u32,
    name: &str,
    what: &str,
    detail_msg: &str,
) -> HttpResponse {
    let resp = ErrorResponse {
        code: status,
        message: match status {
            404 => "Not Found".to_string(),
            500 => "Internal Service Error".to_string(),
            _ => "Error".to_string(),
        },
        error: ErrorBody {
            code,
            name: name.to_string(),
            what: what.to_string(),
            details: vec![ErrorDetail {
                message: detail_msg.to_string(),
                file: "wallet_manager.rs".to_string(),
                line_number: 0,
                method: String::new(),
            }],
        },
    };
    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status)
            .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR),
    )
    .json(resp)
}

fn manager_err_to_response(e: ManagerError) -> HttpResponse {
    match &e {
        ManagerError::WalletAlreadyExists(_) => error_response(
            500,
            3120001,
            "wallet_exist_exception",
            "Wallet already exists",
            &e.to_string(),
        ),
        ManagerError::WalletNotFound(_) => error_response(
            500,
            3120002,
            "wallet_nonexistent_exception",
            "Nonexistent wallet",
            &e.to_string(),
        ),
        ManagerError::WalletError(we) => match we {
            crate::wallet::WalletError::Locked => error_response(
                500,
                3120003,
                "wallet_locked_exception",
                "Wallet locked",
                &e.to_string(),
            ),
            crate::wallet::WalletError::InvalidPassword(_) => error_response(
                500,
                3120005,
                "wallet_invalid_password_exception",
                "Invalid wallet password",
                &e.to_string(),
            ),
            _ => error_response(
                500,
                3120000,
                "wallet_exception",
                "Wallet exception",
                &e.to_string(),
            ),
        },
        ManagerError::NoUnlockedWallets => error_response(
            500,
            3120003,
            "wallet_locked_exception",
            "Wallet locked",
            &e.to_string(),
        ),
        ManagerError::PublicKeyNotFound(_) => error_response(
            500,
            3120004,
            "wallet_missing_pub_key_exception",
            "Missing public key",
            &e.to_string(),
        ),
        _ => error_response(
            500,
            3120000,
            "wallet_exception",
            "Wallet exception",
            &e.to_string(),
        ),
    }
}

// ---------- Request/Response types ----------

#[derive(Deserialize)]
struct UnlockRequest(String, String); // [name, password]

#[derive(Deserialize)]
struct ImportKeyRequest(String, String); // [name, wif_key]

#[derive(Deserialize)]
struct RemoveKeyRequest(String, String, String); // [name, password, public_key]

#[derive(Deserialize)]
struct ListKeysRequest(String, String); // [name, password]

#[derive(Deserialize)]
struct CreateKeyRequest(String, String); // [name, key_type] (key_type ignored, always K1)

#[derive(Deserialize)]
struct SignDigestRequest {
    digest: String,
    public_key: String,
}

#[derive(Deserialize)]
struct SignTransactionRequest(Transaction, Vec<String>, Id); // [transaction, public_keys, chain_id]

// ---------- Endpoint handlers ----------

/// POST /v1/wallet/create
/// Body: "wallet_name" (JSON string)
/// Returns: "password" (JSON string)
#[post("/v1/wallet/create")]
async fn wallet_create(data: web::Data<AppState>, body: web::Json<String>) -> HttpResponse {
    let name = body.into_inner();
    let mut mgr = data.manager.lock().unwrap();
    match mgr.create(&name) {
        Ok(password) => HttpResponse::Created().json(password),
        Err(e) => manager_err_to_response(e),
    }
}

/// POST /v1/wallet/open
/// Body: "wallet_name" (JSON string)
#[post("/v1/wallet/open")]
async fn wallet_open(data: web::Data<AppState>, body: web::Json<String>) -> HttpResponse {
    let name = body.into_inner();
    let mut mgr = data.manager.lock().unwrap();
    match mgr.open(&name) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({})),
        Err(e) => manager_err_to_response(e),
    }
}

/// POST /v1/wallet/lock
/// Body: "wallet_name" (JSON string)
#[post("/v1/wallet/lock")]
async fn wallet_lock(data: web::Data<AppState>, body: web::Json<String>) -> HttpResponse {
    let name = body.into_inner();
    let mut mgr = data.manager.lock().unwrap();
    match mgr.lock(&name) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({})),
        Err(e) => manager_err_to_response(e),
    }
}

/// POST /v1/wallet/lock_all
#[post("/v1/wallet/lock_all")]
async fn wallet_lock_all(data: web::Data<AppState>) -> HttpResponse {
    let mut mgr = data.manager.lock().unwrap();
    match mgr.lock_all() {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({})),
        Err(e) => manager_err_to_response(e),
    }
}

/// POST /v1/wallet/unlock
/// Body: ["wallet_name", "password"]
#[post("/v1/wallet/unlock")]
async fn wallet_unlock(data: web::Data<AppState>, body: web::Json<UnlockRequest>) -> HttpResponse {
    let req = body.into_inner();
    let mut mgr = data.manager.lock().unwrap();
    match mgr.unlock(&req.0, &req.1) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({})),
        Err(e) => manager_err_to_response(e),
    }
}

/// POST /v1/wallet/import_key
/// Body: ["wallet_name", "wif_private_key"]
#[post("/v1/wallet/import_key")]
async fn wallet_import_key(
    data: web::Data<AppState>,
    body: web::Json<ImportKeyRequest>,
) -> HttpResponse {
    let req = body.into_inner();
    let mut mgr = data.manager.lock().unwrap();
    match mgr.import_key(&req.0, &req.1) {
        Ok(()) => HttpResponse::Created().json(serde_json::json!({})),
        Err(e) => manager_err_to_response(e),
    }
}

/// POST /v1/wallet/remove_key
/// Body: ["wallet_name", "password", "public_key"]
#[post("/v1/wallet/remove_key")]
async fn wallet_remove_key(
    data: web::Data<AppState>,
    body: web::Json<RemoveKeyRequest>,
) -> HttpResponse {
    let req = body.into_inner();
    let mut mgr = data.manager.lock().unwrap();
    match mgr.remove_key(&req.0, &req.1, &req.2) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({})),
        Err(e) => manager_err_to_response(e),
    }
}

/// POST /v1/wallet/create_key
/// Body: ["wallet_name", "key_type"]
#[post("/v1/wallet/create_key")]
async fn wallet_create_key(
    data: web::Data<AppState>,
    body: web::Json<CreateKeyRequest>,
) -> HttpResponse {
    let req = body.into_inner();
    let mut mgr = data.manager.lock().unwrap();
    match mgr.create_key(&req.0) {
        Ok(pub_key) => HttpResponse::Created().json(pub_key),
        Err(e) => manager_err_to_response(e),
    }
}

/// POST /v1/wallet/list_wallets
#[post("/v1/wallet/list_wallets")]
async fn wallet_list_wallets(data: web::Data<AppState>) -> HttpResponse {
    let mut mgr = data.manager.lock().unwrap();
    let wallets = mgr.list_wallets();
    HttpResponse::Ok().json(wallets)
}

/// Also support GET for list_wallets (cleos uses GET sometimes)
#[get("/v1/wallet/list_wallets")]
async fn wallet_list_wallets_get(data: web::Data<AppState>) -> HttpResponse {
    let mut mgr = data.manager.lock().unwrap();
    let wallets = mgr.list_wallets();
    HttpResponse::Ok().json(wallets)
}

/// POST /v1/wallet/list_keys
/// Body: ["wallet_name", "password"]
#[post("/v1/wallet/list_keys")]
async fn wallet_list_keys(
    data: web::Data<AppState>,
    body: web::Json<ListKeysRequest>,
) -> HttpResponse {
    let req = body.into_inner();
    let mut mgr = data.manager.lock().unwrap();
    match mgr.list_keys(&req.0, &req.1) {
        Ok(keys) => {
            // Return as array of [pub_key, priv_key] pairs (EOSIO format)
            let pairs: Vec<Vec<String>> = keys
                .into_iter()
                .map(|(pub_k, priv_k)| vec![pub_k, priv_k])
                .collect();
            HttpResponse::Ok().json(pairs)
        }
        Err(e) => manager_err_to_response(e),
    }
}

/// POST /v1/wallet/get_public_keys
#[post("/v1/wallet/get_public_keys")]
async fn wallet_get_public_keys(data: web::Data<AppState>) -> HttpResponse {
    let mut mgr = data.manager.lock().unwrap();
    match mgr.get_public_keys() {
        Ok(keys) => HttpResponse::Ok().json(keys),
        Err(e) => manager_err_to_response(e),
    }
}

/// GET /v1/wallet/get_public_keys
#[get("/v1/wallet/get_public_keys")]
async fn wallet_get_public_keys_get(data: web::Data<AppState>) -> HttpResponse {
    let mut mgr = data.manager.lock().unwrap();
    match mgr.get_public_keys() {
        Ok(keys) => HttpResponse::Ok().json(keys),
        Err(e) => manager_err_to_response(e),
    }
}

/// POST /v1/wallet/set_timeout
/// Body: integer (seconds)
#[post("/v1/wallet/set_timeout")]
async fn wallet_set_timeout(data: web::Data<AppState>, body: web::Json<u64>) -> HttpResponse {
    let secs = body.into_inner();
    let mut mgr = data.manager.lock().unwrap();
    mgr.set_timeout(secs);
    HttpResponse::Ok().json(serde_json::json!({}))
}

/// POST /v1/wallet/sign_digest
/// Body: ["digest_hex", "public_key"]
#[post("/v1/wallet/sign_digest")]
async fn wallet_sign_digest(
    data: web::Data<AppState>,
    body: web::Json<(String, String)>,
) -> HttpResponse {
    let (digest_hex, public_key) = body.into_inner();

    let digest_bytes = match hex::decode(&digest_hex) {
        Ok(b) => b,
        Err(_) => {
            return error_response(
                500,
                3120000,
                "wallet_exception",
                "Wallet exception",
                "Invalid digest hex",
            );
        }
    };

    let mut mgr = data.manager.lock().unwrap();
    match mgr.sign_digest(&digest_bytes, &[public_key]) {
        Ok(sigs) => {
            // Return the first signature
            if let Some(sig) = sigs.values().next() {
                HttpResponse::Ok().json(sig)
            } else {
                error_response(
                    500,
                    3120004,
                    "wallet_missing_pub_key_exception",
                    "Missing public key",
                    "No signature produced",
                )
            }
        }
        Err(e) => manager_err_to_response(e),
    }
}

/// POST /v1/wallet/sign_transaction
/// Body: [transaction_json, [public_keys], "chain_id"]
#[post("/v1/wallet/sign_transaction")]
async fn wallet_sign_transaction(
    data: web::Data<AppState>,
    body: web::Json<SignTransactionRequest>,
) -> HttpResponse {
    let req = body.into_inner();
    let _transaction = req.0;
    let public_keys = req.1;
    let chain_id = req.2;
    let digest = _transaction.signing_digest(&chain_id, &Vec::new()).unwrap(); // TODO: Handle error gracefully

    let mut mgr = data.manager.lock().unwrap();
    match mgr.sign_digest(&digest, &public_keys) {
        Ok(sigs) => {
            // Attach signatures to the transaction
            let mut map = Map::new();
            let sig_array: Vec<String> = sigs.values().cloned().collect();
            map.insert("signatures".to_string(), serde_json::json!(sig_array));
            HttpResponse::Ok().json(map)
        }
        Err(e) => manager_err_to_response(e),
    }
}

/// POST /v1/keosd/stop - Shutdown the daemon
#[post("/v1/keosd/stop")]
async fn keosd_stop() -> HttpResponse {
    info!("Received stop request, shutting down...");
    // In production, this would trigger a graceful shutdown.
    // For now, we just acknowledge it.
    std::process::exit(0);
}

/// Configure all wallet API routes.
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(wallet_create)
        .service(wallet_open)
        .service(wallet_lock)
        .service(wallet_lock_all)
        .service(wallet_unlock)
        .service(wallet_import_key)
        .service(wallet_remove_key)
        .service(wallet_create_key)
        .service(wallet_list_wallets)
        .service(wallet_list_wallets_get)
        .service(wallet_list_keys)
        .service(wallet_get_public_keys)
        .service(wallet_get_public_keys_get)
        .service(wallet_set_timeout)
        .service(wallet_sign_digest)
        .service(wallet_sign_transaction)
        .service(keosd_stop);
}
