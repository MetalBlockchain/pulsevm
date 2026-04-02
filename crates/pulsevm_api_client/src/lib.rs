use pulsevm_core::transaction::Transaction;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// JSON-RPC error object.
#[derive(Debug, Deserialize, Clone)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(default)]
    pub data: Option<Value>,
}

/// Full JSON-RPC response envelope.
#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Error)]
pub enum ClientError {
    /// HTTP transport or connection error.
    #[error("HTTP error: {0}")]
    Http(String),

    /// JSON-RPC error returned by the server.
    #[error("RPC error {code}: {message}")]
    Rpc {
        code: i64,
        message: String,
        data: Option<Value>,
    },

    /// Failed to parse the server's response.
    #[error("Response parse error: {0}")]
    Parse(String),
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        ClientError::Http(e.to_string())
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(e: serde_json::Error) -> Self {
        ClientError::Parse(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Parameters for the `pulsevm.getRequiredKeys` method.
#[derive(Debug, Clone, Serialize)]
pub struct GetRequiredKeysParams {
    pub trx: Transaction,
    pub candidate_keys: Vec<String>,
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

struct Transport {
    base_url: String,
    client: reqwest::Client,
}

impl Transport {
    /// Send a POST request with a JSON body and return the raw response bytes.
    async fn post(&self, path: &str, body: &Value) -> Result<(u16, Vec<u8>), ClientError> {
        let url = format!("{}{}", self.base_url, path.trim_end_matches("/").to_string());
        let resp = self.client.post(&url).json(body).send().await?;
        println!("sending POST to {} with body: {}", url, body);
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await?.to_vec();
        Ok((status, bytes))
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Async JSON-RPC client for the PulseVM API.
///
/// Supports `pulsevm.*` RPC methods over HTTP.
pub struct PulseVmClient {
    transport: Transport,
    next_id: AtomicU64,
}

impl PulseVmClient {
    /// Create a client that connects via HTTP.
    ///
    /// ```rust,no_run
    /// let client = pulsevm_rpc_client::PulseVmClient::new("http://127.0.0.1:8080");
    /// ```
    pub fn new(base_url: &str) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        PulseVmClient {
            transport: Transport {
                base_url,
                client: reqwest::Client::new(),
            },
            next_id: AtomicU64::new(0),
        }
    }

    // ------ Internal helpers ------

    /// Build a JSON-RPC 2.0 request envelope.
    fn build_request(&self, method: &str, params: Option<Value>) -> Value {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        })
    }

    /// Send a JSON-RPC call and deserialize the result field.
    async fn rpc_call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<T, ClientError> {
        let request = self.build_request(method, params);
        // JSON-RPC is path-agnostic; POST to "/" (or "/rpc" depending on server).
        let (status, bytes) = self.transport.post("/", &request).await?;
        self.handle_response::<T>(status, &bytes)
    }

    /// Parse the JSON-RPC response envelope, returning the `result` or an error.
    fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        _status: u16,
        bytes: &[u8],
    ) -> Result<T, ClientError> {
        let envelope: JsonRpcResponse =
            serde_json::from_slice(bytes).map_err(|e| {
                ClientError::Parse(format!(
                    "{} — raw body: {}",
                    e,
                    String::from_utf8_lossy(bytes)
                ))
            })?;

        if let Some(err) = envelope.error {
            return Err(ClientError::Rpc {
                code: err.code,
                message: err.message,
                data: err.data,
            });
        }

        let value = envelope.result.ok_or_else(|| {
            ClientError::Parse("JSON-RPC response missing both result and error".to_string())
        })?;

        serde_json::from_value(value).map_err(|e| ClientError::Parse(e.to_string()))
    }

    // ------ Public API ------

    pub async fn get_info(
        &self,
    ) -> Result<Vec<String>, ClientError> {
        self.rpc_call("pulsevm.getInfo", None).await
    }

    /// Get the set of public keys required to sign a transaction.
    ///
    /// Calls `pulsevm.getRequiredKeys` with the given transaction and
    /// candidate public keys. Returns the subset of candidate keys that
    /// are required to authorize the transaction.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), pulsevm_rpc_client::ClientError> {
    /// use pulsevm_rpc_client::*;
    ///
    /// let client = PulseVmClient::new("http://127.0.0.1:8080");
    ///
    /// let trx = Transaction {
    ///     actions: vec![Action {
    ///         account: "pulse".into(),
    ///         name: "newaccount".into(),
    ///         data: "00".into(),
    ///         authorization: vec![Authorization {
    ///             actor: "pulse".into(),
    ///             permission: "active".into(),
    ///         }],
    ///     }],
    ///     expiration: "1970-01-01T00:00:00Z".into(),
    ///     max_net_usage_words: 0,
    ///     max_cpu_usage_ms: 0,
    /// };
    ///
    /// let candidate_keys = vec![
    ///     "PUB_K1_8fsJkG5ka4o1G1wBhySUavHuGqstcjtXMrquxiRWVcYw8ZvZLX".into(),
    /// ];
    ///
    /// let required = client.get_required_keys(&trx, &candidate_keys).await?;
    /// println!("Required keys: {:?}", required);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_required_keys(
        &self,
        trx: &Transaction,
        candidate_keys: &[String],
    ) -> Result<Vec<String>, ClientError> {
        let params = serde_json::to_value(GetRequiredKeysParams {
            trx: trx.clone(),
            candidate_keys: candidate_keys.to_vec(),
        })?;

        self.rpc_call("pulsevm.getRequiredKeys", Some(params)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_constructor() {
        let client = PulseVmClient::new("http://127.0.0.1:8080");
        assert_eq!(client.transport.base_url, "http://127.0.0.1:8080");
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client = PulseVmClient::new("http://127.0.0.1:8080/");
        assert_eq!(client.transport.base_url, "http://127.0.0.1:8080");
    }

    #[test]
    fn handle_response_success() {
        let client = PulseVmClient::new("http://localhost");
        let body = br#"{"jsonrpc":"2.0","id":0,"result":["PUB_K1_8fsJkG5ka4o1G1wBhySUavHuGqstcjtXMrquxiRWVcYw8ZvZLX"]}"#;
        let result: Result<Vec<String>, _> = client.handle_response(200, body);
        let keys = result.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0],
            "PUB_K1_8fsJkG5ka4o1G1wBhySUavHuGqstcjtXMrquxiRWVcYw8ZvZLX"
        );
    }

    #[test]
    fn handle_response_rpc_error() {
        let client = PulseVmClient::new("http://localhost");
        let body = br#"{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"Method not found"}}"#;
        let result: Result<Vec<String>, _> = client.handle_response(200, body);
        match result {
            Err(ClientError::Rpc { code, message, .. }) => {
                assert_eq!(code, -32601);
                assert_eq!(message, "Method not found");
            }
            other => panic!("Expected Rpc error, got: {:?}", other),
        }
    }

    #[test]
    fn build_request_format() {
        let client = PulseVmClient::new("http://localhost");
        let params = serde_json::json!({"trx": {}, "candidate_keys": []});
        let req = client.build_request("pulsevm.getRequiredKeys", Some(params));

        assert_eq!(req["jsonrpc"], "2.0");
        assert_eq!(req["method"], "pulsevm.getRequiredKeys");
        assert!(req["id"].is_u64());
    }

    #[test]
    fn request_id_increments() {
        let client = PulseVmClient::new("http://localhost");
        let r1 = client.build_request("test", Some(serde_json::json!(null)));
        let r2 = client.build_request("test", Some(serde_json::json!(null)));
        assert_eq!(r1["id"].as_u64().unwrap() + 1, r2["id"].as_u64().unwrap());
    }
}