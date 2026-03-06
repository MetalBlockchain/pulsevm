use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// EOSIO-compatible error detail returned by keosd.
#[derive(Debug, Deserialize, Clone)]
pub struct KeosdErrorDetail {
    pub message: String,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line_number: u32,
    #[serde(default)]
    pub method: String,
}

/// EOSIO-compatible error body returned by keosd.
#[derive(Debug, Deserialize, Clone)]
pub struct KeosdErrorBody {
    pub code: u32,
    pub name: String,
    pub what: String,
    #[serde(default)]
    pub details: Vec<KeosdErrorDetail>,
}

/// Full error response from keosd.
#[derive(Debug, Deserialize, Clone)]
pub struct KeosdErrorResponse {
    pub code: u16,
    pub message: String,
    pub error: KeosdErrorBody,
}

#[derive(Debug, Error)]
pub enum ClientError {
    /// HTTP transport or connection error.
    #[error("HTTP error: {0}")]
    Http(String),

    /// Server returned an EOSIO-formatted error.
    #[error("keosd error {code}: {name} - {what}")]
    Keosd {
        code: u32,
        name: String,
        what: String,
        details: Vec<KeosdErrorDetail>,
    },

    /// Failed to parse the server's response.
    #[error("Response parse error: {0}")]
    Parse(String),

    /// Unix socket I/O error.
    #[error("Unix socket error: {0}")]
    UnixSocket(String),
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

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::UnixSocket(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Transport abstraction
// ---------------------------------------------------------------------------

enum Transport {
    /// TCP connection via reqwest.
    Tcp {
        base_url: String,
        client: reqwest::Client,
    },
    /// Unix domain socket connection using raw HTTP over UDS.
    Unix {
        socket_path: PathBuf,
    },
}

impl Transport {
    /// Send a POST request with a JSON body and return the raw response bytes.
    async fn post(&self, path: &str, body: &Value) -> Result<(u16, Vec<u8>), ClientError> {
        match self {
            Transport::Tcp { base_url, client } => {
                let url = format!("{}{}", base_url, path);
                let resp = client
                    .post(&url)
                    .json(body)
                    .send()
                    .await?;
                let status = resp.status().as_u16();
                let bytes = resp.bytes().await?.to_vec();
                Ok((status, bytes))
            }
            Transport::Unix { socket_path } => {
                unix_post(socket_path, path, body).await
            }
        }
    }

    /// Send a GET request and return the raw response bytes.
    async fn get(&self, path: &str) -> Result<(u16, Vec<u8>), ClientError> {
        match self {
            Transport::Tcp { base_url, client } => {
                let url = format!("{}{}", base_url, path);
                let resp = client.get(&url).send().await?;
                let status = resp.status().as_u16();
                let bytes = resp.bytes().await?.to_vec();
                Ok((status, bytes))
            }
            Transport::Unix { socket_path } => {
                unix_get(socket_path, path).await
            }
        }
    }
}

/// Perform an HTTP POST over a Unix domain socket using raw I/O.
#[cfg(unix)]
async fn unix_post(socket_path: &Path, path: &str, body: &Value) -> Result<(u16, Vec<u8>), ClientError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let body_bytes = serde_json::to_vec(body)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        body_bytes.len()
    );

    let mut stream = UnixStream::connect(socket_path).await?;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&body_bytes).await?;
    stream.flush().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    parse_http_response(&response)
}

/// Perform an HTTP GET over a Unix domain socket using raw I/O.
#[cfg(unix)]
async fn unix_get(socket_path: &Path, path: &str) -> Result<(u16, Vec<u8>), ClientError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        path
    );

    let mut stream = UnixStream::connect(socket_path).await?;
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    parse_http_response(&response)
}

#[cfg(not(unix))]
async fn unix_post(_socket_path: &Path, _path: &str, _body: &Value) -> Result<(u16, Vec<u8>), ClientError> {
    Err(ClientError::UnixSocket("Unix sockets not supported on this platform".to_string()))
}

#[cfg(not(unix))]
async fn unix_get(_socket_path: &Path, _path: &str) -> Result<(u16, Vec<u8>), ClientError> {
    Err(ClientError::UnixSocket("Unix sockets not supported on this platform".to_string()))
}

/// Parse a raw HTTP/1.1 response into (status_code, body_bytes).
fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), ClientError> {
    let raw_str = String::from_utf8_lossy(raw);

    // Find the end of headers
    let header_end = raw_str
        .find("\r\n\r\n")
        .ok_or_else(|| ClientError::Parse("Malformed HTTP response: no header terminator".to_string()))?;

    let headers = &raw_str[..header_end];
    let body = &raw[header_end + 4..];

    // Parse status line: "HTTP/1.1 200 OK"
    let status_line = headers
        .lines()
        .next()
        .ok_or_else(|| ClientError::Parse("Empty HTTP response".to_string()))?;
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ClientError::Parse(format!("Cannot parse status from: {}", status_line)))?;

    Ok((status_code, body.to_vec()))
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Async client for the keosd wallet daemon API.
///
/// Supports all `/v1/wallet/*` and `/v1/keosd/*` endpoints.
pub struct KeosdClient {
    transport: Transport,
}

impl KeosdClient {
    /// Create a client that connects via TCP.
    ///
    /// ```rust,no_run
    /// let client = pulsevm_keosd_client::KeosdClient::tcp("http://127.0.0.1:8900");
    /// ```
    pub fn tcp(base_url: &str) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        KeosdClient {
            transport: Transport::Tcp {
                base_url,
                client: reqwest::Client::new(),
            },
        }
    }

    /// Create a client that connects via a Unix domain socket.
    ///
    /// ```rust,no_run
    /// let client = pulsevm_keosd_client::KeosdClient::unix("/home/user/eosio-wallet/keosd.sock");
    /// ```
    pub fn unix(socket_path: impl AsRef<Path>) -> Self {
        KeosdClient {
            transport: Transport::Unix {
                socket_path: socket_path.as_ref().to_path_buf(),
            },
        }
    }

    // ------ Internal helpers ------

    /// POST with JSON body, parse the response. Checks for keosd error format.
    async fn post<T: serde::de::DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T, ClientError> {
        let (status, bytes) = self.transport.post(path, body).await?;
        self.handle_response::<T>(status, &bytes)
    }

    /// POST with no body (empty JSON object).
    async fn post_empty<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        self.post(path, &serde_json::json!(null)).await
    }

    /// GET request, parse the response.
    async fn get_request<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        let (status, bytes) = self.transport.get(path).await?;
        self.handle_response::<T>(status, &bytes)
    }

    /// Check status and deserialize, or parse a keosd error.
    fn handle_response<T: serde::de::DeserializeOwned>(&self, status: u16, bytes: &[u8]) -> Result<T, ClientError> {
        if status >= 200 && status < 300 {
            serde_json::from_slice(bytes).map_err(|e| {
                ClientError::Parse(format!(
                    "{} — raw body: {}",
                    e,
                    String::from_utf8_lossy(bytes)
                ))
            })
        } else {
            // Try to parse as EOSIO error
            if let Ok(err_resp) = serde_json::from_slice::<KeosdErrorResponse>(bytes) {
                Err(ClientError::Keosd {
                    code: err_resp.error.code,
                    name: err_resp.error.name,
                    what: err_resp.error.what,
                    details: err_resp.error.details,
                })
            } else {
                Err(ClientError::Http(format!(
                    "HTTP {}: {}",
                    status,
                    String::from_utf8_lossy(bytes)
                )))
            }
        }
    }

    // ------ Public API ------

    /// Create a new wallet. Returns the generated password.
    ///
    /// `POST /v1/wallet/create`
    pub async fn create(&self, name: &str) -> Result<String, ClientError> {
        self.post("/v1/wallet/create", &serde_json::json!(name)).await
    }

    /// Open an existing wallet file.
    ///
    /// `POST /v1/wallet/open`
    pub async fn open(&self, name: &str) -> Result<(), ClientError> {
        let _: Value = self.post("/v1/wallet/open", &serde_json::json!(name)).await?;
        Ok(())
    }

    /// Lock a specific wallet.
    ///
    /// `POST /v1/wallet/lock`
    pub async fn lock(&self, name: &str) -> Result<(), ClientError> {
        let _: Value = self.post("/v1/wallet/lock", &serde_json::json!(name)).await?;
        Ok(())
    }

    /// Lock all open wallets.
    ///
    /// `POST /v1/wallet/lock_all`
    pub async fn lock_all(&self) -> Result<(), ClientError> {
        let _: Value = self.post("/v1/wallet/lock_all", &serde_json::json!(null)).await?;
        Ok(())
    }

    /// Unlock a wallet with the given password.
    ///
    /// `POST /v1/wallet/unlock`
    pub async fn unlock(&self, name: &str, password: &str) -> Result<(), ClientError> {
        let _: Value = self
            .post("/v1/wallet/unlock", &serde_json::json!([name, password]))
            .await?;
        Ok(())
    }

    /// Import a WIF private key into the named wallet.
    ///
    /// `POST /v1/wallet/import_key`
    pub async fn import_key(&self, name: &str, wif_private_key: &str) -> Result<(), ClientError> {
        let _: Value = self
            .post(
                "/v1/wallet/import_key",
                &serde_json::json!([name, wif_private_key]),
            )
            .await?;
        Ok(())
    }

    /// Remove a key from a wallet. Requires the wallet password.
    ///
    /// `POST /v1/wallet/remove_key`
    pub async fn remove_key(
        &self,
        name: &str,
        password: &str,
        public_key: &str,
    ) -> Result<(), ClientError> {
        let _: Value = self
            .post(
                "/v1/wallet/remove_key",
                &serde_json::json!([name, password, public_key]),
            )
            .await?;
        Ok(())
    }

    /// Create a new key pair inside the named wallet. Returns the public key.
    ///
    /// `POST /v1/wallet/create_key`
    pub async fn create_key(&self, name: &str, key_type: &str) -> Result<String, ClientError> {
        self.post(
            "/v1/wallet/create_key",
            &serde_json::json!([name, key_type]),
        )
        .await
    }

    /// List all opened wallets. Unlocked wallets have a ` *` suffix.
    ///
    /// `POST /v1/wallet/list_wallets`
    pub async fn list_wallets(&self) -> Result<Vec<String>, ClientError> {
        self.post("/v1/wallet/list_wallets", &serde_json::json!(null))
            .await
    }

    /// List key pairs in a wallet. Requires wallet name and password.
    /// Returns a list of `[public_key, private_key]` pairs.
    ///
    /// `POST /v1/wallet/list_keys`
    pub async fn list_keys(
        &self,
        name: &str,
        password: &str,
    ) -> Result<Vec<Vec<String>>, ClientError> {
        self.post("/v1/wallet/list_keys", &serde_json::json!([name, password]))
            .await
    }

    /// Get all public keys from all unlocked wallets.
    ///
    /// `POST /v1/wallet/get_public_keys`
    pub async fn get_public_keys(&self) -> Result<Vec<String>, ClientError> {
        self.post("/v1/wallet/get_public_keys", &serde_json::json!(null))
            .await
    }

    /// Set the auto-lock timeout in seconds.
    ///
    /// `POST /v1/wallet/set_timeout`
    pub async fn set_timeout(&self, seconds: u64) -> Result<(), ClientError> {
        let _: Value = self
            .post("/v1/wallet/set_timeout", &serde_json::json!(seconds))
            .await?;
        Ok(())
    }

    /// Sign a hex-encoded digest with the specified public key.
    /// Returns the hex-encoded signature.
    ///
    /// `POST /v1/wallet/sign_digest`
    pub async fn sign_digest(
        &self,
        digest_hex: &str,
        public_key: &str,
    ) -> Result<String, ClientError> {
        self.post(
            "/v1/wallet/sign_digest",
            &serde_json::json!([digest_hex, public_key]),
        )
        .await
    }

    /// Sign a transaction with the specified public keys and chain ID.
    /// Returns the transaction JSON with `signatures` attached.
    ///
    /// `POST /v1/wallet/sign_transaction`
    pub async fn sign_transaction(
        &self,
        transaction: &Value,
        public_keys: &[String],
        chain_id: &str,
    ) -> Result<Value, ClientError> {
        self.post(
            "/v1/wallet/sign_transaction",
            &serde_json::json!([transaction, public_keys, chain_id]),
        )
        .await
    }

    /// Stop the keosd daemon.
    ///
    /// `POST /v1/keosd/stop`
    ///
    /// Note: the connection will likely be dropped as the server exits.
    pub async fn stop(&self) -> Result<(), ClientError> {
        // Server exits immediately, so we ignore connection-reset errors
        let result: Result<Value, _> = self.post("/v1/keosd/stop", &serde_json::json!(null)).await;
        match result {
            Ok(_) => Ok(()),
            Err(ClientError::Http(_)) => Ok(()), // expected — server shut down
            Err(ClientError::UnixSocket(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_response_ok() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\"hello\"";
        let (status, body) = parse_http_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"\"hello\"");
    }

    #[test]
    fn parse_http_response_error() {
        let raw = b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"code\":500}";
        let (status, body) = parse_http_response(raw).unwrap();
        assert_eq!(status, 500);
        assert_eq!(body, b"{\"code\":500}");
    }

    #[test]
    fn parse_http_response_malformed() {
        let raw = b"garbage data";
        assert!(parse_http_response(raw).is_err());
    }

    #[test]
    fn client_tcp_constructor() {
        let client = KeosdClient::tcp("http://127.0.0.1:8900");
        match &client.transport {
            Transport::Tcp { base_url, .. } => assert_eq!(base_url, "http://127.0.0.1:8900"),
            _ => panic!("Expected TCP transport"),
        }
    }

    #[test]
    fn client_tcp_strips_trailing_slash() {
        let client = KeosdClient::tcp("http://127.0.0.1:8900/");
        match &client.transport {
            Transport::Tcp { base_url, .. } => assert_eq!(base_url, "http://127.0.0.1:8900"),
            _ => panic!("Expected TCP transport"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn client_unix_constructor() {
        let client = KeosdClient::unix("/tmp/keosd.sock");
        match &client.transport {
            Transport::Unix { socket_path } => {
                assert_eq!(socket_path, &PathBuf::from("/tmp/keosd.sock"))
            }
            _ => panic!("Expected Unix transport"),
        }
    }

    #[test]
    fn handle_response_success() {
        let client = KeosdClient::tcp("http://localhost");
        let body = br#""PW5abc123""#;
        let result: Result<String, _> = client.handle_response(201, body);
        assert_eq!(result.unwrap(), "PW5abc123");
    }

    #[test]
    fn handle_response_keosd_error() {
        let client = KeosdClient::tcp("http://localhost");
        let body = br#"{"code":500,"message":"Internal Service Error","error":{"code":3120001,"name":"wallet_exist_exception","what":"Wallet already exists","details":[]}}"#;
        let result: Result<String, _> = client.handle_response(500, body);
        match result {
            Err(ClientError::Keosd { code, name, .. }) => {
                assert_eq!(code, 3120001);
                assert_eq!(name, "wallet_exist_exception");
            }
            other => panic!("Expected Keosd error, got: {:?}", other),
        }
    }
}