mod abi;
mod request;
mod session;
mod types;

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use pulsevm_serialization::{Read, Write};
use serde::Deserialize;
use tokio::{net::TcpListener as TokioTcpListener, select, sync::{RwLock, Semaphore}};
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::CloseFrame};
use tokio_tungstenite::{accept_async, accept_async_with_config};
use tokio_util::sync::CancellationToken;
use tungstenite::{Message, protocol::WebSocketConfig};

use crate::{chain::{AbiDefinition, Controller, Id}, state_history::{abi::SHIP_ABI, request::RequestType, session::Session, types::{BlockPosition, GetStatusResult}}, VirtualMachine};

#[derive(Clone)]
pub struct StateHistoryServer {
    controller: Arc<RwLock<Controller>>,
}

impl StateHistoryServer {
    pub fn new(vm: VirtualMachine) -> Self {
        Self { controller: vm.controller.clone() }
    }

    pub async fn run_ws_server(&self, bind: &str, cancel: CancellationToken) -> anyhow::Result<()> {
        let listener = TokioTcpListener::bind(bind).await?;
        spdlog::info!("WebSocket listening on {}", bind);

        // Limit concurrent connections
        let permits = Arc::new(Semaphore::new(1024));

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    spdlog::info!("WS server: shutdown signal received");
                    break;
                }
                accept_res = listener.accept() => {
                    spdlog::info!("WS server: new connection accepted");
                    let (stream, peer): (tokio::net::TcpStream, SocketAddr) = accept_res?;
                    stream.set_nodelay(true).ok();
                    let controller = self.controller.clone();

                    tokio::spawn(async move {
                        let session = Session::new(peer, controller);
                        if let Err(e) = session.start(stream).await {
                            eprintln!("{} conn error: {e:?}", peer);
                        }
                    });
                }
            }
        }
        Ok(())
    }
}

fn wrap_variant(input: &str, key: &str) -> String {
    // input is like {"get_blocks_ack_request_v0":{"num_messages":1}}
    // We wrap into {"<key>":{...}} which it already is, but we normalize by extracting that subobject.
    let v: serde_json::Value = serde_json::from_str(input).unwrap_or_default();
    let inner = v.get(key).cloned().unwrap_or(serde_json::json!({}));
    serde_json::json!({ key: inner }).to_string()
}

#[derive(Deserialize)]
struct GetBlocksAck {
    #[serde(rename = "get_blocks_ack_request_v0")]
    get_blocks_ack_request_v0: AckBody,
}

#[derive(Deserialize)]
struct AckBody { num_messages: u32 }