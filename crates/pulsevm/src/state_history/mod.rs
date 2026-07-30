mod request;
mod session;
mod types;

use std::{io::ErrorKind, net::SocketAddr, sync::Arc};

use pulsevm_core::controller::Controller;
use tokio::{
    net::TcpListener as TokioTcpListener,
    sync::{RwLock, Semaphore},
};
use tokio_util::sync::CancellationToken;

use crate::{VirtualMachine, state_history::session::Session};

/// Rewrites a bind address to request an ephemeral port, preserving the host.
/// Falls back to all interfaces if the host cannot be determined.
fn ephemeral_addr(bind: &str) -> String {
    match bind.rsplit_once(':') {
        Some((host, _port)) if !host.is_empty() => format!("{host}:0"),
        _ => "0.0.0.0:0".to_string(),
    }
}

#[derive(Clone)]
pub struct StateHistoryServer {
    controller: Arc<RwLock<Controller>>,
}

impl StateHistoryServer {
    pub fn new(vm: VirtualMachine) -> Self {
        Self {
            controller: vm.controller.clone(),
        }
    }

    /// Serves the state history WebSocket API.
    ///
    /// When `allow_port_fallback` is set and `bind` is already taken, an
    /// ephemeral port is used instead of failing. This matters when several
    /// nodes run on one host -- a local cluster or an e2e test -- where a fixed
    /// default port means only the first node gets a state history server and
    /// the rest fail silently. A `WS_BIND` supplied by an operator is never
    /// silently relocated.
    pub async fn run_ws_server(
        &self,
        bind: &str,
        allow_port_fallback: bool,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let listener = match TokioTcpListener::bind(bind).await {
            Ok(listener) => listener,
            Err(e) if allow_port_fallback && e.kind() == ErrorKind::AddrInUse => {
                let fallback = ephemeral_addr(bind);
                spdlog::warn!(
                    "state history: {} is already in use, falling back to an ephemeral port \
                     (set WS_BIND to choose one explicitly)",
                    bind
                );
                TokioTcpListener::bind(&fallback).await?
            }
            Err(e) => return Err(e.into()),
        };

        // Report the resolved address rather than the requested one: they differ
        // whenever a port of 0 or a fallback is in play.
        spdlog::info!("WebSocket listening on {}", listener.local_addr()?);

        // TODO: Limit concurrent connections
        let _permits = Arc::new(Semaphore::new(1024));

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    spdlog::info!("state history server: shutdown signal received");
                    break;
                }
                accept_res = listener.accept() => {
                    spdlog::info!("state history server: new connection accepted");
                    let (stream, peer): (tokio::net::TcpStream, SocketAddr) = accept_res?;
                    stream.set_nodelay(true).ok();
                    let controller = self.controller.clone();

                    tokio::spawn(async move {
                        let mut session = Session::new(peer, controller);
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
