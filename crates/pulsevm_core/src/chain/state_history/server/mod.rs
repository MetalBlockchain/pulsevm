mod request;
mod session;
mod types;

use std::{
    io::ErrorKind,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use crate::controller::Controller;
use tokio::{
    net::TcpListener as TokioTcpListener,
    sync::{
        OwnedSemaphorePermit,
        RwLock,
        Semaphore,
        TryAcquireError,
    },
};
use tokio_util::sync::CancellationToken;

use self::session::Session;

/// Most simultaneous state-history sessions. A new connection past this is
/// closed immediately rather than queued: the peers are indexers, a handful
/// per node, and each session holds a writer task and a block stream.
pub(crate) const MAX_CONNECTIONS: usize = 1024;

/// Pause after a failed `accept`. File-descriptor exhaustion is the usual
/// cause; retrying at once would spin, and returning would end the server.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Take a session slot, or `None` when the server is at its limit. The permit
/// is held by the session task and released when the session ends.
fn try_admit(permits: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    match permits.clone().try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(TryAcquireError::NoPermits) => None,
        // The semaphore is never closed; treat it like exhaustion if it were.
        Err(TryAcquireError::Closed) => None,
    }
}

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
    pub fn new(controller: Arc<RwLock<Controller>>) -> Self {
        Self { controller }
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

        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    spdlog::info!("state history server: shutdown signal received");
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, peer): (tokio::net::TcpStream, SocketAddr) = match accept_res {
                        Ok(accepted) => accepted,
                        Err(e) => {
                            // A transient accept failure must not take the
                            // whole state-history service down.
                            spdlog::warn!("state history server: accept failed: {e}");
                            tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                            continue;
                        }
                    };
                    let Some(permit) = try_admit(&permits) else {
                        spdlog::warn!(
                            "state history server: connection from {peer} refused, \
                             {MAX_CONNECTIONS} sessions already open"
                        );
                        drop(stream);
                        continue;
                    };
                    spdlog::info!("state history server: new connection accepted");
                    stream.set_nodelay(true).ok();
                    let controller = self.controller.clone();

                    tokio::spawn(async move {
                        // Held for the life of the session.
                        let _permit = permit;
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use crate::controller::Controller;

    use super::{
        StateHistoryServer,
        try_admit,
    };
    use std::sync::Arc as StdArc;
    use tokio::sync::Semaphore;

    #[test]
    fn connections_past_the_limit_are_refused_and_slots_are_reused() {
        let permits = StdArc::new(Semaphore::new(2));
        let first = try_admit(&permits).expect("first slot");
        let _second = try_admit(&permits).expect("second slot");
        assert!(try_admit(&permits).is_none(), "the third must be refused");
        drop(first);
        assert!(
            try_admit(&permits).is_some(),
            "a finished session frees its slot"
        );
    }

    #[test]
    fn the_server_limit_is_the_documented_constant() {
        assert_eq!(super::MAX_CONNECTIONS, 1024);
    }

    #[test]
    fn server_retains_the_supplied_controller() {
        let controller = Arc::new(RwLock::new(Controller::new()));
        let server = StateHistoryServer::new(controller.clone());

        assert!(Arc::ptr_eq(&server.controller, &controller));
    }
}
