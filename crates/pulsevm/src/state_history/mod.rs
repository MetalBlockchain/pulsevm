mod request;
mod session;
mod types;

use std::{net::SocketAddr, sync::Arc};

use pulsevm_core::controller::Controller;
use tokio::{
    net::TcpListener as TokioTcpListener,
    sync::{RwLock, Semaphore},
};
use tokio_util::sync::CancellationToken;

use crate::{VirtualMachine, state_history::session::Session};

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

    pub async fn run_ws_server(&self, bind: &str, cancel: CancellationToken) -> anyhow::Result<()> {
        let listener = TokioTcpListener::bind(bind).await?;
        spdlog::info!("WebSocket listening on {}", bind);

        // Limit concurrent connections
        let permits = Arc::new(Semaphore::new(1024));

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
