use std::{sync::Arc, time::Duration};

use pulsevm_core::mempool::Mempool;
use pulsevm_grpc::messenger::{Message, NotifyRequest, messenger_client::MessengerClient};
use tokio::{sync::RwLock, task::JoinHandle, time::interval};
use tonic::Request;

#[derive(Clone)]
pub struct BlockTimer {
    pub mempool: Arc<RwLock<Mempool>>,
    pub server_address: Arc<RwLock<Option<String>>>,
    pub block_timer: Arc<RwLock<Option<JoinHandle<()>>>>,
}

impl BlockTimer {
    pub fn new(mempool: Arc<RwLock<Mempool>>) -> Self {
        BlockTimer {
            mempool,
            server_address: Arc::new(RwLock::new(None)),
            block_timer: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn start(&mut self, address: String) {
        let mut server_address = self.server_address.write().await;
        *server_address = Some(address);

        let mut block_timer = self.block_timer.write().await;

        if block_timer.is_none() {
            *block_timer = Some(build_block_timer(self.clone()));
        }
    }

    pub async fn request_block_build(&self) {
        let server_address = self.server_address.read().await;
        let mut client: MessengerClient<tonic::transport::Channel> =
            MessengerClient::connect(format!("http://{}", server_address.as_ref().unwrap()))
                .await
                .expect("failed to connect to messenger engine");

        let _ = client
            .notify(Request::new(NotifyRequest {
                message: Message::BuildBlock as i32,
            }))
            .await;
    }

    pub async fn check_block_build(&self) {
        let mempool = self.mempool.read().await;

        if mempool.has_transactions() {
            self.request_block_build().await;
        }
    }
}

fn build_block_timer(timer: BlockTimer) -> JoinHandle<()> {
    return tokio::spawn(async move {
        let mut ticker = interval(Duration::from_millis(500));
        loop {
            ticker.tick().await;
            timer.check_block_build().await;
        }
    });
}
