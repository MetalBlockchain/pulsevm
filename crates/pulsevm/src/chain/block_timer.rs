use std::{sync::Arc, time::Duration};

use pulsevm_core::mempool::Mempool;
use tokio::{sync::{Notify, RwLock}, task::JoinHandle, time::interval};

#[derive(Clone)]
pub struct BlockTimer {
    pub mempool: Arc<RwLock<Mempool>>,
    pub notify_block_build: Arc<Notify>,
    pub server_address: Arc<RwLock<Option<String>>>,
    pub block_timer: Arc<RwLock<Option<JoinHandle<()>>>>,
}

impl BlockTimer {
    pub fn new(mempool: Arc<RwLock<Mempool>>) -> Self {
        BlockTimer {
            mempool,
            notify_block_build: Arc::new(Notify::new()),
            server_address: Arc::new(RwLock::new(None)),
            block_timer: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn start(&mut self, address: String) {
        let mut server_address = self.server_address.write().await;
        *server_address = Some(address);

        let mut block_timer = self.block_timer.write().await;

        if block_timer.is_none() {
            *block_timer = Some(build_block_timer(self.clone()).await);
        }
    }

    pub async fn request_block_build(&self) {
        self.notify_block_build.notify_one();
    }

    pub async fn check_block_build(&self) {
        let mempool = self.mempool.read().await;

        if mempool.has_transactions() {
            self.request_block_build().await;
        }
    }

    pub async fn wait_for_block_build(&self) {
        self.notify_block_build.notified().await;
    }
}

async fn build_block_timer(timer: BlockTimer) -> JoinHandle<()> {
    return tokio::spawn(async move {
        let mut ticker = interval(Duration::from_millis(500));
        loop {
            ticker.tick().await;
            timer.check_block_build().await;
        }
    });
}
