use std::{sync::Arc, time::Duration};

use tokio::{sync::RwLock, task::JoinHandle, time::interval};

use super::Mempool;

pub struct BlockTimer {
    pub mempool: Arc<RwLock<Mempool>>,
    pub block_timer: Option<JoinHandle<()>>,
}

impl BlockTimer {
    pub fn new(mempool: Arc<RwLock<Mempool>>) -> Self {
        BlockTimer {
            mempool,
            block_timer: None,
        }
    }

    pub async fn start(&mut self) {
        if self.block_timer.is_none() {
            self.block_timer = Some(build_block_timer(self.mempool.clone()));
        }
    }
}

fn build_block_timer(mempool: Arc<RwLock<Mempool>>) -> JoinHandle<()> {
    let mempool = Arc::clone(&mempool);

    return tokio::spawn(async move {
        let mut ticker = interval(Duration::from_millis(500));
        loop {
            ticker.tick().await;
            let instance = mempool.read().await;
            instance.check_block_build().await;
        }
    });
}
