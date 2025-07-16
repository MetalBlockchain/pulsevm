use std::{sync::Arc, time::Duration};

use tokio::{sync::RwLock, time::interval};

use super::Mempool;

pub fn build_block_timer(mempool: Arc<RwLock<Mempool>>) {
    let mempool = Arc::clone(&mempool);

    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_millis(500));
        loop {
            ticker.tick().await;
            let instance = mempool.read().await;
            instance.check_block_build().await;
        }
    });
}
