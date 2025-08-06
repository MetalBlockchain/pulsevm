mod block_timer;
pub use block_timer::BlockTimer;

use pulsevm_grpc::messenger::{Message, NotifyRequest, messenger_client::MessengerClient};
use tonic::Request;

use std::collections::{HashSet, VecDeque};

use tokio::{
    sync::{
        Mutex,
        mpsc::{self, Receiver, Sender, error::SendError},
    },
    task::JoinHandle,
    time::interval,
};

use crate::chain::{Id, Transaction};

pub struct Mempool {
    transactions_list: VecDeque<Transaction>,
    transactions_map: HashSet<Id>,
    request_block_mutex: Mutex<()>,
    server_address: String,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            transactions_list: VecDeque::new(),
            transactions_map: HashSet::new(),
            request_block_mutex: Mutex::new(()),
            server_address: String::new(),
        }
    }

    pub fn add_transaction(&mut self, transaction: Transaction) {
        let tx_id = transaction.id();

        if self.transactions_map.contains(&tx_id) {
            return; // Transaction already exists in the mempool
        }

        self.transactions_list.push_back(transaction);
        self.transactions_map.insert(tx_id);
    }

    pub fn pop_transaction(&mut self) -> Option<Transaction> {
        if let Some(tx) = self.transactions_list.pop_front() {
            self.transactions_map.remove(&tx.id());
            return Some(tx)
        }

        return None
    }

    pub fn remove_transaction(&mut self, tx_id: &Id) {
        if let Some(index) = self.transactions_list.iter().position(|x| x.id() == *tx_id) {
            self.transactions_list.remove(index);
            self.transactions_map.remove(tx_id);
        }
    }

    pub fn set_server_address(&mut self, address: String) {
        self.server_address = address;
    }

    pub async fn request_block_build(&self) {
        let mut client: MessengerClient<tonic::transport::Channel> =
            MessengerClient::connect(format!("http://{}", self.server_address))
                .await
                .expect("failed to connect to messenger engine");

        let _ = client
            .notify(Request::new(NotifyRequest {
                message: Message::BuildBlock as i32,
            }))
            .await;
    }

    pub async fn check_block_build(&self) {
        let _ = self.request_block_mutex.lock().await;

        if self.transactions_list.len() > 0 {
            self.request_block_build().await;
        }
    }
}
