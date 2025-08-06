mod block_timer;
pub use block_timer::BlockTimer;

use pulsevm_grpc::messenger::{Message, NotifyRequest, messenger_client::MessengerClient};
use tonic::Request;

use std::{
    collections::VecDeque
};

use tokio::{sync::{
    mpsc::{self, error::SendError, Receiver, Sender}, Mutex
}, task::JoinHandle, time::interval};

use crate::chain::Transaction;

pub struct Mempool {
    transactions: VecDeque<Transaction>,
    request_block_mutex: Mutex<()>,
    server_address: String,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            transactions: VecDeque::new(),
            request_block_mutex: Mutex::new(()),
            server_address: String::new(),
        }
    }

    pub fn add_transaction(&mut self, transaction: Transaction) {
        self.transactions.push_back(transaction);
    }

    pub fn pop_transaction(&mut self) -> Option<Transaction> {
        self.transactions.pop_front()
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

        if self.transactions.len() > 0 {
            self.request_block_build().await;
        }
    }
}
