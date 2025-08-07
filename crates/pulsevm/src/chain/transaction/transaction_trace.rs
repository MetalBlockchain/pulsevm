use crate::chain::{AccountDelta, ActionTrace, Id, TransactionReceiptHeader, error::ChainError};

#[derive(Default, Clone)]
pub struct TransactionTrace {
    pub id: Id,
    pub block_num: u32,
    pub block_time: u32,
    pub receipt: Option<TransactionReceiptHeader>,
    pub elapsed: u32,
    pub net_usage: u64,
    pub action_traces: Vec<ActionTrace>,
    pub account_ram_delta: Option<AccountDelta>,

    pub except: Option<ChainError>,
    pub error_code: i64,
}

impl TransactionTrace {
    pub fn id(&self) -> &Id {
        return &self.id;
    }
}
