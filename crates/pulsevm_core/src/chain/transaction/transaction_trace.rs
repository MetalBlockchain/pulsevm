use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{
    account::AccountDelta,
    block::BlockTimestamp,
    id::Id,
    transaction::{ActionTrace, TransactionReceiptHeader},
};

#[derive(Default, Clone, Read, Write, NumBytes)]
pub struct TransactionTrace {
    pub id: Id,
    pub block_num: u32,
    pub block_time: BlockTimestamp,
    pub receipt: TransactionReceiptHeader,
    pub elapsed: u32,
    pub net_usage: u64,
    pub scheduled: bool,
    pub action_traces: Vec<ActionTrace>,
    pub account_ram_delta: Option<AccountDelta>,

    pub except: Option<u8>,
    pub error_code: Option<u64>,
}

impl TransactionTrace {
    pub fn id(&self) -> &Id {
        return &self.id;
    }

    pub fn action_traces(&self) -> &Vec<ActionTrace> {
        &self.action_traces
    }
}
