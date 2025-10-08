use core::fmt;

use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{Action, ActionReceipt, BlockTimestamp, Id, Name, error::ChainError};

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes)]
pub struct ActionTrace {
    pub action_ordinal: u32,
    pub creator_action_ordinal: u32,
    pub closest_unnotified_ancestor_action_ordinal: u32,
    pub receipt: Option<ActionReceipt>,
    pub receiver: Name,
    pub act: Action,
    pub context_free: bool,
    pub elapsed: u32,
    pub console: String,
    pub trx_id: Id,
    pub block_num: u32,
    pub block_time: BlockTimestamp,
    pub except: Option<u8>,
    pub error_code: Option<u64>,
    pub return_value: Vec<u8>,
}

impl ActionTrace {
    pub fn new(
        trx_id: Id,
        block_num: u32,
        block_time: BlockTimestamp,
        act: &Action,
        receiver: Name,
        context_free: bool,
        action_ordinal: u32,
        creator_action_ordinal: u32,
        closest_unnotified_ancestor_action_ordinal: u32,
    ) -> Self {
        ActionTrace {
            trx_id,
            block_num,
            block_time,
            action_ordinal,
            creator_action_ordinal,
            closest_unnotified_ancestor_action_ordinal,
            receiver,
            act: act.clone(),
            context_free,
            receipt: None,
            elapsed: 0,
            console: String::new(),
            except: None,
            error_code: None,
            return_value: vec![],
        }
    }

    pub fn action_ordinal(&self) -> u32 {
        self.action_ordinal
    }

    pub fn creator_action_ordinal(&self) -> u32 {
        self.creator_action_ordinal
    }

    pub fn receiver(&self) -> Name {
        self.receiver
    }

    pub fn action(&self) -> Action {
        self.act.clone()
    }

    pub fn elapsed(&self) -> u32 {
        self.elapsed
    }

    pub fn set_elapsed(&mut self, elapsed: u32) {
        self.elapsed = elapsed;
    }
}

impl fmt::Display for ActionTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "action_trace {{ action_ordinal: {}, creator_action_ordinal: {}, receiver: {}, act: {}, context_free: {}, elapsed: {}, console: {}, except: {:?}, error_code: {:?}, return_value: {:?} }}",
            self.action_ordinal,
            self.creator_action_ordinal,
            self.receiver,
            self.act,
            self.context_free,
            self.elapsed,
            self.console,
            self.except,
            self.error_code,
            self.return_value
        )
    }
}
