use crate::chain::{Action, ActionReceipt, Id, Name, TransactionTrace, error::ChainError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionTrace {
    action_ordinal: u32,
    creator_action_ordinal: u32,
    closest_unnotified_ancestor_action_ordinal: u32,
    receipt: Option<ActionReceipt>,
    receiver: Name,
    pub act: Action,
    context_free: bool,
    elapsed: u32,
    console: String,
    trx_id: Id,
    block_num: u32,
    block_time: u32,
    except: Option<ChainError>,
    error_code: Option<u64>,
    return_value: Vec<u8>,
}

impl ActionTrace {
    pub fn new(
        trx_id: Id,
        block_num: u32,
        block_time: u32,
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
