use crate::chain::{Action, Name};

pub struct ActionTrace {
    action_ordinal: u32,
    creator_action_ordinal: u32,
    receiver: Name,
    action: Action,
}

impl ActionTrace {
    pub fn new(
        action_ordinal: u32,
        creator_action_ordinal: u32,
        receiver: Name,
        action: Action,
    ) -> Self {
        ActionTrace {
            action_ordinal,
            creator_action_ordinal,
            receiver,
            action,
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
        self.action.clone()
    }
}
