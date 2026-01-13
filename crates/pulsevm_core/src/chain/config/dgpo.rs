use pulsevm_proc_macros::{NumBytes, Read, Write};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct DynamicGlobalPropertyObject {
    pub global_action_sequence: u64,
}

impl DynamicGlobalPropertyObject {
    pub fn new(global_action_sequence: u64) -> Self {
        DynamicGlobalPropertyObject {
            global_action_sequence,
        }
    }
}
