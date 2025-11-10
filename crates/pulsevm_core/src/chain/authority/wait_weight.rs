use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes, Serialize)]
pub struct WaitWeight {
    pub wait_sec: u32,
    pub weight: u16,
}
