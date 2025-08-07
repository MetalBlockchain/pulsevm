use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::Name;

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes)]
pub struct AccountDelta {
    account: Name,
    delta: i64,
}
