use serde::Serialize;

use crate::chain::BlockTimestamp;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct AccountResourceLimit {
    pub used: i64,
    ///< quantity used in current window
    pub available: i64,
    ///< quantity available in current window (based upon fractional reserve)
    pub max: i64,
    ///< max per window under current congestion
    pub last_usage_update_time: BlockTimestamp,
    ///< last usage timestamp
    pub current_used: i64,
}

impl AccountResourceLimit {
    pub fn new(
        used: i64,
        available: i64,
        max: i64,
        last_usage_update_time: BlockTimestamp,
        current_used: i64,
    ) -> Self {
        Self {
            used,
            available,
            max,
            last_usage_update_time,
            current_used,
        }
    }
}
