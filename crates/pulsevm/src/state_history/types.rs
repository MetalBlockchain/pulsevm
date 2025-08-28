use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::Serialize;

use crate::chain::Id;

#[derive(Debug, Clone, Read, Write, NumBytes)]
pub struct BlockPosition {
    pub block_num: u32,
    pub block_id: Id,
}

#[derive(Debug, Clone, Read, Write, NumBytes)]
pub struct GetStatusResult {
    pub variant: u8,
    pub head: BlockPosition,
    pub last_irreversible: BlockPosition,
    pub trace_begin_block: u32,
    pub trace_end_block: u32,
    pub chain_state_begin_block: u32,
    pub chain_state_end_block: u32,
    pub chain_id: Id,
}

#[derive(Debug, Clone, Read, Write, NumBytes)]
pub struct GetBlocksRequestV0 {
    pub start_block_num: u32,
    pub end_block_num: u32,
    pub max_messages_in_flight: u32,
    pub have_positions: Vec<BlockPosition>,
    pub irreversible_only: bool,
    pub fetch_block: bool,
    pub fetch_traces: bool,
    pub fetch_deltas: bool,
}