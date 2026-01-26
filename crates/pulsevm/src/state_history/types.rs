use std::collections::HashMap;

use pulsevm_core::{
    account::AccountDelta, crypto::Signature, id::Id, name::Name, transaction::{Action, TransactionStatus, TransactionTrace}
};
use pulsevm_crypto::{Bytes, Digest};
use pulsevm_proc_macros::{NumBytes, Read, Write, name};
use pulsevm_serialization::VarUint32;
use pulsevm_time::TimePointSec;

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

#[derive(Debug, Clone, Read, Write, NumBytes)]
pub struct GetBlocksResponseV0 {
    pub variant: u8,
    pub head: BlockPosition,
    pub last_irreversible: BlockPosition,
    pub this_block: Option<BlockPosition>,
    pub prev_block: Option<BlockPosition>,
    pub block: Option<Bytes>,
    pub traces: Option<Bytes>,
    pub deltas: Option<Bytes>,
}

#[derive(Debug, Clone, Read, Write, NumBytes)]
pub struct GetBlocksAckRequestV0 {
    pub num_messages: u32,
}

#[derive(Clone, Read, Write, NumBytes)]
pub struct AccountAuthSequence {
    pub account: u64,
    pub sequence: u64,
}

#[derive(Clone, Read, Write, NumBytes)]
pub struct ActionReceiptV0 {
    pub variant: u8,
    pub receiver: u64,
    pub act_digest: Digest,
    pub global_sequence: u64,
    pub recv_sequence: u64,
    pub auth_sequence: Vec<AccountAuthSequence>,
    pub code_sequence: VarUint32,
    pub abi_sequence: VarUint32,
}

#[derive(Clone, Read, Write, NumBytes)]
pub struct ActionTraceV1 {
    pub variant: u8,
    pub action_ordinal: VarUint32,
    pub creator_action_ordinal: VarUint32,
    pub receipt: Option<ActionReceiptV0>,
    pub receiver: u64,
    pub act: Action,
    pub context_free: bool,
    pub elapsed: i64,
    pub console: String,
    pub account_ram_deltas: HashMap<Name, i64>,
    pub except: Option<String>,
    pub error_code: Option<u64>,
    pub return_value: Bytes,
}

impl ActionTraceV1 {
    pub const fn new(
        action_ordinal: VarUint32,
        creator_action_ordinal: VarUint32,
        receipt: Option<ActionReceiptV0>,
        receiver: u64,
        act: Action,
        context_free: bool,
        elapsed: i64,
        console: String,
        account_ram_deltas: HashMap<Name, i64>,
        except: Option<String>,
        error_code: Option<u64>,
        return_value: Bytes,
    ) -> Self {
        ActionTraceV1 {
            variant: 1,
            action_ordinal,
            creator_action_ordinal,
            receipt,
            receiver,
            act,
            context_free,
            elapsed,
            console,
            account_ram_deltas,
            except,
            error_code,
            return_value,
        }
    }
}

#[derive(Clone, Read, Write, NumBytes)]
pub struct PartialTransactionV0 {
    pub variant: u8,
    pub expiration: TimePointSec,
    pub ref_block_num: u16,
    pub ref_block_prefix: u32,
    pub max_net_usage_words: VarUint32,
    pub max_cpu_usage_ms: u8,
    pub delay_sec: VarUint32,
    pub transaction_extensions: Vec<Bytes>,
    pub signatures: Vec<Signature>,
    pub context_free_data: Vec<Bytes>,
}

#[derive(Clone, Read, Write, NumBytes)]
pub struct TransactionTraceV0 {
    pub variant: u8,
    pub id: Id,
    pub status: TransactionStatus,
    pub cpu_usage_us: u32,
    pub net_usage_words: VarUint32,
    pub elapsed: i64,
    pub net_usage: u64,
    pub scheduled: bool,
    pub action_traces: Vec<ActionTraceV1>,
    pub account_ram_delta: Option<AccountDelta>,
    pub except: Option<String>,
    pub error_code: Option<u64>,
    pub failed_dtrx_trace: Option<bool>,
    pub partial: Option<PartialTransactionV0>,
}

impl TransactionTraceV0 {
    pub const fn new(
        id: Id,
        status: TransactionStatus,
        cpu_usage_us: u32,
        net_usage_words: VarUint32,
        elapsed: i64,
        net_usage: u64,
        scheduled: bool,
        action_traces: Vec<ActionTraceV1>,
        account_ram_delta: Option<AccountDelta>,
        except: Option<String>,
        error_code: Option<u64>,
        failed_dtrx_trace: Option<bool>,
        partial: Option<PartialTransactionV0>,
    ) -> Self {
        TransactionTraceV0 {
            variant: 0,
            id,
            status,
            cpu_usage_us,
            net_usage_words,
            elapsed,
            net_usage,
            scheduled,
            action_traces,
            account_ram_delta,
            except,
            error_code,
            failed_dtrx_trace,
            partial,
        }
    }
}

impl From<&TransactionTrace> for TransactionTraceV0 {
    fn from(trace: &TransactionTrace) -> Self {
        let action_traces: Vec<ActionTraceV1> = trace
            .action_traces()
            .into_iter()
            .map(|at| {
                ActionTraceV1::new(
                    VarUint32(at.action_ordinal()),
                    VarUint32(at.creator_action_ordinal()),
                    at.receipt.as_ref().map(|receipt| ActionReceiptV0 {
                        variant: 0,
                        receiver: receipt.receiver.as_u64(),
                        act_digest: receipt.act_digest,
                        global_sequence: receipt.global_sequence,
                        recv_sequence: receipt.recv_sequence,
                        auth_sequence: receipt
                            .auth_sequence
                            .iter()
                            .map(|(k, v)| AccountAuthSequence {
                                account: *k,
                                sequence: *v,
                            })
                            .collect(),
                        code_sequence: VarUint32(receipt.code_sequence),
                        abi_sequence: VarUint32(receipt.abi_sequence),
                    }),
                    at.receiver().as_u64(),
                    at.act.clone(),
                    at.context_free,
                    at.elapsed as i64,
                    at.console.clone(),
                    at.account_ram_deltas.clone(),
                    None,
                    None,
                    Bytes::new(at.return_value.clone()),
                )
            })
            .collect();

        let receipt = trace.receipt.clone();

        TransactionTraceV0::new(
            trace.id,
            receipt.status,
            receipt.cpu_usage_us,
            receipt.net_usage_words,
            trace.elapsed as i64,
            trace.net_usage,
            trace.scheduled,
            action_traces,
            trace.account_ram_delta.clone(),
            None,
            None,
            None,
            None, // Placeholder for partial transaction, not implemented yet
        )
    }
}
