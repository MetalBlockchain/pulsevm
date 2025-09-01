use std::{
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, atomic::AtomicI64},
};

use anyhow::{Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use pulsevm_crypto::Bytes;
use pulsevm_proc_macros::name;
use pulsevm_serialization::{Read, VarUint32, Write};
use pulsevm_time::TimePointSec;
use tokio::sync::RwLock;
use tokio_tungstenite::accept_async;
use tungstenite::Message;

use crate::{
    chain::{
        ACTIVE_NAME, Action, Controller, Id, NEWACCOUNT_NAME, Name, PULSE_NAME, Permission,
        PermissionLevel, Signature, TransactionStatus,
    },
    state_history::{
        abi::SHIP_ABI,
        request::RequestType,
        types::{
            AccountAuthSequence, ActionReceiptV0, ActionTraceV1, BlockPosition, GetBlocksRequestV0,
            GetBlocksResponseV0, GetStatusResult, PartialTransactionV0, TransactionTraceV0,
        },
    },
};

pub struct Session {
    peer: SocketAddr,
    controller: Arc<RwLock<Controller>>,
    current_request: Option<GetBlocksRequestV0>,
    to_send_block_num: u32,
}

impl Session {
    pub fn new(peer: SocketAddr, controller: Arc<RwLock<Controller>>) -> Self {
        Self {
            peer,
            controller,
            current_request: None,
            to_send_block_num: 0,
        }
    }

    pub async fn start(&mut self, stream: tokio::net::TcpStream) -> Result<()> {
        let mut ws = accept_async(stream).await?;

        println!("{} connected; ABI sent", self.peer);

        // 1) First frame must be the ABI (text)
        ws.send(Message::Text(SHIP_ABI.to_string())).await?;

        let in_flight_budget = Arc::new(AtomicI64::new(0));
        let streaming = Arc::new(tokio::sync::watch::channel(false).0);

        while let Some(msg) = ws.next().await {
            let msg = msg?;
            match msg {
                Message::Binary(b) => {
                    let req_type = RequestType::read(&b, &mut 0)
                        .map_err(|e| anyhow!("failed to parse request type: {:?}", e))?;

                    match req_type {
                        RequestType::GetStatusRequestV0 => {
                            let result = self.get_status().await?;
                            let packed = result.pack()?;
                            ws.send(Message::Binary(packed)).await?;
                        }
                        RequestType::GetBlocksRequestV0 => {
                            println!("{} get_blocks_request_v0 {}", self.peer, hex::encode(&b));
                            let request = GetBlocksRequestV0::read(&b, &mut 1).map_err(|e| {
                                anyhow!("failed to parse GetBlocksRequestV0: {:?}", e)
                            })?;
                            self.update_current_request(&request).await?;
                            println!("{} {:?}", self.peer, request);
                            let result = self.get_block_response().await?;
                            let result = result.pack()?;
                            let hex_encoded = hex::encode(&result);
                            println!("{} sending block response {}", self.peer, hex_encoded);
                            ws.send(Message::Binary(result)).await?;
                        }
                        RequestType::GetBlocksAckRequestV0 => {
                            println!("{} get_blocks_ack_request_v0", self.peer);
                        }
                    }
                }
                Message::Close(cf) => {
                    let _ = ws.send(Message::Close(cf)).await;
                    break;
                }
                Message::Ping(p) => {
                    ws.send(Message::Pong(p)).await?;
                }
                Message::Text(s) => {
                    // SHiP clients shouldn't send text after the ABI, but we won't crash.
                    eprintln!("{} unexpected text: {}", self.peer, s);
                }
                _ => {}
            }
        }

        // turn off streaming for any background producer
        let _ = streaming.send_replace(false);
        Ok(())
    }

    async fn get_status(&self) -> Result<GetStatusResult> {
        let controller = self.controller.read().await;
        let chain_id = controller.chain_id();
        let head_block = controller.last_accepted_block();

        Ok(GetStatusResult {
            variant: 0,
            head: BlockPosition {
                block_num: head_block.block_num(),
                block_id: head_block.id(),
            },
            last_irreversible: BlockPosition {
                block_num: head_block.block_num(),
                block_id: head_block.id(),
            },
            trace_begin_block: 1,
            trace_end_block: head_block.block_num(),
            chain_state_begin_block: 1,
            chain_state_end_block: head_block.block_num(),
            chain_id: chain_id,
        })
    }

    async fn get_block_response(&self) -> Result<GetBlocksResponseV0> {
        let controller = self.controller.read().await;
        let head_block = controller.last_accepted_block();
        let head_block_packed = head_block.pack()?;
        let encoded = hex::encode(&head_block_packed);
        let transaction_trace = TransactionTraceV0::new(
            Id::default(),
            TransactionStatus::Executed,
            100,
            VarUint32(10),
            150,
            10,
            false,
            vec![ActionTraceV1::new(
                VarUint32(1),
                VarUint32(1),
                Some(
                    ActionReceiptV0 {
                        variant: 0,
                        receiver: Name::new(name!("pulse")),
                        act_digest: Default::default(),
                        global_sequence: 1,
                        recv_sequence: 1,
                        auth_sequence: vec![AccountAuthSequence {
                            account: Name::new(name!("pulse")),
                            sequence: 1,
                        }],
                        code_sequence: VarUint32(1),
                        abi_sequence: VarUint32(1),
                    }
                ),
                Name::new(name!("pulse")),
                Action::new(PULSE_NAME, NEWACCOUNT_NAME, vec![], vec![PermissionLevel::new(PULSE_NAME, ACTIVE_NAME)]),
                false,
                137,
                "".to_owned(),
                vec![],
                None,
                None,
                Bytes::new(vec![]),
            )],
            None,
            None,
            None,
            None,
            Some(
                PartialTransactionV0 {
                    variant: 0,
                    expiration: TimePointSec::from_str("2025-08-30T22:00:00Z").unwrap(),
                    ref_block_num: head_block.block_num() as u16,
                    ref_block_prefix: 0,
                    max_cpu_usage_ms: 10,
                    max_net_usage_words: VarUint32(100),
                    delay_sec: VarUint32(0),
                    context_free_data: vec![Bytes::new(vec![])],
                    transaction_extensions: vec![],
                    signatures: vec![
                        Signature::from_str("SIG_K1_Kd1GbZcs4icCo3Ap25o7YJrTNyXDDBSctc22M2AAR2Zqbz9CfyYxHLwf79kLmaMbEQwAQmgewQ2ozJazxZ3J47mKsBC7kP").unwrap()
                    ],
                }
            ),
        );
        let traces = vec![transaction_trace];
        let packed = traces.pack()?;

        Ok(GetBlocksResponseV0 {
            variant: 1,
            head: BlockPosition {
                block_num: head_block.block_num(),
                block_id: head_block.id(),
            },
            last_irreversible: BlockPosition {
                block_num: head_block.block_num(),
                block_id: head_block.id(),
            },
            this_block: Some(BlockPosition {
                block_num: head_block.block_num(),
                block_id: head_block.id(),
            }),
            prev_block: None,
            block: Some(head_block_packed.into()),
            traces: Some(packed.into()),
            deltas: None,
        })
    }

    pub async fn update_current_request(&mut self, req: &GetBlocksRequestV0) -> Result<()> {
        self.to_send_block_num = std::cmp::max(req.start_block_num, 1);

        for cp in req.have_positions.iter() {
            if req.start_block_num <= cp.block_num {
                continue;
            }
        }

        self.current_request = Some(req.clone());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use pulsevm_crypto::Bytes;
    use pulsevm_serialization::{VarUint32, Write};
    use pulsevm_time::TimePointSec;

    use crate::{chain::{AccountDelta, Action, Id, Name, PermissionLevel, Signature, TransactionStatus, ACTIVE_NAME, NEWACCOUNT_NAME, PULSE_NAME}, state_history::types::{AccountAuthSequence, ActionReceiptV0, ActionTraceV1, BlockPosition, GetBlocksResponseV0, PartialTransactionV0, TransactionTraceV0}};

    #[test]
    fn it_works() {
        let block_id = Id::from_str("384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0").unwrap();
        let transaction_trace = TransactionTraceV0::new(
            block_id,
            TransactionStatus::Executed,
            100,
            VarUint32(10),
            150,
            10,
            true,
            vec![ActionTraceV1::new(
                VarUint32(1),
                VarUint32(1),
                Some(
                    ActionReceiptV0 {
                        variant: 0,
                        receiver: PULSE_NAME,
                        act_digest: Default::default(),
                        global_sequence: 1,
                        recv_sequence: 1,
                        auth_sequence: vec![AccountAuthSequence {
                            account: PULSE_NAME,
                            sequence: 1,
                        }],
                        code_sequence: VarUint32(1),
                        abi_sequence: VarUint32(1),
                    }
                ),
                PULSE_NAME,
                Action::new(PULSE_NAME, NEWACCOUNT_NAME, vec![], vec![PermissionLevel::new(PULSE_NAME, ACTIVE_NAME)]),
                true,
                137,
                "".to_owned(),
                vec![
                    AccountDelta {
                        account: PULSE_NAME,
                        delta: 100,
                    }
                ],
                None,
                None,
                Bytes::new(vec![]),
            )],
            None,
            None,
            Some(10),
            None,
            Some(
                PartialTransactionV0 {
                    variant: 0,
                    expiration: TimePointSec::from_str("2025-08-30T22:00:00Z").unwrap(),
                    ref_block_num: 1u16,
                    ref_block_prefix: 0,
                    max_cpu_usage_ms: 10,
                    max_net_usage_words: VarUint32(100),
                    delay_sec: VarUint32(0),
                    context_free_data: vec![Bytes::new(vec![])],
                    transaction_extensions: vec![],
                    signatures: vec![
                        Signature::from_str("SIG_K1_Kd1GbZcs4icCo3Ap25o7YJrTNyXDDBSctc22M2AAR2Zqbz9CfyYxHLwf79kLmaMbEQwAQmgewQ2ozJazxZ3J47mKsBC7kP").unwrap()
                    ],
                }
            ),
        );
        let traces = vec![transaction_trace];
        let packed = traces.pack().unwrap();
        let response = GetBlocksResponseV0 {
            variant: 1,
            head: BlockPosition {
                block_num: 1,
                block_id: block_id,
            },
            last_irreversible: BlockPosition {
                block_num: 1,
                block_id: block_id,
            },
            this_block: Some(BlockPosition {
                block_num: 1,
                block_id: block_id,
            }),
            prev_block: None,
            block: None,
            traces: Some(packed.into()),
            deltas: None,
        };
        let packed = response.pack().unwrap();
        let hex_encoded = hex::encode(&packed);
        println!("{}", hex_encoded);
    }
}