use std::{net::SocketAddr, sync::{atomic::AtomicI64, Arc}};

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use pulsevm_serialization::{Read, Write};
use tokio::sync::RwLock;
use tokio_tungstenite::accept_async;
use tungstenite::Message;

use crate::{chain::Controller, state_history::{abi::SHIP_ABI, request::RequestType, types::{BlockPosition, GetBlocksRequestV0, GetStatusResult}}};

pub struct Session {
    peer: SocketAddr,
    controller: Arc<RwLock<Controller>>,
}

impl Session {
    pub fn new(peer: SocketAddr, controller: Arc<RwLock<Controller>>) -> Self {
        Self { peer, controller }
    }

    pub async fn start(&self, stream: tokio::net::TcpStream) -> Result<()> {
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
                    let req_type = RequestType::read(&b, &mut 0).map_err(|e| anyhow!("failed to parse request type: {:?}", e))?;

                    match req_type {
                        RequestType::GetStatusRequestV0 => {
                            let result = self.get_status().await?;
                            let packed = result.pack()?;
                            ws.send(Message::Binary(packed)).await?;
                        }
                        RequestType::GetBlocksRequestV0 => {
                            println!("{} get_blocks_request_v0 {}", self.peer, hex::encode(&b));
                            let request = GetBlocksRequestV0::read(&b, &mut 1).map_err(|e| anyhow!("failed to parse GetBlocksRequestV0: {:?}", e))?;
                            println!("{} get_blocks_request_v0", self.peer);
                            println!("{} {:?}", self.peer, request);
                        }
                        RequestType::GetBlocksRequestV1 => {
                            let request = GetBlocksRequestV0::read(&b, &mut 1).map_err(|e| anyhow!("failed to parse GetBlocksRequestV1: {:?}", e))?;
                            println!("{} get_blocks_request_v1", self.peer);
                            println!("{} {:?}", self.peer, request);
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
                block_num: head_block.height as u32,
                block_id: head_block.id(),
            },
            last_irreversible: BlockPosition {
                block_num: head_block.height as u32,
                block_id: head_block.id(),
            },
            trace_begin_block: 1,
            trace_end_block: head_block.height as u32,
            chain_state_begin_block: 1,
            chain_state_end_block: head_block.height as u32,
            chain_id: chain_id,
        })
    }
}