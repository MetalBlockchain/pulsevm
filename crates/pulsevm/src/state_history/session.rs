use std::{
    net::SocketAddr,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use anyhow::{Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use pulsevm_core::{controller::Controller, state_history::SHIP_ABI, transaction::TransactionTrace};
use pulsevm_crypto::Bytes;
use pulsevm_serialization::{Read, Write};
use spdlog::{error, info};
use tokio::{
    sync::{
        RwLock, mpsc,
        watch::{self, Sender},
    },
    task::JoinHandle,
};
use tokio_tungstenite::accept_async;
use tungstenite::Message;

use crate::state_history::{
    request::RequestType,
    types::{BlockPosition, GetBlocksAckRequestV0, GetBlocksRequestV0, GetBlocksResponseV0, GetStatusResult, TransactionTraceV0},
};

pub struct Session {
    peer: SocketAddr,
    controller: Arc<RwLock<Controller>>,
    current_request: Option<GetBlocksRequestV0>,
    to_send_block_num: u32,
    // streaming control
    stream_cancel: Option<Sender<()>>,
    stream_handle: Option<JoinHandle<()>>,
}

impl Session {
    pub fn new(peer: SocketAddr, controller: Arc<RwLock<Controller>>) -> Self {
        Self {
            peer,
            controller,
            current_request: None,
            to_send_block_num: 0,
            stream_cancel: None,
            stream_handle: None,
        }
    }

    pub async fn start(&mut self, stream: tokio::net::TcpStream) -> Result<()> {
        let ws = accept_async(stream).await?;

        // Split socket once; dedicate a writer task fed by mpsc
        let (mut sink, mut reader) = ws.split();
        let (tx_out, mut rx_out) = mpsc::channel::<Message>(128);

        let writer = tokio::spawn(async move {
            while let Some(msg) = rx_out.recv().await {
                if let Err(e) = sink.send(msg).await {
                    eprintln!("writer: send failed: {e}");
                    break;
                }
            }
            // Try to finish the close handshake gracefully
            let _ = sink.flush().await;
            let _ = sink.close().await;
        });

        // ABI must be the first frame sent
        tx_out.send(Message::Text(SHIP_ABI.to_string())).await.ok();

        // messages-in-flight budget (incremented by ACKs)
        let in_flight_budget = Arc::new(AtomicI64::new(0));

        while let Some(msg) = reader.next().await {
            let msg = msg?;
            match msg {
                Message::Binary(b) => {
                    let req_type = RequestType::read(&b, &mut 0).map_err(|e| anyhow!("failed to parse request type: {:?}", e))?;

                    match req_type {
                        RequestType::GetStatusRequestV0 => {
                            let result = self.get_status().await?;
                            let packed = result.pack()?;
                            let _ = tx_out.send(Message::Binary(packed)).await;
                        }
                        RequestType::GetBlocksRequestV0 => {
                            let mut request =
                                GetBlocksRequestV0::read(&b, &mut 1).map_err(|e| anyhow!("failed to parse GetBlocksRequestV0: {:?}", e))?;
                            self.update_current_request(&mut request).await?;

                            // Initialize window (fallback if zero)
                            let window = if request.max_messages_in_flight == 0 {
                                16
                            } else {
                                request.max_messages_in_flight as i64
                            };
                            in_flight_budget.store(window, Ordering::SeqCst);

                            // Cancel any previous stream
                            if let Some(tx) = &self.stream_cancel {
                                let _ = tx.send(());
                            }
                            if let Some(handle) = self.stream_handle.take() {
                                // Immediate stop; comment if you prefer graceful await
                                handle.abort();
                                let _ = handle.await;
                            }

                            // New cancel channel for this stream
                            let (stop_tx, mut stop_rx) = watch::channel(());
                            self.stream_cancel = Some(stop_tx);

                            // Spawn background producer
                            let ctrl = self.controller.clone();
                            let start_from = self.to_send_block_num;
                            let tx_clone = tx_out.clone();
                            let budget = in_flight_budget.clone();

                            self.stream_handle = Some(tokio::spawn(async move {
                                let mut next = start_from;

                                loop {
                                    // cooperative cancel
                                    if stop_rx.has_changed().unwrap_or(false) {
                                        break;
                                    }

                                    // backpressure window
                                    if budget.fetch_sub(1, Ordering::SeqCst) <= 0 {
                                        budget.fetch_add(1, Ordering::SeqCst);
                                        tokio::time::sleep(Duration::from_millis(3)).await;
                                        continue;
                                    }

                                    match make_block_response_for(ctrl.clone(), &request, next).await {
                                        Ok(resp) => {
                                            match resp.pack() {
                                                Ok(bytes) => {
                                                    if tx_clone.send(Message::Binary(bytes)).await.is_err() {
                                                        // writer/socket is gone, stop
                                                        break;
                                                    }
                                                    next = next.saturating_add(1);
                                                }
                                                Err(e) => {
                                                    error!("pack failed for block {next}: {e}");
                                                    // give window slot back
                                                    budget.fetch_add(1, Ordering::SeqCst);
                                                    tokio::time::sleep(Duration::from_millis(5)).await;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            // Likely "block not ready yet" — backoff and retry
                                            // return slot because nothing was sent
                                            budget.fetch_add(1, Ordering::SeqCst);
                                            //error!("build response for block {next} failed: {e}");
                                            tokio::time::sleep(Duration::from_millis(500)).await;
                                        }
                                    }

                                    // react quickly to cancellation
                                    if stop_rx.has_changed().unwrap_or(false) {
                                        break;
                                    }
                                }
                            }));
                        }
                        RequestType::GetBlocksAckRequestV0 => {
                            let request =
                                GetBlocksAckRequestV0::read(&b, &mut 1).map_err(|e| anyhow!("failed to parse GetBlocksAckRequestV0: {:?}", e))?;

                            in_flight_budget.fetch_add(request.num_messages as i64, Ordering::SeqCst);
                        }
                    }
                }
                Message::Ping(p) => {
                    tx_out.send(Message::Pong(p)).await.ok();
                }
                Message::Close(cf) => {
                    let _ = tx_out.send(Message::Close(cf)).await;
                    break;
                }
                Message::Text(s) => {
                    // SHiP clients shouldn't send text after the ABI, but we won't crash.
                    eprintln!("{} unexpected text: {}", self.peer, s);
                }
                _ => {}
            }
        }

        // Shut down any active stream
        if let Some(tx) = &self.stream_cancel {
            let _ = tx.send(());
        }
        if let Some(h) = self.stream_handle.take() {
            h.abort();
            let _ = h.await;
        }

        // Drop the tx to end the writer; then await it
        drop(tx_out);
        let _ = writer.await;

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
            chain_id: chain_id.clone(),
        })
    }

    pub async fn update_current_request(&mut self, req: &mut GetBlocksRequestV0) -> Result<()> {
        let controller = self.controller.read().await;

        self.to_send_block_num = std::cmp::max(req.start_block_num, 1);

        for cp in req.have_positions.iter() {
            if req.start_block_num <= cp.block_num {
                continue;
            }

            let id = controller.get_block_id(cp.block_num).await?;

            if id.is_none() || id.unwrap() != cp.block_id {
                req.start_block_num = std::cmp::min(req.start_block_num, cp.block_num);
            }

            if id.is_none() {
                self.to_send_block_num = std::cmp::min(self.to_send_block_num, cp.block_num);
                info!("block {} is not available", cp.block_num);
            } else if id.unwrap() != cp.block_id {
                self.to_send_block_num = std::cmp::min(self.to_send_block_num, cp.block_num);
                info!(
                    "the id for block {} in block request have_positions does not match the existing",
                    cp.block_num
                );
            }
        }

        self.current_request = Some(req.clone());

        Ok(())
    }
}

// Builds a GetBlocksResponseV0 for a specific block number.
// Replace internals with your real "get block by number" logic.
// As-is, it waits until head >= block_num and then returns head as the block payload.
async fn make_block_response_for(controller: Arc<RwLock<Controller>>, request: &GetBlocksRequestV0, block_num: u32) -> Result<GetBlocksResponseV0> {
    let controller = controller.read().await;
    let head = controller.last_accepted_block();

    if head.block_num() < block_num {
        return Err(anyhow!("block {block_num} not yet available"));
    }

    // Get the requested block
    let this_block_id = controller
        .get_block_id(block_num)
        .await?
        .ok_or(anyhow!("block {block_num} not found, may not be available yet",))?;

    // Get the previous block if it exists
    let mut previous_block: Option<BlockPosition> = None;
    if block_num > 1 {
        if let Some(prev_id) = controller.get_block_id(block_num - 1).await? {
            previous_block = Some(BlockPosition {
                block_num: block_num - 1,
                block_id: prev_id,
            });
        }
    }

    let mut block: Option<Bytes> = None;
    if request.fetch_block {
        let signed_block = controller
            .get_block(this_block_id)
            .map_err(|e| anyhow!("failed to get block {block_num} by id {this_block_id:?}: {e}"))?
            .unwrap();
        let signed_block_packed = signed_block.pack()?;
        block = Some(Bytes::new(signed_block_packed));
    }

    let mut traces: Option<Bytes> = None;
    if request.fetch_traces && block_num > 1 {
        let trace_log = controller.trace_log();

        if let Some(log) = &trace_log {
            if let Ok(packed_traces) = log.read_block(block_num) {
                let transaction_traces: Vec<TransactionTrace> =
                    Vec::read(&packed_traces, &mut 0).map_err(|e| anyhow!("failed to read traces for block {block_num}: {e}"))?;
                let converted_traces = transaction_traces
                    .iter()
                    .map(|t| TransactionTraceV0::from(t))
                    .collect::<Vec<TransactionTraceV0>>();
                let packed_converted_traces = converted_traces.pack()?;
                traces = Some(Bytes::new(packed_converted_traces));
            }
        }
    }

    println!("sending block {block_num}");

    Ok(GetBlocksResponseV0 {
        variant: 1,
        head: BlockPosition {
            block_num: head.block_num(),
            block_id: head.id(),
        },
        last_irreversible: BlockPosition {
            block_num: head.block_num(),
            block_id: head.id(),
        },
        this_block: Some(BlockPosition {
            block_num,
            block_id: this_block_id,
        }),
        prev_block: previous_block,
        block: block,
        traces: traces,
        deltas: None,
    })
}
