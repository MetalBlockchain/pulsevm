use std::sync::{mpsc, Arc, RwLock};

use rust_rocksdb::{BoundColumnFamily, Direction, OptimisticTransactionDB, TransactionDB, DB};
use tokio::sync::oneshot;

use crate::{undo_session::Message, ChainbaseError};

pub enum Request {
    Close,
    Put { cf: &'static str, key: Vec<u8>, val: Vec<u8> },
    Delete { cf: &'static str, key: Vec<u8> },
    Commit,
    GenerateId { cf: &'static str },
    Get { cf: &'static str, key: Vec<u8> },
    Next { cf: &'static str, key: Vec<u8> },
    Previous { cf: &'static str, key: Vec<u8> },
}

pub enum Response {
    OK,
    Error(ChainbaseError),
    Value(Option<Vec<u8>>),
}

pub struct WriteThread;

impl WriteThread {
    pub fn run_server(db: Arc<OptimisticTransactionDB>, recv: kanal::Receiver<Message>) {
        let txn = db.transaction();

        while let Some(msg) = recv.recv().ok() {
            match msg.req {
                Request::Close => {
                    send_response(msg.resp_channel, Response::OK);
                    return;
                }
                Request::Get { cf, key } => {
                    let handle = match db.cf_handle(cf) {
                        Some(h) => h,
                        None => {
                            send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                                format!("column family {} not found", cf),
                            )));
                            continue;
                        }
                    };
                    let res = txn.get_cf(&handle, key);
                    match res {
                        Ok(v) => send_response(msg.resp_channel, Response::Value(v)),
                        Err(e) => send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                            format!("internal error: {}", e),
                        ))),
                    }
                }
                Request::Delete { cf, key } => {
                    let handle = match db.cf_handle(cf) {
                        Some(h) => h,
                        None => {
                            send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                                format!("column family {} not found", cf),
                            )));
                            continue;
                        }
                    };
                    let res = txn.delete_cf(&handle, key);
                    match res {
                        Ok(_) => send_response(msg.resp_channel, Response::OK),
                        Err(e) => send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                            format!("internal error: {}", e),
                        ))),
                    }
                }
                Request::Put { cf, key, val } => {
                    let handle = match db.cf_handle(cf) {
                        Some(h) => h,
                        None => {
                            send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                                format!("column family {} not found", cf),
                            )));
                            continue;
                        }
                    };
                    let res = txn.put_cf(&handle, key, val);
                    match res {
                        Ok(_) => send_response(msg.resp_channel, Response::OK),
                        Err(e) => send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                            format!("internal error: {}", e),
                        ))),
                    }
                }
                Request::GenerateId { cf } => {
                    let handle = match db.cf_handle(cf) {
                        Some(h) => h,
                        None => {
                            send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                                format!("column family {} not found", cf),
                            )));
                            continue;
                        }
                    };
                    let res = txn.get_cf(&handle, b"__id_counter__");
                    match res {
                        Ok(opt_bytes) => {
                            let new_id = if let Some(bytes) = opt_bytes {
                                let mut arr = [0u8; 8];
                                arr.copy_from_slice(&bytes[..8]);
                                u64::from_le_bytes(arr) + 1
                            } else {
                                1u64
                            };
                            let new_bytes = new_id.to_le_bytes().to_vec();
                            let put_res = txn.put_cf(&handle, b"__id_counter__", new_bytes);
                            match put_res {
                                Ok(_) => send_response(msg.resp_channel, Response::Value(Some(new_id.to_le_bytes().to_vec()))),
                                Err(e) => send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                                    format!("internal error: {}", e),
                                ))),
                            }
                        }
                        Err(e) => send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                            format!("internal error: {}", e),
                        ))),
                    }
                }
                Request::Next { cf, key } => {
                    let handle = match db.cf_handle(cf) {
                        Some(h) => h,
                        None => {
                            send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                                format!("column family {} not found", cf),
                            )));
                            continue;
                        }
                    };
                    let mut res = txn.iterator_cf(&handle, rust_rocksdb::IteratorMode::From(key.as_slice(), Direction::Forward));

                    match res.next() {
                        Some(Ok((k, v))) => send_response(msg.resp_channel, Response::Value(Some(v.to_vec()))),
                        Some(Err(e)) => send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                            format!("internal error: {}", e),
                        ))),
                        None => send_response(msg.resp_channel, Response::Value(None)),
                    }
                }
                Request::Previous { cf, key } => {
                    let handle = match db.cf_handle(cf) {
                        Some(h) => h,
                        None => {
                            send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                                format!("column family {} not found", cf),
                            )));
                            continue;
                        }
                    };
                    let mut res = txn.iterator_cf(&handle, rust_rocksdb::IteratorMode::From(key.as_slice(), Direction::Reverse));

                    match res.next() {
                        Some(Ok((k, v))) => send_response(msg.resp_channel, Response::Value(Some(v.to_vec()))),
                        Some(Err(e)) => send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                            format!("internal error: {}", e),
                        ))),
                        None => send_response(msg.resp_channel, Response::Value(None)),
                    }
                }
                Request::Commit => {
                    let res = txn.commit();
                    match res {
                        Ok(_) => send_response(msg.resp_channel, Response::OK),
                        Err(e) => send_response(msg.resp_channel, Response::Error(ChainbaseError::InternalError(
                            format!("internal error: {}", e),
                        ))),
                    }
                    return;
                }
            }
        }
    }
}

#[inline]
fn send_response(ch: kanal::Sender<Response>, res: Response) {
    ch.send(res).ok();
}