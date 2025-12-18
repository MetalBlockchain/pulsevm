use std::sync::{mpsc, Arc};

use anyhow::Result;
use rust_rocksdb::{OptimisticTransactionDB, TransactionDB};
use tokio::{sync::oneshot, task::{spawn_blocking, JoinHandle}};

use crate::{index::Index, write_thread::{Request, Response, WriteThread}, ChainbaseError, ChainbaseObject, SecondaryIndex};

pub struct Message {
    pub(crate) req: Request,
    pub(crate) resp_channel: kanal::Sender<Response>,
}

#[derive(Clone)]
pub struct UndoSession {
    jh: Arc<JoinHandle<()>>,
    send: kanal::Sender<Message>,
}

impl UndoSession {
    #[inline]
    pub fn new(
        db: Arc<OptimisticTransactionDB>,
    ) -> Result<Self, ChainbaseError> {
        let (send, recv) = kanal::bounded::<Message>(0);
        let jh = spawn_blocking(move || WriteThread::run_server(db.clone(), recv));

        Ok(Self {
            jh: Arc::new(jh),
            send,
        })
    }

    fn process_request(&self, req: Request) -> Result<Response, ChainbaseError> {
        let (tx, rx) = kanal::bounded(1);

        let m = Message {
            req,
            resp_channel: tx,
        };
        if let Err(e) = self.send.send(m) {
            return Err(ChainbaseError::InternalError(format!(
                "failed to send request to write thread: {}",
                e
            )));
        }
        let resp = rx.recv();

        match resp {
            Err(e) => Err(ChainbaseError::InternalError(format!(
                "failed to receive response from write thread: {}",
                e
            ))),
            Ok(r) => Ok(r),
        }
    }

    #[must_use]
    #[inline]
    pub fn find<T: ChainbaseObject>(&self, key: T::PrimaryKey) -> Result<Option<T>, ChainbaseError> {
        let r = self.process_request(Request::Get { cf: T::table_name(), key: T::primary_key_to_bytes(key) })?;
        
        match r {
            Response::Value(opt_bytes) => {
                if let Some(bytes) = opt_bytes {
                    let mut pos = 0usize;
                    let obj = T::read(&bytes, &mut pos)
                        .map_err(|_| ChainbaseError::InternalError("failed to read object".into()))?;
                    Ok(Some(obj))
                } else {
                    Ok(None)
                }
            }
            Response::Error(status) => Err(ChainbaseError::InternalError(format!("error getting object: {}", status))),
            _ => Err(ChainbaseError::InternalError("unexpected response type".into())),
        }
    }

    #[must_use]
    #[inline]
    pub fn get<T: ChainbaseObject>(&self, key: T::PrimaryKey) -> Result<T, ChainbaseError> {
        let r = self.find(key)?;

        match r {
            Some(obj) => Ok(obj),
            None => Err(ChainbaseError::InternalError(format!("object in {} not found", T::table_name()))),
        }
    }

    #[must_use]
    #[inline]
    pub fn find_by_secondary<T: ChainbaseObject, S: SecondaryIndex<T>>(
        &self,
        key: S::Key,
    ) -> Result<Option<T>, ChainbaseError> {
        let result = self.process_request(Request::Get {
            cf: S::index_name(),
            key: S::secondary_key_as_bytes(key),
        })?;
        
        match result {
            Response::Value(Some(primary_key_bytes)) => {
                let primary_key: T::PrimaryKey = T::primary_key_from_bytes(&primary_key_bytes)
                    .map_err(|_| ChainbaseError::InternalError("failed to read primary key".into()))?;
                self.find::<T>(primary_key)
            }
            Response::Value(None) => Ok(None),
            Response::Error(status) => Err(ChainbaseError::InternalError(format!("error getting by secondary key: {}", status))),
            _ => Err(ChainbaseError::InternalError("unexpected response type".into())),
        }
    }

    #[must_use]
    #[inline]
    pub fn get_by_secondary<T: ChainbaseObject, S: SecondaryIndex<T>>(
        &mut self,
        key: S::Key,
    ) -> Result<T, ChainbaseError> {
        let r = self.find_by_secondary::<T, S>(key)?;

        match r {
            Some(obj) => Ok(obj),
            None => Err(ChainbaseError::InternalError("object not found".into())),
        }
    }

    #[inline]
    pub fn generate_id<T: ChainbaseObject>(&mut self) -> Result<u64, ChainbaseError> {
        let result = self.process_request(Request::GenerateId { cf: T::table_name() })?;
        match result {
            Response::Value(Some(bytes)) => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes[..8]);
                Ok(u64::from_le_bytes(arr))
            }
            Response::Error(status) => Err(ChainbaseError::InternalError(format!("error generating id: {}", status))),
            _ => Err(ChainbaseError::InternalError("unexpected response type".into())),
        }
    }

    pub fn insert<T: ChainbaseObject>(&self, object: &T) -> Result<(), ChainbaseError> {
        let key = object.primary_key();
        let serialized = object.pack().map_err(|_| {
            ChainbaseError::InternalError(format!("failed to serialize object for key: {:?}", key))
        })?;
        self.process_request(Request::Put { cf: T::table_name(), key: key.clone(), val: serialized })?;

        for index in object.secondary_indexes() {
            self.process_request(Request::Put { cf: index.index_name, key: index.key, val: key.clone() })?;
        }
        Ok(())
    }

    #[inline]
    pub fn modify<T, F>(&mut self, old: &mut T, f: F) -> Result<(), ChainbaseError>
    where
        T: ChainbaseObject,
        F: FnOnce(&mut T) -> Result<()>,
    {
        let key = old.primary_key();
        f(old).map_err(|e| {
            ChainbaseError::InternalError(format!("failed to modify object for key {:?}: {e}", key))
        })?;
        let new_bytes = old.pack().map_err(|_| {
            ChainbaseError::InternalError(format!(
                "failed to serialize modified object for key: {:?}",
                key
            ))
        })?;
        self.process_request(Request::Put { cf: T::table_name(), key, val: new_bytes })?;
        Ok(())
    }

    pub fn next_key(&mut self, cf: &'static str, current_key: Option<Vec<u8>>) -> Result<Option<Vec<u8>>, ChainbaseError> {
        let start_key = match current_key {
            Some(k) => k,
            None => vec![],
        };
        let result = self.process_request(Request::Next { cf, key: start_key })?;
        match result {
            Response::Value(Some(next_key_bytes)) => {
                Ok(Some(next_key_bytes))
            }
            Response::Value(None) => Ok(None),
            Response::Error(status) => Err(ChainbaseError::InternalError(format!("error getting next object: {}", status))),
            _ => Err(ChainbaseError::InternalError("unexpected response type".into())),
        }
    }

    pub fn previous_key(&mut self, cf: &'static str, current_key: Option<Vec<u8>>) -> Result<Option<Vec<u8>>, ChainbaseError> {
        let start_key = match current_key {
            Some(k) => k,
            None => vec![],
        };
        let result = self.process_request(Request::Previous { cf, key: start_key })?;
        match result {
            Response::Value(Some(next_key_bytes)) => {
                Ok(Some(next_key_bytes))
            }
            Response::Value(None) => Ok(None),
            Response::Error(status) => Err(ChainbaseError::InternalError(format!("error getting previous object: {}", status))),
            _ => Err(ChainbaseError::InternalError("unexpected response type".into())),
        }
    }

    #[inline]
    pub fn remove<T: ChainbaseObject>(&mut self, object: T) -> Result<(), ChainbaseError> {
        let key = object.primary_key();
        self.process_request(Request::Delete { cf: T::table_name(), key })?;
        for index in object.secondary_indexes() {
            self.process_request(Request::Delete { cf: index.index_name, key: index.key })?;
        }
        Ok(())
    }

    #[inline]
    pub fn commit(self) -> Result<(), ChainbaseError> {
        self.process_request(Request::Commit)?;
        Ok(())
    }

    #[inline]
    pub fn rollback(self) -> Result<(), ChainbaseError> {
        self.process_request(Request::Close)?;
        Ok(())
    }

    #[inline]
    pub fn get_index<C, S>(&self) -> Index<C, S>
    where
        C: ChainbaseObject,
        S: SecondaryIndex<C>,
    {
        Index::<C, S>::new(self.clone())
    }
}