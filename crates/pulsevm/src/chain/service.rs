use std::{
    collections::BTreeSet,
    str::FromStr,
    sync::{
        Arc,
        RwLock as StdRwLock,
        atomic::{
            AtomicU64,
            Ordering,
        },
    },
    time::Instant,
};

use jsonrpsee::{
    proc_macros::rpc,
    types::ErrorObjectOwned,
};
use pulsevm_core::{
    ChainError,
    abi::AbiDefinition,
    authorization_manager::AuthorizationManager,
    block::SignedBlock,
    controller::{
        Controller,
        MempoolAdmissionState,
    },
    crypto::{
        PublicKey,
        Signature,
    },
    id::Id,
    mempool::Mempool,
    name::Name,
    protocol_features::PROTOCOL_VERSION,
    time::{
        TimePoint,
        seconds,
    },
    transaction::{
        PackedTransaction,
        Transaction,
        TransactionCompression,
    },
    utils::{
        Base64Bytes,
        I32Flex,
        StringFlex,
    },
};
use pulsevm_crypto::{
    Bytes,
    Digest,
};
use pulsevm_serialization::Read;
use serde_json::Value;
use tokio::sync::RwLock;
use tonic::async_trait;

use crate::{
    api::{
        GetCodeHashResponse,
        GetInfoResponse,
        GetProducersResponse,
        GetRawABIResponse,
        IssueTxResponse,
    },
    chain::{
        GossipType,
        Gossipable,
        NetworkManager,
    },
};

#[rpc(server)]
pub trait Rpc {
    #[method(name = "pulsevm.issueTx")]
    async fn issue_tx(
        &self,
        signatures: BTreeSet<Signature>,
        compression: TransactionCompression,
        packed_context_free_data: Bytes,
        packed_trx: Bytes,
    ) -> Result<IssueTxResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getABI")]
    async fn get_abi(&self, account_name: Name) -> Result<AbiDefinition, ErrorObjectOwned>;

    #[method(name = "pulsevm.getAccount")]
    async fn get_account(
        &self,
        account_name: Name,
        expected_core_symbol: Option<String>,
    ) -> Result<Value, ErrorObjectOwned>;

    #[method(name = "pulsevm.getBlock")]
    async fn get_block(&self, block_num_or_id: String) -> Result<SignedBlock, ErrorObjectOwned>;

    #[method(name = "pulsevm.getCodeHash")]
    async fn get_code_hash(
        &self,
        account_name: Name,
    ) -> Result<GetCodeHashResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getCurrencyBalance")]
    async fn get_currency_balance(
        &self,
        code: Name,
        account: Name,
        symbol: Option<String>,
    ) -> Result<Value, ErrorObjectOwned>;

    #[method(name = "pulsevm.getCurrencyStats")]
    async fn get_currency_stats(
        &self,
        code: Name,
        symbol: String,
    ) -> Result<Value, ErrorObjectOwned>;

    #[method(name = "pulsevm.getInfo")]
    async fn get_info(&self) -> Result<GetInfoResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getProducers")]
    async fn get_producers(&self) -> Result<GetProducersResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getRawABI")]
    async fn get_raw_abi(&self, account_name: Name) -> Result<GetRawABIResponse, ErrorObjectOwned>;

    #[method(name = "pulsevm.getRawBlock")]
    async fn get_raw_block(&self, block_num_or_id: String)
    -> Result<SignedBlock, ErrorObjectOwned>;

    #[method(name = "pulsevm.getRequiredKeys")]
    async fn get_required_keys(
        &self,
        trx: Transaction,
        candidate_keys: BTreeSet<PublicKey>,
    ) -> Result<BTreeSet<PublicKey>, ErrorObjectOwned>;

    #[method(name = "pulsevm.getTableByScope")]
    async fn get_table_by_scope(
        &self,
        code: Name,
        table: Name,
        lower_bound: Option<StringFlex>,
        upper_bound: Option<StringFlex>,
        limit: Option<I32Flex>,
        reverse: Option<bool>,
    ) -> Result<Value, ErrorObjectOwned>;

    #[method(name = "pulsevm.getTableRows")]
    async fn get_table_rows(
        &self,
        json: Option<bool>,
        code: Name,
        scope: String,
        table: Name,
        table_key: Option<String>,
        lower_bound: Option<StringFlex>,
        upper_bound: Option<StringFlex>,
        limit: Option<I32Flex>,
        key_type: String,
        index_position: Option<I32Flex>,
        encode_type: Option<String>, //dec, hex , default=dec
        reverse: Option<bool>,
        show_payer: Option<bool>,
    ) -> Result<Value, ErrorObjectOwned>;
}

#[derive(Clone)]
pub struct RpcService {
    mempool: Arc<RwLock<Mempool>>,
    controller: Arc<RwLock<Controller>>,
    admission_state: Arc<StdRwLock<Option<MempoolAdmissionState>>>,
    admission_metrics: Arc<AdmissionMetrics>,
    network_manager: Arc<RwLock<NetworkManager>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmissionMetricsSnapshot {
    pub state_preflights: u64,
    pub fallback_controller_preflights: u64,
    pub controller_lock_wait_nanos: u64,
    pub max_controller_lock_wait_nanos: u64,
    pub mempool_lock_wait_nanos: u64,
    pub max_mempool_lock_wait_nanos: u64,
}

#[derive(Default)]
struct AdmissionMetrics {
    state_preflights: AtomicU64,
    fallback_controller_preflights: AtomicU64,
    controller_lock_wait_nanos: AtomicU64,
    max_controller_lock_wait_nanos: AtomicU64,
    mempool_lock_wait_nanos: AtomicU64,
    max_mempool_lock_wait_nanos: AtomicU64,
}

impl AdmissionMetrics {
    fn record_mempool_wait(&self, started: Instant) {
        let waited = started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        self.mempool_lock_wait_nanos
            .fetch_add(waited, Ordering::Relaxed);
        self.max_mempool_lock_wait_nanos
            .fetch_max(waited, Ordering::Relaxed);
    }

    fn snapshot(&self) -> AdmissionMetricsSnapshot {
        AdmissionMetricsSnapshot {
            state_preflights: self.state_preflights.load(Ordering::Relaxed),
            fallback_controller_preflights: self
                .fallback_controller_preflights
                .load(Ordering::Relaxed),
            controller_lock_wait_nanos: self.controller_lock_wait_nanos.load(Ordering::Relaxed),
            max_controller_lock_wait_nanos: self
                .max_controller_lock_wait_nanos
                .load(Ordering::Relaxed),
            mempool_lock_wait_nanos: self.mempool_lock_wait_nanos.load(Ordering::Relaxed),
            max_mempool_lock_wait_nanos: self.max_mempool_lock_wait_nanos.load(Ordering::Relaxed),
        }
    }
}

impl RpcService {
    pub fn new(
        mempool: Arc<RwLock<Mempool>>,
        controller: Arc<RwLock<Controller>>,
        network_manager: Arc<RwLock<NetworkManager>>,
    ) -> Self {
        RpcService {
            mempool,
            controller,
            admission_state: Arc::new(StdRwLock::new(None)),
            admission_metrics: Arc::new(AdmissionMetrics::default()),
            network_manager,
        }
    }

    /// Install the current controller-backed preflight view after controller
    /// initialization. Its database handle is internally synchronized, so
    /// admission no longer waits for the controller's exclusive block lock.
    pub fn set_admission_state(&self, state: MempoolAdmissionState) {
        *self
            .admission_state
            .write()
            .expect("admission state lock poisoned") = Some(state);
    }

    pub fn admission_metrics(&self) -> AdmissionMetricsSnapshot {
        self.admission_metrics.snapshot()
    }

    pub async fn handle_api_request(
        &self,
        request_body: &str,
    ) -> Result<String, serde_json::Error> {
        // Make sure `RpcService` implements your API trait
        let module = self.clone().into_rpc();

        // Run the request and return the response
        let (resp, mut _stream) = module.raw_json_request(request_body, 1).await?;
        //let resp: ResponseSuccess<u64> =
        // serde_json::from_str::<Response<u64>>(&resp).unwrap().try_into().unwrap();

        Ok(resp)
    }

    /// Validate a packed transaction and admit it to the mempool. Returns
    /// `Ok(true)` if it was newly added, `Ok(false)` if it was already known (or
    /// the mempool is full), and `Err` if it failed validation and must not be
    /// propagated. Shared by the RPC issue path and the peer-gossip path so both
    /// apply the same admission rules. Admission validates transaction shape,
    /// lifetime, referenced accounts, and authorization, but defers action
    /// execution to block production. The newly-added flag lets the caller relay
    /// exactly once, which stops gossip from looping.
    pub async fn admit_transaction(
        &self,
        packed_trx: PackedTransaction,
    ) -> Result<bool, ChainError> {
        // Expired transactions must not occupy a bounded mempool or make a
        // re-gossiped transaction look like a duplicate. Do this before the
        // membership check so a newly arrived transaction can reclaim stale
        // capacity immediately.
        let now = TimePoint::now();
        let expires_present = {
            let lock_started = Instant::now();
            let mempool = self.mempool.read().await;
            self.admission_metrics.record_mempool_wait(lock_started);

            // Fast path: a transaction we already hold has been validated and
            // relayed once already, so skip preflight and report it as not newly
            // added. This is what absorbs re-gossip of a transaction already in
            // flight.
            if mempool.contains(packed_trx.id()) {
                return Ok(false);
            }
            mempool.has_expired(&now)
        };
        if expires_present {
            let lock_started = Instant::now();
            let mut mempool = self.mempool.write().await;
            self.admission_metrics.record_mempool_wait(lock_started);
            mempool.prune_expired(&now);
            if mempool.contains(packed_trx.id()) {
                return Ok(false);
            }
        }

        // Preflight is synchronous, performs database reads and signature
        // recovery, and has no await points. Run it on the blocking pool rather
        // than holding an async read lock on a runtime worker. It does not
        // execute WASM or open an undo session.
        let admission_state = self
            .admission_state
            .read()
            .expect("admission state lock poisoned")
            .clone();
        let controller = self.controller.clone();
        let metrics = self.admission_metrics.clone();
        let trx_for_exec = packed_trx.clone();
        let execution = tokio::task::spawn_blocking(move || {
            let pending_block_timestamp = TimePoint::now().into();
            match admission_state {
                Some(state) => {
                    metrics.state_preflights.fetch_add(1, Ordering::Relaxed);
                    state.validate_transaction(&trx_for_exec, &pending_block_timestamp)
                }
                // Tests and callers that construct RpcService before controller
                // initialization retain the safe, serialized fallback until the
                // controller installs its read-only admission state.
                None => {
                    metrics
                        .fallback_controller_preflights
                        .fetch_add(1, Ordering::Relaxed);
                    let lock_started = Instant::now();
                    let controller = controller.blocking_read();
                    let waited = lock_started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
                    metrics
                        .controller_lock_wait_nanos
                        .fetch_add(waited, Ordering::Relaxed);
                    metrics
                        .max_controller_lock_wait_nanos
                        .fetch_max(waited, Ordering::Relaxed);
                    controller
                        .validate_transaction_for_mempool(&trx_for_exec, &pending_block_timestamp)
                }
            }
        })
        .await
        .map_err(|e| {
            ChainError::InternalError(format!("transaction execution task failed: {e}"))
        })?;
        match execution {
            Ok(_) => {}
            Err(error) if error.is_fatal_consistency() => {
                crate::abort_on_fatal_consistency("transaction admission", &error)
            }
            Err(error) => return Err(error),
        }

        let lock_started = Instant::now();
        let mut mempool = self.mempool.write().await;
        self.admission_metrics.record_mempool_wait(lock_started);
        let now = TimePoint::now();
        if mempool.has_expired(&now) {
            mempool.prune_expired(&now);
        }
        Ok(mempool.add_transaction(packed_trx))
    }

    /// Build a candidate from a detached mempool batch. Keeping this orchestration
    /// beside admission makes the lock boundary explicit: controller execution is
    /// exclusive, but the live pool is available again before that execution
    /// starts.
    pub async fn build_block(&self) -> Result<SignedBlock, ChainError> {
        let mut batch = {
            let mut mempool = self.mempool.write().await;
            mempool.take_all()
        };
        let result = {
            let mut controller = self.controller.write().await;
            controller.build_block(batch.transactions_mut()).await
        };
        self.mempool.write().await.finish_batch(batch);
        result
    }

    /// Verify a candidate using the same detached-batch policy as production.
    /// Transactions that arrived while verification ran remain in the live pool;
    /// deferred older entries are restored when the batch finishes.
    pub async fn verify_block(&self, block: &SignedBlock) -> Result<(), ChainError> {
        let mut batch = {
            let mut mempool = self.mempool.write().await;
            mempool.take_all()
        };
        let result = {
            let mut controller = self.controller.write().await;
            controller
                .verify_block(block, batch.transactions_mut())
                .await
        };
        self.mempool.write().await.finish_batch(batch);
        result
    }
}

#[async_trait]
impl RpcServer for RpcService {
    async fn get_abi(&self, account_name: Name) -> Result<AbiDefinition, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let abi_bytes = db
            .arena_account_abi_bytes(account_name.as_u64())
            .ok_or_else(|| {
                ErrorObjectOwned::owned(
                    404,
                    "account_error",
                    Some(format!("account {} not found", account_name)),
                )
            })?;
        let abi = AbiDefinition::read(abi_bytes.as_slice(), &mut 0).map_err(|e| {
            ErrorObjectOwned::owned(400, "abi_error", Some(format!("failed to read ABI: {}", e)))
        })?;
        Ok(abi)
    }

    async fn get_account(
        &self,
        name: Name,
        expected_core_symbol: Option<String>,
    ) -> Result<Value, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let head_block_time = controller.last_accepted_block().timestamp().to_time_point();
        let head_block_num = controller.last_accepted_block().block_num();

        match expected_core_symbol {
            Some(symbol) => {
                let account_info_json = db.get_account_info_with_core_symbol(
                    name.as_u64(),
                    &symbol,
                    head_block_num,
                    &head_block_time,
                )?;
                let account_info: Value =
                    serde_json::from_str(&account_info_json).map_err(|e| {
                        ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
                    })?;
                Ok(account_info)
            }
            None => {
                let account_info_json = db.get_account_info_without_core_symbol(
                    name.as_u64(),
                    head_block_num,
                    &head_block_time,
                )?;
                let account_info: Value =
                    serde_json::from_str(&account_info_json).map_err(|e| {
                        ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
                    })?;
                Ok(account_info)
            }
        }
    }

    async fn get_block(&self, block_num_or_id: String) -> Result<SignedBlock, ErrorObjectOwned> {
        return self.get_raw_block(block_num_or_id).await;
    }

    async fn get_code_hash(
        &self,
        account_name: Name,
    ) -> Result<GetCodeHashResponse, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let (code_hash, _vm_type, _vm_version) = db
            .account_code_hash_vm(account_name.as_u64())
            .map_err(|e| ErrorObjectOwned::owned(404, "account_error", Some(format!("{}", e))))?;
        Ok(GetCodeHashResponse {
            account_name,
            code_hash: Id::new(code_hash),
        })
    }

    async fn get_currency_balance(
        &self,
        code: Name,
        account: Name,
        symbol: Option<String>,
    ) -> Result<Value, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let response = match symbol {
            Some(s) => {
                let balance_str = db
                    .get_currency_balance_with_symbol(code.as_u64(), account.as_u64(), &s)
                    .map_err(|e| {
                        ErrorObjectOwned::owned(500, "internal_error", Some(format!("{}", e)))
                    })?;
                let balance: Value = serde_json::from_str(&balance_str).map_err(|e| {
                    ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
                })?;
                Ok(balance)
            }
            None => {
                let balance_str = db
                    .get_currency_balance_without_symbol(code.as_u64(), account.as_u64())
                    .map_err(|e| {
                        ErrorObjectOwned::owned(500, "internal_error", Some(format!("{}", e)))
                    })?;
                let balance: Value = serde_json::from_str(&balance_str).map_err(|e| {
                    ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
                })?;
                Ok(balance)
            }
        };

        return response;
    }

    async fn get_currency_stats(
        &self,
        code: Name,
        symbol: String,
    ) -> Result<Value, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let database = controller.database();
        let response = database.get_currency_stats(code.as_u64(), symbol.as_str())?;
        let stats: Value = serde_json::from_str(&response).map_err(|e| {
            ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
        })?;
        Ok(stats)
    }

    async fn get_info(&self) -> Result<GetInfoResponse, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let head_block = controller.last_accepted_block();
        let db = controller.database();
        let head_block_id = head_block.id()?;

        Ok(GetInfoResponse {
            server_version: "d133c641".to_owned(),
            protocol_version: controller.protocol_version(head_block.block_num()),
            supported_protocol_version: PROTOCOL_VERSION,
            protocol_upgrade_schedule_hash: hex::encode(
                controller.protocol_upgrade_schedule_hash(),
            ),
            next_protocol_upgrade: controller
                .next_protocol_upgrade(head_block.block_num())
                .map(|upgrade| crate::api::ProtocolUpgradeInfo {
                    protocol_version: upgrade.protocol_version,
                    activation_height: upgrade.activation_height,
                }),
            server_time: TimePoint::now().into(),
            chain_id: controller.chain_id().clone(),
            head_block_num: head_block.block_num(),
            last_irreversible_block_num: head_block.block_num(),
            last_irreversible_block_id: head_block_id,
            head_block_id: head_block_id,
            head_block_time: head_block.timestamp().clone(),
            head_block_producer: head_block.signed_block_header.header.producer,
            virtual_block_cpu_limit: db.get_virtual_block_cpu_limit()?,
            virtual_block_net_limit: db.get_virtual_block_net_limit()?,
            block_cpu_limit: db.get_block_cpu_limit()?,
            block_net_limit: db.get_block_net_limit()?,
            server_version_string: "v5.0.3".to_owned(),
            fork_db_head_block_id: head_block_id,
            fork_db_head_block_num: head_block.block_num(),
            server_full_version_string: "v5.0.3-d133c6413ce8ce2e96096a0513ec25b4a8dbe837"
                .to_owned(), // Mimic EOS here
            total_cpu_weight: db.get_total_cpu_weight()?,
            total_net_weight: db.get_total_net_weight()?,
            earliest_available_block_num: 1,
            last_irreversible_block_time: head_block.timestamp().clone(),
        })
    }

    async fn get_producers(&self) -> Result<GetProducersResponse, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let schedule = controller.active_producer_schedule();
        Ok(GetProducersResponse {
            schedule_version: schedule.version,
            active_producers: schedule.producers.iter().map(|p| p.producer_name).collect(),
        })
    }

    async fn get_raw_abi(&self, account_name: Name) -> Result<GetRawABIResponse, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let abi_bytes = db
            .arena_account_abi_bytes(account_name.as_u64())
            .unwrap_or_default();
        let (code_hash, _vm_type, _vm_version) = db
            .account_code_hash_vm(account_name.as_u64())
            .map_err(|e| ErrorObjectOwned::owned(404, "account_error", Some(format!("{}", e))))?;

        let mut abi_hash = Digest::default();
        if !abi_bytes.is_empty() {
            abi_hash = Digest::hash(abi_bytes.as_slice());
        }

        Ok(GetRawABIResponse {
            account_name,
            code_hash: Id::new(code_hash),
            abi_hash,
            abi: Base64Bytes::new(abi_bytes),
        })
    }

    async fn get_raw_block(
        &self,
        block_num_or_id: String,
    ) -> Result<SignedBlock, ErrorObjectOwned> {
        let controller = self.controller.clone();
        let controller = controller.read().await;

        if let Ok(n) = block_num_or_id.parse::<u32>() {
            let block = controller.get_block_by_height(n)?;

            match block {
                Some(b) => return Ok(b),
                None => {
                    return Err(ErrorObjectOwned::owned(
                        404,
                        "block_not_found",
                        Some(format!("block {} not found", n)),
                    ));
                }
            }
        } else if let Ok(id) = Id::from_str(block_num_or_id.as_str()) {
            let block = controller.get_block(id)?;

            match block {
                Some(b) => return Ok(b),
                None => {
                    return Err(ErrorObjectOwned::owned(
                        404,
                        "block_not_found",
                        Some(format!("block {} not found", id)),
                    ));
                }
            }
        }

        return Err(ErrorObjectOwned::owned(
            400,
            "invalid_block_identifier",
            Some("block number or ID is invalid".to_string()),
        ));
    }

    async fn issue_tx(
        &self,
        signatures: BTreeSet<Signature>,
        compression: TransactionCompression,
        packed_context_free_data: Bytes,
        packed_trx: Bytes,
    ) -> Result<IssueTxResponse, ErrorObjectOwned> {
        let packed_trx = PackedTransaction::new(
            signatures,
            compression,
            packed_context_free_data,
            packed_trx,
        )?;

        // Validate and admit; only gossip a transaction we hadn't already seen.
        let newly_added = self.admit_transaction(packed_trx.clone()).await?;
        if newly_added {
            let nm = self.network_manager.read().await;
            let gossipable_msg = Gossipable::new(GossipType::Transaction, packed_trx.clone())?;
            nm.gossip(gossipable_msg).await?;
        }

        // Return a simple response
        Ok(IssueTxResponse {
            tx_id: packed_trx.id().clone(),
        })
    }

    async fn get_required_keys(
        &self,
        trx: Transaction,
        candidate_keys: BTreeSet<PublicKey>,
    ) -> Result<BTreeSet<PublicKey>, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let mut db = controller.database();

        let required_keys = AuthorizationManager::get_required_keys(
            &mut db,
            &trx,
            &candidate_keys,
            seconds(trx.header.delay_sec.into()),
        )?;

        Ok(required_keys)
    }

    async fn get_table_by_scope(
        &self,
        code: Name,
        table: Name,
        lower_bound: Option<StringFlex>,
        upper_bound: Option<StringFlex>,
        limit: Option<I32Flex>,
        reverse: Option<bool>,
    ) -> Result<Value, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let response = db.get_table_by_scope(
            code.as_u64(),
            table.as_u64(),
            &lower_bound.unwrap_or_default().0,
            &upper_bound.unwrap_or_default().0,
            limit.unwrap_or(I32Flex(10)).0 as u32,
            reverse.unwrap_or(false),
        )?;

        let response: Value = serde_json::from_str(&response).map_err(|e| {
            ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
        })?;

        Ok(response)
    }

    async fn get_table_rows(
        &self,
        json: Option<bool>,
        code: Name,
        scope: String,
        table: Name,
        table_key: Option<String>,
        lower_bound: Option<StringFlex>,
        upper_bound: Option<StringFlex>,
        limit: Option<I32Flex>,
        key_type: String,
        index_position: Option<I32Flex>,
        encode_type: Option<String>, //dec, hex , default=dec
        reverse: Option<bool>,
        show_payer: Option<bool>,
    ) -> Result<Value, ErrorObjectOwned> {
        let controller = self.controller.read().await;
        let db = controller.database();
        let response = db.get_table_rows(
            json.unwrap_or(false),
            code.as_u64(),
            &scope,
            table.as_u64(),
            &table_key.unwrap_or_default(),
            &lower_bound.unwrap_or_default().0,
            &upper_bound.unwrap_or_default().0,
            limit.unwrap_or(I32Flex(10)).0 as u32,
            &key_type,
            &index_position.unwrap_or(I32Flex(1)).0.to_string(),
            &encode_type.unwrap_or_else(|| "dec".to_string()),
            reverse.unwrap_or(false),
            show_payer.unwrap_or(false),
        )?;

        let rows: Value = serde_json::from_str(&response).map_err(|e| {
            ErrorObjectOwned::owned(500, "serialization_error", Some(format!("{}", e)))
        })?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulsevm_core::{
        authority::{
            Authority,
            KeyWeight,
            PermissionLevel,
        },
        crypto::PrivateKey,
        pulse_contract::NewAccount,
        time::TimePointSec,
        transaction::{
            Action,
            TransactionHeader,
        },
    };
    use pulsevm_serialization::Write;
    use serde_json::json;
    use std::time::Duration;
    use tokio::{
        sync::oneshot,
        time::{
            sleep,
            timeout,
        },
    };

    const GENESIS_KEY: &str = "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez";
    const CHAIN_ID: &str = "c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6";
    const EMPTY_PROTOCOL_SCHEDULE_HASH: &str =
        "bd592e76c0fd69a5a57fe16bb4db1a26d80d7b66c16b760e44207008c07d5d7c";

    fn genesis_bytes(key: &PrivateKey) -> Vec<u8> {
        // Mirrors the controller test genesis: point-denominated CPU budgets and a
        // wide transaction lifetime so the builders' "never expires" expiration is
        // accepted.
        json!({
            "initial_timestamp": "2023-01-01T00:00:00",
            "initial_key": key.get_public_key().to_string(),
            "initial_configuration": {
                "max_block_net_usage": 1048576,
                "target_block_net_usage_pct": 1000,
                "max_transaction_net_usage": 524288,
                "base_per_transaction_net_usage": 12,
                "net_usage_leeway": 500,
                "context_free_discount_net_usage_num": 20,
                "context_free_discount_net_usage_den": 100,
                "max_block_cpu_usage": 3000000000u64,
                "target_block_cpu_usage_pct": 2500,
                "max_transaction_cpu_usage": 1000000000,
                "min_transaction_cpu_usage": 100000,
                "max_transaction_lifetime": 4294967295u32,
                "max_inline_action_size": 4096,
                "max_inline_action_depth": 6,
                "max_authority_depth": 6,
                "max_action_return_value_size": 256
            }
        })
        .to_string()
        .into_bytes()
    }

    // A newaccount transaction whose new account is controlled by `auth_key`,
    // signed by `signer`. Passing a `signer` other than the genesis key models
    // untrusted gossip: the signature can't satisfy pulse@active, so validation
    // must reject it.
    fn newaccount_tx(
        auth_key: &PrivateKey,
        signer: &PrivateKey,
        account: &str,
        chain_id: &Id,
    ) -> PackedTransaction {
        let authority = Authority::new(
            1,
            vec![KeyWeight::new(auth_key.get_public_key().into_k1(), 1)],
            vec![],
            vec![],
        );
        let action = Action::new(
            Name::from_str("pulse").unwrap(),
            Name::from_str("newaccount").unwrap(),
            NewAccount {
                creator: Name::from_str("pulse").unwrap(),
                name: Name::from_str(account).unwrap(),
                owner: authority.clone(),
                active: authority,
            }
            .pack()
            .unwrap(),
            vec![PermissionLevel::new(
                Name::from_str("pulse").unwrap().as_u64(),
                Name::from_str("active").unwrap().as_u64(),
            )],
        );
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![action],
        )
        .sign(signer, chain_id)
        .unwrap();
        PackedTransaction::from_signed_transaction(trx).unwrap()
    }

    fn service_with_genesis() -> (
        RpcService,
        Arc<RwLock<Mempool>>,
        PrivateKey,
        Id,
        tempfile::TempDir,
    ) {
        let genesis_key = PrivateKey::from_str(GENESIS_KEY).unwrap();
        let chain_id = Id::from_str(CHAIN_ID).unwrap();
        let temp = tempfile::tempdir().unwrap();

        let mut controller = Controller::new();
        let config_bytes = json!({
            "producer_name": "pulse",
            "producer_key": genesis_key.to_string(),
        })
        .to_string()
        .into_bytes();
        controller
            .initialize(
                &chain_id,
                &config_bytes,
                &genesis_bytes(&genesis_key),
                temp.path().to_str().unwrap(),
            )
            .unwrap();

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let admission_state = controller.mempool_admission_state();
        let service = RpcService::new(
            mempool.clone(),
            Arc::new(RwLock::new(controller)),
            Arc::new(RwLock::new(NetworkManager::new())),
        );
        service.set_admission_state(admission_state);
        (service, mempool, genesis_key, chain_id, temp)
    }

    #[tokio::test]
    async fn get_info_reports_and_serializes_accepted_protocol_state() {
        let (service, _mempool, _genesis_key, _chain_id, _temp) = service_with_genesis();

        let response = service.get_info().await.unwrap();
        assert_eq!(response.protocol_version, 1);
        assert_eq!(response.supported_protocol_version, PROTOCOL_VERSION);
        assert_eq!(
            response.protocol_upgrade_schedule_hash,
            EMPTY_PROTOCOL_SCHEDULE_HASH
        );
        assert!(response.next_protocol_upgrade.is_none());
        assert_eq!(response.head_block_num, 1);

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["protocol_version"], json!(1));
        assert_eq!(json["supported_protocol_version"], json!(PROTOCOL_VERSION));
        assert_eq!(
            json["protocol_upgrade_schedule_hash"],
            json!(EMPTY_PROTOCOL_SCHEDULE_HASH)
        );
        assert_eq!(json["next_protocol_upgrade"], serde_json::Value::Null);
    }

    async fn wait_for_batch_detach(mempool: &Arc<RwLock<Mempool>>) {
        timeout(Duration::from_secs(1), async {
            while mempool.read().await.has_transactions() {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("producer did not detach the mempool batch before waiting for the controller");
    }

    // A correctly signed transaction is validated and admitted once; a second
    // copy (re-gossip) is reported as already known so the caller doesn't relay
    // it again.
    #[tokio::test]
    async fn admit_transaction_validates_and_dedups() {
        let (service, mempool, genesis_key, chain_id, _temp) = service_with_genesis();

        let good = newaccount_tx(&genesis_key, &genesis_key, "alice", &chain_id);
        assert!(
            service.admit_transaction(good.clone()).await.unwrap(),
            "a valid transaction should be newly admitted"
        );
        assert!(mempool.read().await.contains(good.id()));

        assert!(
            !service.admit_transaction(good.clone()).await.unwrap(),
            "a re-gossiped transaction should not be admitted (or relayed) twice"
        );
    }

    // A transaction whose signature can't satisfy the required authority is the
    // shape of untrusted gossip. It must be rejected and must never enter the
    // mempool.
    #[tokio::test]
    async fn admit_transaction_rejects_unauthorized() {
        let (service, mempool, genesis_key, chain_id, _temp) = service_with_genesis();

        let forged = newaccount_tx(&genesis_key, &PrivateKey::random(), "mallory", &chain_id);
        assert!(
            service.admit_transaction(forged.clone()).await.is_err(),
            "a transaction with an unsatisfiable authority must be rejected"
        );
        assert!(
            !mempool.read().await.contains(forged.id()),
            "a rejected transaction must not reach the mempool"
        );
    }

    // Admission intentionally does not execute actions. This transaction has a
    // valid lifetime, account references, and signature, but attempts to create
    // the already-existing `pulse` account and therefore fails only when the
    // producer attempts to build a block. Keeping this distinction prevents
    // every successfully produced transaction from paying for a speculative
    // execute-and-revert first.
    #[tokio::test]
    async fn admit_transaction_defers_action_execution_to_block_production() {
        let (service, mempool, genesis_key, chain_id, _temp) = service_with_genesis();
        let invalid_at_execution = newaccount_tx(&genesis_key, &genesis_key, "pulse", &chain_id);

        assert!(
            service
                .admit_transaction(invalid_at_execution.clone())
                .await
                .unwrap(),
            "static preflight should admit a transaction without executing its action"
        );
        assert!(mempool.read().await.contains(invalid_at_execution.id()));

        let build_result = service.build_block().await;
        assert!(
            build_result.is_err(),
            "the unexecutable transaction should be discarded while building"
        );
        assert!(
            !mempool.read().await.contains(invalid_at_execution.id()),
            "a transaction rejected during block production must not remain queued"
        );
    }

    // Admission uses the synchronized database handle installed at controller
    // initialization rather than taking the controller RwLock. Holding that
    // lock models the full duration of build_block/verify_block execution.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admission_progresses_while_controller_execution_lock_is_held() {
        let (service, mempool, genesis_key, chain_id, _temp) = service_with_genesis();
        let transaction = newaccount_tx(&genesis_key, &genesis_key, "alice", &chain_id);
        let controller_guard = service.controller.write().await;

        let (complete_tx, mut complete_rx) = oneshot::channel();
        let admission_service = service.clone();
        tokio::spawn(async move {
            let _ = complete_tx.send(admission_service.admit_transaction(transaction).await);
        });

        let mut result = None;
        for _ in 0..100 {
            match complete_rx.try_recv() {
                Ok(admission) => {
                    result = Some(admission);
                    break;
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    panic!("admission task exited before returning a result")
                }
            }
        }

        assert!(
            result
                .expect("admission remained blocked on the controller execution lock")
                .expect("admission failed")
        );
        assert!(mempool.read().await.has_transactions());
        let metrics = service.admission_metrics();
        assert_eq!(metrics.state_preflights, 1);
        assert_eq!(metrics.fallback_controller_preflights, 0);
        assert_eq!(metrics.controller_lock_wait_nanos, 0);
        drop(controller_guard);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_ingress_progresses_during_controller_execution() {
        let (service, mempool, genesis_key, chain_id, _temp) = service_with_genesis();
        let controller_guard = service.controller.write().await;

        let mut admissions = Vec::new();
        for account in ["a1", "a2", "a3", "a4", "a5"] {
            let transaction = newaccount_tx(&genesis_key, &genesis_key, account, &chain_id);
            let admission_service = service.clone();
            admissions.push(tokio::spawn(async move {
                admission_service.admit_transaction(transaction).await
            }));
        }

        for admission in admissions {
            assert!(admission.await.unwrap().unwrap());
        }
        let metrics = service.admission_metrics();
        assert_eq!(metrics.state_preflights, 5);
        assert_eq!(metrics.fallback_controller_preflights, 0);
        assert_eq!(metrics.controller_lock_wait_nanos, 0);
        assert_eq!(mempool.read().await.has_transactions(), true);
        drop(controller_guard);
    }

    // This exercises the exact path called by Vm::build_block. The controller
    // writer is deliberately held before the producer starts: that makes the
    // test deterministic while proving the producer detaches the batch before
    // it waits for exclusive execution, and that ingress remains live during
    // the whole interval.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ingress_survives_actual_build_block_pipeline() {
        let (service, mempool, genesis_key, chain_id, _temp) = service_with_genesis();
        let selected = newaccount_tx(&genesis_key, &genesis_key, "alice", &chain_id);
        assert!(service.admit_transaction(selected.clone()).await.unwrap());

        let controller_guard = service.controller.write().await;
        let producer = service.clone();
        let build = tokio::spawn(async move { producer.build_block().await });
        wait_for_batch_detach(&mempool).await;

        let late_transactions: Vec<_> = ["b1", "b2", "b3", "b4", "b5"]
            .into_iter()
            .map(|account| newaccount_tx(&genesis_key, &genesis_key, account, &chain_id))
            .collect();
        let admissions: Vec<_> = late_transactions
            .iter()
            .cloned()
            .map(|transaction| {
                let service = service.clone();
                tokio::spawn(async move { service.admit_transaction(transaction).await })
            })
            .collect();
        for admission in admissions {
            assert!(admission.await.unwrap().unwrap());
        }
        let live_mempool = mempool.read().await;
        assert!(
            late_transactions
                .iter()
                .all(|transaction| live_mempool.contains(transaction.id())),
            "ingress must remain visible while production is waiting for the controller"
        );
        drop(live_mempool);
        let metrics = service.admission_metrics();
        assert_eq!(metrics.state_preflights, 6);
        assert_eq!(metrics.fallback_controller_preflights, 0);
        assert_eq!(metrics.controller_lock_wait_nanos, 0);

        drop(controller_guard);
        let block = build.await.unwrap().unwrap();
        assert_eq!(
            block.transactions.len(),
            1,
            "only the detached transaction is built"
        );
        let mempool = mempool.read().await;
        assert!(
            !mempool.contains(selected.id()),
            "a transaction selected for the built block must not be restored"
        );
        assert!(
            late_transactions
                .iter()
                .all(|transaction| mempool.contains(transaction.id())),
            "transactions admitted during production must remain queued for the next block"
        );
    }

    // Verify uses the same production batch handoff. Produce the block on an
    // independent node, then hold the verifier's controller lock long enough
    // to prove incoming RPCs do not wait on it and survive verification.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ingress_survives_actual_block_verify_pipeline() {
        let (producer, _producer_pool, producer_key, producer_chain_id, _producer_temp) =
            service_with_genesis();
        let included = newaccount_tx(&producer_key, &producer_key, "alice", &producer_chain_id);
        assert!(producer.admit_transaction(included).await.unwrap());
        let block = producer.build_block().await.unwrap();

        let (verifier, verifier_pool, verifier_key, verifier_chain_id, _verifier_temp) =
            service_with_genesis();
        let queued = newaccount_tx(&verifier_key, &verifier_key, "bob", &verifier_chain_id);
        assert!(verifier.admit_transaction(queued.clone()).await.unwrap());

        let controller_guard = verifier.controller.write().await;
        let verifying_service = verifier.clone();
        let verifying_block = block.clone();
        let verify =
            tokio::spawn(async move { verifying_service.verify_block(&verifying_block).await });
        wait_for_batch_detach(&verifier_pool).await;

        let late = newaccount_tx(&verifier_key, &verifier_key, "carol", &verifier_chain_id);
        assert!(verifier.admit_transaction(late.clone()).await.unwrap());
        assert!(verifier_pool.read().await.contains(late.id()));
        let metrics = verifier.admission_metrics();
        assert_eq!(metrics.state_preflights, 2);
        assert_eq!(metrics.fallback_controller_preflights, 0);
        assert_eq!(metrics.controller_lock_wait_nanos, 0);

        drop(controller_guard);
        verify.await.unwrap().unwrap();
        let mempool = verifier_pool.read().await;
        assert!(mempool.contains(queued.id()));
        assert!(mempool.contains(late.id()));
    }

    // Admission is intentionally optimistic, so multiple concurrent copies can
    // preflight. The final pool insertion remains the single deduplication
    // point, even while a producer has reservations outstanding.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_duplicate_ingress_is_exactly_once_during_build_handoff() {
        let (service, mempool, genesis_key, chain_id, _temp) = service_with_genesis();
        let selected = newaccount_tx(&genesis_key, &genesis_key, "alice", &chain_id);
        assert!(service.admit_transaction(selected).await.unwrap());

        let controller_guard = service.controller.write().await;
        let producer = service.clone();
        let build = tokio::spawn(async move { producer.build_block().await });
        wait_for_batch_detach(&mempool).await;

        let duplicate = newaccount_tx(&genesis_key, &genesis_key, "bob", &chain_id);
        let admissions: Vec<_> = (0..32)
            .map(|_| {
                let service = service.clone();
                let duplicate = duplicate.clone();
                tokio::spawn(async move { service.admit_transaction(duplicate).await })
            })
            .collect();
        let mut newly_admitted = 0;
        for admission in admissions {
            newly_admitted += admission.await.unwrap().unwrap() as usize;
        }
        assert_eq!(
            newly_admitted, 1,
            "exactly one concurrent duplicate may enter the pool"
        );
        assert!(mempool.read().await.contains(duplicate.id()));

        drop(controller_guard);
        build.await.unwrap().unwrap();
        assert!(mempool.read().await.contains(duplicate.id()));
    }
}
