use std::{
    collections::BTreeSet,
    str::FromStr,
    sync::Arc,
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
    controller::Controller,
    crypto::{
        PublicKey,
        Signature,
    },
    id::Id,
    mempool::Mempool,
    name::Name,
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
    network_manager: Arc<RwLock<NetworkManager>>,
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
            network_manager,
        }
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
    /// apply the same admission rules — a transaction only enters the mempool
    /// after it executes cleanly, and the newly-added flag lets the caller relay
    /// exactly once, which stops gossip from looping.
    pub async fn admit_transaction(
        &self,
        packed_trx: PackedTransaction,
    ) -> Result<bool, ChainError> {
        // Fast path: a transaction we already hold has been validated and
        // relayed once already, so skip the expensive execute-and-revert and
        // report it as not newly added. This is what absorbs re-gossip of a
        // transaction already in flight.
        if self.mempool.read().await.contains(packed_trx.id()) {
            return Ok(false);
        }

        // Execution is synchronous, with blocking database/wasm work and no await points,
        // so run it on the blocking pool and take the lock with blocking_write()
        // instead of holding the async lock on a runtime worker, which would
        // stall every other handler. push_transaction reverts the database, so
        // this is validation only — nothing is committed.
        let controller = self.controller.clone();
        let trx_for_exec = packed_trx.clone();
        tokio::task::spawn_blocking(move || {
            let mut controller = controller.blocking_write();
            let pending_block_timestamp = TimePoint::now().into();
            controller.push_transaction(
                &trx_for_exec,
                &pending_block_timestamp,
                &pulsevm_core::block::BlockStatus::Verifying,
            )
        })
        .await
        .map_err(|e| {
            ChainError::InternalError(format!("transaction execution task failed: {e}"))
        })??;

        let mut mempool = self.mempool.write().await;
        Ok(mempool.add_transaction(packed_trx))
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

    const GENESIS_KEY: &str = "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez";
    const CHAIN_ID: &str = "c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6";

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
        let service = RpcService::new(
            mempool.clone(),
            Arc::new(RwLock::new(controller)),
            Arc::new(RwLock::new(NetworkManager::new())),
        );
        (service, mempool, genesis_key, chain_id, temp)
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
}
