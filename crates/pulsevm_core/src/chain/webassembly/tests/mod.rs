use std::{
    collections::BTreeSet,
    str::FromStr,
};

use pulsevm_crypto::{
    AuthorityPublicKey,
    Digest,
};
use pulsevm_database::{
    BlockTimestamp,
    Database,
    PermissionLevel,
    TimePointSec,
};
use pulsevm_serialization::Write;
use tempfile::TempDir;
use wasmer::{
    FunctionEnv,
    FunctionEnvMut,
    Instance,
    Memory,
    Module,
    RuntimeError,
    Store,
    WasmPtr,
    imports,
};
use wasmer_middlewares::metering::{
    MeteringPoints,
    get_remaining_points,
    set_remaining_points,
};

use super::{
    WasmContext,
    WasmRuntime,
};
use crate::{
    ACTIVE_NAME,
    PULSE_NAME,
    apply_context::ApplyContext,
    block::BlockStatus,
    chain::webassembly::*,
    controller::Controller,
    crypto::PrivateKey,
    id::Id,
    name::Name,
    protocol_features::ProtocolUpgradeSchedule,
    transaction::{
        Action,
        PackedTransaction,
        SignedTransaction,
        Transaction,
        TransactionHeader,
    },
    transaction_context::TransactionContext,
};

mod builtins;
mod context;
mod crypto_memory;
mod database;
mod privileged;

const END: u32 = 65_536;
const OUT: u32 = 513; // Deliberately unaligned: the host ABI permits this.

// This module is a child of wasm_runtime so the fixture can attach memory and
// the metered instance without adding test-only setters to the production API.
struct Host {
    store: Store,
    env: FunctionEnv<WasmContext>,
    memory: Memory,
    instance: Instance,
    db: Database,
    trx: TransactionContext,
    transaction: Transaction,
    action: Action,
    key: PrivateKey,
    _dir: TempDir,
}

impl Host {
    fn new(context_free: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = PrivateKey::new_k1_from_string("host-function-test-only").unwrap();
        let mut genesis: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../genesis.json"
        )))
        .unwrap();
        genesis["initial_key"] = serde_json::json!(key.get_public_key().to_string());
        let mut controller = Controller::new();
        controller
            .initialize(
                &Id::default(),
                &serde_json::to_vec(
                    &serde_json::json!({"producer_name": "pulse", "producer_key": key.to_string()}),
                )
                .unwrap(),
                &serde_json::to_vec(&genesis).unwrap(),
                dir.path().to_str().unwrap(),
            )
            .unwrap();
        let db = controller.database();
        let runtime = controller.get_wasm_runtime().clone();
        let action = Action::new(
            PULSE_NAME,
            Name::from_str("test").unwrap(),
            b"action-data".to_vec(),
            vec![PermissionLevel::new(
                PULSE_NAME.as_u64(),
                ACTIVE_NAME.as_u64(),
            )],
        );
        let mut cf_action = action.clone();
        cf_action.authorization.clear();
        let transaction = Transaction::new(
            TransactionHeader::new(
                TimePointSec::new(1_800_000_000),
                42,
                0x12345678,
                0u32.into(),
                0,
                0u32.into(),
            ),
            vec![cf_action.clone()],
            vec![action.clone()],
        );
        let packed = PackedTransaction::from_signed_transaction(SignedTransaction::new(
            transaction.clone(),
            BTreeSet::new(),
            vec![b"abcdef".to_vec().into(), Vec::new().into()],
        ))
        .unwrap();
        let time = BlockTimestamp::new(1234);
        let mut trx = TransactionContext::new(
            db.clone(),
            runtime.clone(),
            ProtocolUpgradeSchedule::default()
                .execution_context(1)
                .unwrap(),
            time.clone(),
            &Id::default(),
            BlockStatus::Verifying,
            packed,
            0,
        );
        trx.disable_subjective_deadline().unwrap();
        let current_action = if context_free {
            cf_action
        } else {
            action.clone()
        };
        let ordinal = trx
            .schedule_action(current_action.clone(), &PULSE_NAME, context_free, 0, 0)
            .unwrap();
        let mut apply = ApplyContext::new(
            db.clone(),
            runtime,
            trx.clone(),
            current_action.clone(),
            PULSE_NAME,
            ordinal,
            0,
            i64::MAX,
            context_free,
        )
        .unwrap();
        apply.exec_one().unwrap();

        let mut store = Store::new(WasmRuntime::deterministic_engine());
        let module = Module::new(
            &store,
            wat::parse_str("(module (memory (export \"memory\") 1))").unwrap(),
        )
        .unwrap();
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
        let memory = instance.exports.get_memory("memory").unwrap().clone();
        let mut context = WasmContext::new(PULSE_NAME, current_action, time, apply, db.clone());
        context.memory = Some(memory.clone());
        context.instance = Some(instance.clone());
        let env = FunctionEnv::new(&mut store, context);
        let mut host = Self {
            store,
            env,
            memory,
            instance,
            db,
            trx,
            transaction,
            action,
            key,
            _dir: dir,
        };
        host.budget(u64::MAX);
        host
    }

    fn env(&mut self) -> FunctionEnvMut<'_, WasmContext> {
        self.env.clone().into_mut(&mut self.store)
    }
    fn budget(&mut self, points: u64) {
        set_remaining_points(&mut self.store, &self.instance, points);
    }
    fn remaining(&mut self) -> u64 {
        match get_remaining_points(&mut self.store, &self.instance) {
            MeteringPoints::Remaining(points) => points,
            MeteringPoints::Exhausted => 0,
        }
    }
    fn write(&self, ptr: u32, bytes: &[u8]) {
        self.memory
            .view(&self.store)
            .write(ptr.into(), bytes)
            .unwrap();
    }
    fn read(&self, ptr: u32, size: usize) -> Vec<u8> {
        let mut bytes = vec![0; size];
        self.memory
            .view(&self.store)
            .read(ptr.into(), &mut bytes)
            .unwrap();
        bytes
    }
    fn read128(&self) -> u128 {
        u128::from_le_bytes(self.read(OUT, 16).try_into().unwrap())
    }
}

fn ptr<T>(offset: u32) -> WasmPtr<T> {
    WasmPtr::new(offset)
}
fn assert_error<T: std::fmt::Debug>(result: Result<T, RuntimeError>, text: &str) {
    let error = result.unwrap_err();
    assert!(
        error.message().contains(text),
        "expected {text:?}, got {error}"
    );
}
