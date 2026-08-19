#[allow(dead_code, unused_imports)]
#[path = "../src/api/mod.rs"]
mod api;
#[allow(dead_code, unused_imports)]
#[path = "../src/chain/mod.rs"]
mod chain;

use std::{
    str::FromStr,
    sync::Arc,
};

use criterion::{
    Criterion,
    black_box,
    criterion_group,
    criterion_main,
};
use futures_util::future::join_all;
use pulsevm_core::{
    ACTIVE_NAME,
    PULSE_NAME,
    authority::{
        Authority,
        KeyWeight,
        PermissionLevel,
    },
    controller::Controller,
    crypto::PrivateKey,
    id::Id,
    mempool::Mempool,
    name::Name,
    pulse_contract::NewAccount,
    time::TimePointSec,
    transaction::{
        Action,
        PackedTransaction,
        Transaction,
        TransactionHeader,
    },
};
use pulsevm_serialization::Write;
use serde_json::json;
use tokio::sync::RwLock;

use chain::{
    NetworkManager,
    RpcService,
};

const GENESIS_KEY: &str = "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez";
const CHAIN_ID: &str = "c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6";

fn genesis_bytes(key: &PrivateKey) -> Vec<u8> {
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

fn newaccount_tx(key: &PrivateKey, account: &str, chain_id: &Id) -> PackedTransaction {
    let authority = Authority::new(
        1,
        vec![KeyWeight::new(key.get_public_key().into_k1(), 1)],
        vec![],
        vec![],
    );
    let transaction = Transaction::new(
        TransactionHeader::new(TimePointSec::maximum(), 0, 0, 0u32.into(), 0, 0u32.into()),
        vec![],
        vec![Action::new(
            PULSE_NAME,
            Name::from_str("newaccount").unwrap(),
            NewAccount {
                creator: PULSE_NAME,
                name: Name::from_str(account).unwrap(),
                owner: authority.clone(),
                active: authority,
            }
            .pack()
            .unwrap(),
            vec![PermissionLevel::new(
                PULSE_NAME.as_u64(),
                ACTIVE_NAME.as_u64(),
            )],
        )],
    )
    .sign(key, chain_id)
    .unwrap();
    PackedTransaction::from_signed_transaction(transaction).unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    let key = PrivateKey::from_str(GENESIS_KEY).unwrap();
    let chain_id = Id::from_str(CHAIN_ID).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut controller = Controller::new();
    controller
        .initialize(
            &chain_id,
            &json!({ "producer_name": "pulse", "producer_key": key.to_string() })
                .to_string()
                .into_bytes(),
            &genesis_bytes(&key),
            temp.path().to_str().unwrap(),
        )
        .unwrap();
    let admission_state = controller.mempool_admission_state();
    let controller = Arc::new(RwLock::new(controller));
    let mempool = Arc::new(RwLock::new(Mempool::new()));
    let service = RpcService::new(
        mempool.clone(),
        controller.clone(),
        Arc::new(RwLock::new(NetworkManager::new())),
    );
    service.set_admission_state(admission_state);
    let transactions = ["a1", "a2", "a3", "a4", "a5"]
        .into_iter()
        .map(|account| newaccount_tx(&key, account, &chain_id))
        .collect::<Vec<_>>();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    c.bench_function(
        "admission_contention/five_ingress_during_controller_write",
        |b| {
            b.to_async(&runtime).iter(|| {
                let service = service.clone();
                let controller = controller.clone();
                let mempool = mempool.clone();
                let transactions = transactions.clone();
                async move {
                    // This guard models block execution. The benchmark verifies that
                    // state-backed preflight does not queue behind it.
                    let controller_guard = controller.write().await;
                    let results = join_all(
                        transactions
                            .into_iter()
                            .map(|transaction| service.admit_transaction(transaction)),
                    )
                    .await;
                    drop(controller_guard);
                    for result in results {
                        black_box(result.unwrap());
                    }
                    *mempool.write().await = Mempool::new();
                    black_box(service.admission_metrics())
                }
            })
        },
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
