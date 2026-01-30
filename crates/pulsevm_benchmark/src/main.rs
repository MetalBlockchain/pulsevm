use std::{
    env::temp_dir,
    fs,
    hint::black_box,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use chrono::Utc;
use pulsevm_core::{
    ACTIVE_NAME, ChainError, PULSE_NAME, asset::{Asset, Symbol}, authority::{Authority, KeyWeight, PermissionLevel}, block::BlockStatus, controller::Controller, crypto::PrivateKey, id::Id, name::Name, pulse_contract::{NewAccount, SetAbi, SetCode}, transaction::{Action, PackedTransaction, Transaction, TransactionHeader}
};
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;
use pulsevm_time::TimePointSec;
use serde_json::json;
use spdlog::info;

#[tokio::main]
async fn main() {
    let private_key = PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez").unwrap();
    let mut controller = Controller::new();
    let genesis_bytes = generate_genesis(&private_key);
    let temp_path = get_temp_dir().to_str().unwrap().to_string();
    controller.initialize(&genesis_bytes.to_vec(), temp_path.as_str()).unwrap();
    let pending_block_timestamp = controller.last_accepted_block().timestamp().clone();
    let block_status = BlockStatus::Building;

    println!("Setting up initial accounts and contracts...");

    // Create 'pulse.token' account
    controller
        .execute_transaction(
            &create_account(&private_key, Name::from_str("pulse.token").unwrap(), controller.chain_id()).unwrap(),
            &pending_block_timestamp,
            &block_status,
        )
        .unwrap();

    println!("Created pulse.token account");

    // Create 'alice' account
    controller
        .execute_transaction(
            &create_account(&private_key, Name::from_str("alice").unwrap(), controller.chain_id()).unwrap(),
            &pending_block_timestamp,
            &block_status,
        )
        .unwrap();

    println!("Created alice account");

    // Create 'bob' account
    controller
        .execute_transaction(
            &create_account(&private_key, Name::from_str("bob").unwrap(), controller.chain_id()).unwrap(),
            &pending_block_timestamp,
            &block_status,
        )
        .unwrap();

    println!("Created bob account");

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let pulse_token_contract = fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
    let pulse_token_abi = fs::read(root.join(Path::new("reference_contracts/pulse_token.abi"))).unwrap();
    controller
        .execute_transaction(
            &set_code(
                &private_key,
                Name::from_str("pulse.token").unwrap(),
                pulse_token_contract,
                controller.chain_id(),
            )
            .unwrap(),
            &pending_block_timestamp,
            &block_status,
        )
        .unwrap();
    controller
        .execute_transaction(
            &set_abi(
                &private_key,
                Name::from_str("pulse.token").unwrap(),
                pulse_token_abi,
                controller.chain_id(),
            )
            .unwrap(),
            &pending_block_timestamp,
            &block_status,
        )
        .unwrap();

    controller
        .execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("pulse.token").unwrap(),
                Name::from_str("create").unwrap(),
                &Create {
                    issuer: Name::from_str("pulse.token").unwrap(),
                    max_supply: Asset::new(100000000, Symbol::from_str("4,EOS").unwrap()),
                },
                controller.chain_id(),
                vec![PermissionLevel::new(Name::from_str("pulse.token").unwrap().as_u64(), ACTIVE_NAME.as_u64())],
            )
            .unwrap(),
            &pending_block_timestamp,
            &block_status,
        )
        .unwrap();

    controller
        .execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("pulse.token").unwrap(),
                Name::from_str("issue").unwrap(),
                &Issue {
                    to: Name::from_str("pulse.token").unwrap(),
                    quantity: Asset {
                        amount: 100000000,
                        symbol: Symbol::from_str("4,EOS").unwrap(),
                    },
                    memo: "Initial transfer".to_string(),
                },
                controller.chain_id(),
                vec![PermissionLevel::new(Name::from_str("pulse.token").unwrap().as_u64(), ACTIVE_NAME.as_u64())],
            )
            .unwrap(),
            &pending_block_timestamp,
            &block_status,
        )
        .unwrap();

    controller
        .execute_transaction(
            &call_contract(
                &private_key,
                Name::from_str("pulse.token").unwrap(),
                Name::from_str("transfer").unwrap(),
                &Transfer {
                    from: Name::from_str("pulse.token").unwrap(),
                    to: Name::from_str("alice").unwrap(),
                    quantity: Asset {
                        amount: 100000000,
                        symbol: Symbol::from_str("4,EOS").unwrap(),
                    },
                    memo: "Initial transfer".to_string(),
                },
                controller.chain_id(),
                vec![PermissionLevel::new(Name::from_str("pulse.token").unwrap().as_u64(), ACTIVE_NAME.as_u64())],
            )
            .unwrap(),
            &pending_block_timestamp,
            &block_status,
        )
        .unwrap();

    for _i in 0..50 {
        controller
            .execute_transaction(
                &call_contract(
                    &private_key,
                    Name::from_str("pulse.token").unwrap(),
                    Name::from_str("transfer").unwrap(),
                    &Transfer {
                        from: Name::from_str("alice").unwrap(),
                        to: Name::from_str("bob").unwrap(),
                        quantity: Asset {
                            amount: 5000,
                            symbol: Symbol::from_str("4,EOS").unwrap(),
                        },
                        memo: "Initial transfer".to_string(),
                    },
                    controller.chain_id(),
                    vec![PermissionLevel::new(Name::from_str("alice").unwrap().as_u64(), ACTIVE_NAME.as_u64())],
                )
                .unwrap(),
                &pending_block_timestamp,
                &block_status,
            )
            .unwrap();
    }
}

fn create_account(private_key: &PrivateKey, account: Name, chain_id: Id) -> Result<PackedTransaction, ChainError> {
    let authority = Authority::new(1, vec![KeyWeight::new(private_key.get_public_key().inner().clone(), 1)], vec![], vec![]);
    let trx = Transaction::new(
        TransactionHeader::new(TimePointSec::new(0), 0, 0, 0u32.into(), 0, 0u32.into()),
        vec![],
        vec![Action::new(
            Name::from_str("pulse")?,
            Name::from_str("newaccount")?,
            NewAccount {
                creator: Name::from_str("pulse")?,
                name: account,
                owner: authority.clone(),
                active: authority.clone(),
            }
            .pack()
            .unwrap(),
            vec![PermissionLevel::new(PULSE_NAME.as_u64(), ACTIVE_NAME.as_u64())],
        )],
    );
    let trx = trx.sign(&private_key, &chain_id)?;
    let packed_trx = PackedTransaction::from_signed_transaction(trx)?;
    Ok(packed_trx)
}

fn set_code(private_key: &PrivateKey, account: Name, wasm_bytes: Vec<u8>, chain_id: Id) -> Result<PackedTransaction, ChainError> {
    let trx = Transaction::new(
        TransactionHeader::new(TimePointSec::new(0), 0, 0, 0u32.into(), 0, 0u32.into()),
        vec![],
        vec![Action::new(
            Name::from_str("pulse").unwrap(),
            Name::from_str("setcode").unwrap(),
            SetCode {
                account,
                vm_type: 0,
                vm_version: 0,
                code: Arc::new(wasm_bytes.into()),
            }
            .pack()
            .unwrap(),
            vec![PermissionLevel::new(account.as_u64(), ACTIVE_NAME.as_u64())],
        )],
    )
    .sign(&private_key, &chain_id)?;
    let packed_trx = PackedTransaction::from_signed_transaction(trx)?;
    Ok(packed_trx)
}

fn set_abi(private_key: &PrivateKey, account: Name, abi_bytes: Vec<u8>, chain_id: Id) -> Result<PackedTransaction, ChainError> {
    let trx = Transaction::new(
        TransactionHeader::new(TimePointSec::new(0), 0, 0, 0u32.into(), 0, 0u32.into()),
        vec![],
        vec![Action::new(
            Name::from_str("pulse").unwrap(),
            Name::from_str("setabi").unwrap(),
            SetAbi {
                account,
                abi: Arc::new(abi_bytes.into()),
            }
            .pack()
            .unwrap(),
            vec![PermissionLevel::new(account.as_u64(), ACTIVE_NAME.as_u64())],
        )],
    )
    .sign(&private_key, &chain_id)?;
    let packed_trx = PackedTransaction::from_signed_transaction(trx)?;
    Ok(packed_trx)
}

fn call_contract<T: Write>(
    private_key: &PrivateKey,
    account: Name,
    action: Name,
    action_data: &T,
    chain_id: Id,
    permissions: Vec<PermissionLevel>,
) -> Result<PackedTransaction, ChainError> {
    let trx = Transaction::new(
        TransactionHeader::new(TimePointSec::new(0), 0, 0, 0u32.into(), 0, 0u32.into()),
        vec![],
        vec![Action::new(account, action, action_data.pack().unwrap(), permissions)],
    )
    .sign(&private_key, &chain_id)?;
    let packed_trx = PackedTransaction::from_signed_transaction(trx)?;
    Ok(packed_trx)
}

fn get_temp_dir() -> PathBuf {
    let temp_dir_name = format!("db_{}.pulsevm", Utc::now().format("%Y%m%d%H%M%S"));
    let res = temp_dir().join(Path::new(&temp_dir_name));
    info!("using temporary directory: {}", res.display());
    res
}

fn generate_genesis(private_key: &PrivateKey) -> Vec<u8> {
    let genesis = json!(
    {
        "initial_timestamp": "2023-01-01T00:00:00",
        "initial_key": "PUB_K1_8XeW7H2JhKFP8Wjw31cv4j4Bpw4in8MVMrtmfUunJV4gSVBzqZ",
        "initial_configuration": {
            "max_block_net_usage": 1048576,
            "target_block_net_usage_pct": 1000,
            "max_transaction_net_usage": 524288,
            "base_per_transaction_net_usage": 12,
            "net_usage_leeway": 500,
            "context_free_discount_net_usage_num": 20,
            "context_free_discount_net_usage_den": 100,
            "max_block_cpu_usage": 200000,
            "target_block_cpu_usage_pct": 2500,
            "max_transaction_cpu_usage": 150000,
            "min_transaction_cpu_usage": 100,
            "max_transaction_lifetime": 3600,
            "max_inline_action_size": 4096,
            "max_inline_action_depth": 6,
            "max_authority_depth": 6,
            "max_action_return_value_size": 256
        }
    });
    genesis.to_string().into_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
struct Issue {
    to: Name,
    quantity: Asset,
    memo: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
struct Transfer {
    from: Name,
    to: Name,
    quantity: Asset,
    memo: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
struct Create {
    issuer: Name,
    max_supply: Asset,
}
