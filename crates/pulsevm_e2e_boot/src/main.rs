//! Boots a running PulseVM chain to the point where token transfers work, and
//! reports what happened as JSON on stdout so a test harness can assert on it.
//!
//! Signing happens here, with a private key passed in. The `pulse` CLI delegates
//! signing to keosd, which would mean running and unlocking a wallet daemon
//! inside every test; local signing is what the unit tests already do.
//!
//! Usage:
//!   pulsevm-e2e-boot --url <chain-rpc-url> --private-key <PVT_K1_...> \
//!                    --token-wasm <path/to/pulse_token.wasm> \
//!                    --token-abi <path/to/pulse_token.abi>

use std::{
    str::FromStr,
    sync::Arc,
    time::{
        Duration,
        Instant,
    },
};

use anyhow::{
    Context,
    Result,
    bail,
};
use pulsevm_api_client::PulseVmClient;
use pulsevm_core::{
    ACTIVE_NAME,
    PULSE_NAME,
    abi::AbiDefinition,
    asset::Asset,
    authority::{
        Authority,
        KeyWeight,
        PermissionLevel,
    },
    config::{
        NEWACCOUNT_NAME,
        SETABI_NAME,
        SETCODE_NAME,
    },
    crypto::{
        PrivateKey,
        PublicKey,
    },
    id::Id,
    name::Name,
    producer_schedule::ProducerKey,
    pulse_contract::{
        NewAccount,
        SetAbi,
        SetCode,
    },
    time::TimePointSec,
    transaction::{
        Action,
        PackedTransaction,
        Transaction,
    },
};
use pulsevm_crypto::Bytes;
use pulsevm_name_macro::name;
use pulsevm_proc_macros::{
    NumBytes,
    Read,
    Write,
};
use pulsevm_serialization::Write as _;
use tokio::time::sleep;

/// `create` action of the token contract: declares an asset and its issuer.
#[derive(Debug, Clone, Read, Write, NumBytes)]
struct CreateToken {
    issuer: Name,
    maximum_supply: Asset,
}

/// `issue` action: mints into the issuer's balance.
#[derive(Debug, Clone, Read, Write, NumBytes)]
struct IssueToken {
    to: Name,
    quantity: Asset,
    memo: String,
}

/// `transfer` action: moves a balance between accounts.
#[derive(Debug, Clone, Read, Write, NumBytes)]
struct TransferToken {
    from: Name,
    to: Name,
    quantity: Asset,
    memo: String,
}

struct Args {
    url: String,
    private_key: String,
    token_wasm: String,
    token_abi: String,
}

fn parse_args() -> Result<Args> {
    let (mut url, mut private_key, mut token_wasm, mut token_abi) = (None, None, None, None);
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut take = || argv.next().context(format!("{flag} requires a value"));
        match flag.as_str() {
            "--url" => url = Some(take()?),
            "--private-key" => private_key = Some(take()?),
            "--token-wasm" => token_wasm = Some(take()?),
            "--token-abi" => token_abi = Some(take()?),
            other => bail!("unknown argument: {other}"),
        }
    }
    Ok(Args {
        url: url.context("--url is required")?,
        private_key: private_key.context("--private-key is required")?,
        token_wasm: token_wasm.context("--token-wasm is required")?,
        token_abi: token_abi.context("--token-abi is required")?,
    })
}

/// How long to wait for a submitted transaction to land in a block.
const INCLUSION_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Signs `actions` as one transaction, submits it, and waits for it to be
/// included in a block before returning the tx id.
///
/// Mirrors pulse::utils::push_actions but signs with `key` rather than asking
/// keosd. PulseVM transactions carry no TAPOS reference, only an expiration.
///
/// The wait is essential rather than defensive: `issue_tx` returns once the
/// transaction is *accepted into the mempool*, which PulseVM drains on a 500ms
/// timer. Without waiting, a boot sequence pushes `setcode` against an account
/// whose creating transaction has not executed yet, and the chain rejects it
/// with "permission not found".
async fn push(
    client: &PulseVmClient,
    chain_id: &Id,
    key: &PrivateKey,
    actions: Vec<Action>,
) -> Result<String> {
    let before = client
        .get_info()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .head_block_num;

    let mut txn = Transaction::default();
    txn.header.expiration = TimePointSec::now() + 300;
    txn.actions = actions;

    let signed = txn
        .sign(key, chain_id)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let packed =
        PackedTransaction::from_signed_transaction(signed).map_err(|e| anyhow::anyhow!("{e}"))?;
    let response = client
        .issue_tx(&packed)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let deadline = Instant::now() + INCLUSION_TIMEOUT;
    loop {
        let head = client
            .get_info()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .head_block_num;
        if head > before {
            break;
        }
        if Instant::now() >= deadline {
            bail!(
                "transaction {} was not included within {:?} (head block stuck at {})",
                response.tx_id,
                INCLUSION_TIMEOUT,
                head
            );
        }
        sleep(POLL_INTERVAL).await;
    }

    Ok(response.tx_id.to_string())
}

/// Builds a `newaccount` action granting `key` both owner and active authority.
fn new_account(creator: Name, account: Name, key: &PublicKey) -> Result<Action> {
    let authority = |k: &PublicKey| Authority {
        threshold: 1,
        keys: vec![KeyWeight {
            key: k.clone().into_k1(),
            weight: 1,
        }],
        accounts: vec![],
        waits: vec![],
    };

    Ok(Action {
        account: PULSE_NAME,
        name: NEWACCOUNT_NAME,
        authorization: vec![PermissionLevel {
            actor: creator.into(),
            permission: ACTIVE_NAME.into(),
        }],
        data: NewAccount {
            creator: creator.into(),
            name: account.into(),
            owner: authority(key),
            active: authority(key),
        }
        .try_into()
        .map_err(|e| anyhow::anyhow!("packing newaccount: {e}"))?,
    })
}

/// A minimal privileged contract that forwards the `setprods` action's data (a
/// packed vector<producer_key>) to the set_proposed_producers host function. It
/// guards on the action name, so onblock and native actions dispatched to the
/// account it lives on are ignored — making it safe to deploy onto `pulse`, which
/// is privileged at genesis (set_proposed_producers requires privilege). Built
/// from WAT at runtime so no CDT toolchain is needed for the fixture.
fn setprods_contract_wasm() -> Result<Vec<u8>> {
    let setprods = Name::from_str("setprods")
        .map_err(|e| anyhow::anyhow!("encoding setprods name: {e}"))?
        .as_u64() as i64;
    let wat = format!(
        r#"
        (module
          (import "env" "action_data_size" (func $ads (result i32)))
          (import "env" "read_action_data" (func $read (param i32 i32) (result i32)))
          (import "env" "set_proposed_producers" (func $spp (param i32 i32) (result i64)))
          (memory 1)
          (export "memory" (memory 0))
          (func (export "apply") (param $receiver i64) (param $code i64) (param $action i64)
            (local $len i32)
            (if (i64.eq (local.get $action) (i64.const {setprods}))
              (then
                (local.set $len (call $ads))
                (drop (call $read (i32.const 0) (local.get $len)))
                (drop (call $spp (i32.const 0) (local.get $len)))))))
        "#
    );
    wat::parse_str(&wat).map_err(|e| anyhow::anyhow!("compiling setprods contract: {e}"))
}

/// Builds an action on a deployed contract, packing `data` to binary here so no
/// ABI is needed on the client side.
fn contract_action<T: pulsevm_serialization::Write + pulsevm_serialization::NumBytes>(
    contract: Name,
    action: Name,
    actor: Name,
    data: T,
) -> Result<Action> {
    Ok(Action {
        account: contract.into(),
        name: action.into(),
        authorization: vec![PermissionLevel {
            actor: actor.into(),
            permission: ACTIVE_NAME.into(),
        }],
        data: Arc::from(
            data.pack()
                .map_err(|e| anyhow::anyhow!("packing action data: {e}"))?,
        ),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

    let key = PrivateKey::from_str(&args.private_key)
        .map_err(|e| anyhow::anyhow!("parsing private key: {e}"))?;
    let public_key = key.get_public_key();

    let client = PulseVmClient::new(&args.url);
    let info = client
        .get_info()
        .await
        .map_err(|e| anyhow::anyhow!("get_info: {e}"))?;
    let chain_id =
        Id::from_str(&info.chain_id).map_err(|e| anyhow::anyhow!("parsing chain id: {e}"))?;

    let system: Name = PULSE_NAME.into();
    let token: Name = name!("pulse.token").into();
    let alice: Name = name!("alice").into();
    let bob: Name = name!("bob").into();

    let mut steps = Vec::new();

    // The token contract needs an account to live in, and two ordinary accounts
    // give the transfer a sender and a recipient.
    for account in [token, alice, bob] {
        let tx = push(
            &client,
            &chain_id,
            &key,
            vec![new_account(system, account, &public_key)?],
        )
        .await
        .with_context(|| format!("creating account {account}"))?;
        steps.push(
            serde_json::json!({ "step": "newaccount", "account": account.to_string(), "tx": tx }),
        );
    }

    // Only the code is deployed. The ABI exists to let clients translate JSON to
    // binary; this fixture packs binary directly, and the contract does not need
    // an ABI to execute.
    let wasm =
        std::fs::read(&args.token_wasm).with_context(|| format!("reading {}", args.token_wasm))?;
    let tx = push(
        &client,
        &chain_id,
        &key,
        vec![Action {
            account: PULSE_NAME,
            name: SETCODE_NAME,
            authorization: vec![PermissionLevel {
                actor: token.into(),
                permission: ACTIVE_NAME.into(),
            }],
            data: SetCode {
                account: token.into(),
                vm_type: 0,
                vm_version: 0,
                code: Arc::new(Bytes::new(wasm)),
            }
            .try_into()
            .map_err(|e| anyhow::anyhow!("packing setcode: {e}"))?,
        }],
    )
    .await
    .context("deploying token contract")?;
    steps.push(serde_json::json!({ "step": "setcode", "account": token.to_string(), "tx": tx }));

    // The ABI is not needed to execute actions -- this fixture packs action data
    // itself -- but it is needed to *read* state: getCurrencyBalance decodes the
    // contract's `accounts` table through the ABI and fails with "Table accounts
    // is not specified in the ABI" without it.
    let abi_json =
        std::fs::read(&args.token_abi).with_context(|| format!("reading {}", args.token_abi))?;
    let abi: AbiDefinition =
        serde_json::from_slice(&abi_json).context("parsing token ABI as JSON")?;
    let abi_bytes = Bytes::new(
        abi.pack()
            .map_err(|e| anyhow::anyhow!("packing ABI: {e}"))?,
    );
    let tx = push(
        &client,
        &chain_id,
        &key,
        vec![Action {
            account: PULSE_NAME,
            name: SETABI_NAME,
            authorization: vec![PermissionLevel {
                actor: token.into(),
                permission: ACTIVE_NAME.into(),
            }],
            data: SetAbi {
                account: token.into(),
                abi: Arc::new(abi_bytes),
            }
            .try_into()
            .map_err(|e| anyhow::anyhow!("packing setabi: {e}"))?,
        }],
    )
    .await
    .context("deploying token ABI")?;
    steps.push(serde_json::json!({ "step": "setabi", "account": token.to_string(), "tx": tx }));

    let max_supply = Asset::from_str("1000000000.0000 PULSE")
        .map_err(|e| anyhow::anyhow!("parsing maximum supply: {e}"))?;
    let issued = Asset::from_str("1000.0000 PULSE")
        .map_err(|e| anyhow::anyhow!("parsing issue quantity: {e}"))?;
    let sent =
        Asset::from_str("250.0000 PULSE").map_err(|e| anyhow::anyhow!("parsing transfer: {e}"))?;

    let tx = push(
        &client,
        &chain_id,
        &key,
        vec![contract_action(
            token,
            name!("create").into(),
            token,
            CreateToken {
                issuer: token,
                maximum_supply: max_supply,
            },
        )?],
    )
    .await
    .context("creating token")?;
    steps.push(serde_json::json!({ "step": "create", "tx": tx }));

    // The token contract only permits issuing to the issuer itself, so supply
    // reaches an ordinary account via a subsequent transfer rather than directly.
    let tx = push(
        &client,
        &chain_id,
        &key,
        vec![contract_action(
            token,
            name!("issue").into(),
            token,
            IssueToken {
                to: token,
                quantity: issued.clone(),
                memo: "e2e issue".to_string(),
            },
        )?],
    )
    .await
    .context("issuing tokens")?;
    steps.push(serde_json::json!({ "step": "issue", "to": token.to_string(), "quantity": issued.to_string(), "tx": tx }));

    let funded =
        Asset::from_str("500.0000 PULSE").map_err(|e| anyhow::anyhow!("parsing funding: {e}"))?;
    let tx = push(
        &client,
        &chain_id,
        &key,
        vec![contract_action(
            token,
            name!("transfer").into(),
            token,
            TransferToken {
                from: token,
                to: alice,
                quantity: funded.clone(),
                memo: "e2e funding".to_string(),
            },
        )?],
    )
    .await
    .context("funding alice")?;
    steps.push(serde_json::json!({ "step": "fund", "from": token.to_string(), "to": alice.to_string(), "quantity": funded.to_string(), "tx": tx }));

    let tx = push(
        &client,
        &chain_id,
        &key,
        vec![contract_action(
            token,
            name!("transfer").into(),
            alice,
            TransferToken {
                from: alice,
                to: bob,
                quantity: sent.clone(),
                memo: "e2e transfer".to_string(),
            },
        )?],
    )
    .await
    .context("transferring tokens")?;
    steps.push(serde_json::json!({ "step": "transfer", "from": alice.to_string(), "to": bob.to_string(), "quantity": sent.to_string(), "tx": tx }));

    // Producer election, end to end. Create a second producer account, deploy the
    // setprods forwarder onto `pulse`, then propose a schedule that adds the new
    // producer. The proposal keeps `pulse` (with the node's genesis key) so the
    // single node can keep producing while the change activates on the next
    // accepted block; getProducers then reflects the new set.
    let producerb: Name = name!("producerb").into();
    let tx = push(
        &client,
        &chain_id,
        &key,
        vec![new_account(system, producerb, &public_key)?],
    )
    .await
    .context("creating producerb")?;
    steps.push(
        serde_json::json!({ "step": "newaccount", "account": producerb.to_string(), "tx": tx }),
    );

    let tx = push(
        &client,
        &chain_id,
        &key,
        vec![Action {
            account: PULSE_NAME,
            name: SETCODE_NAME,
            authorization: vec![PermissionLevel {
                actor: system.into(),
                permission: ACTIVE_NAME.into(),
            }],
            data: SetCode {
                account: system.into(),
                vm_type: 0,
                vm_version: 0,
                code: Arc::new(Bytes::new(setprods_contract_wasm()?)),
            }
            .try_into()
            .map_err(|e| anyhow::anyhow!("packing setcode: {e}"))?,
        }],
    )
    .await
    .context("deploying setprods contract to pulse")?;
    steps.push(serde_json::json!({ "step": "setcode", "account": system.to_string(), "tx": tx }));

    let proposed = vec![
        ProducerKey {
            producer_name: system,
            block_signing_key: public_key.clone(),
        },
        ProducerKey {
            producer_name: producerb,
            block_signing_key: public_key.clone(),
        },
    ];
    let tx = push(
        &client,
        &chain_id,
        &key,
        vec![contract_action(
            system,
            name!("setprods").into(),
            system,
            proposed.clone(),
        )?],
    )
    .await
    .context("submitting setprods")?;
    steps.push(serde_json::json!({
        "step": "setprods",
        "tx": tx,
        "proposed": proposed.iter().map(|p| p.producer_name.to_string()).collect::<Vec<_>>(),
    }));

    println!(
        "{}",
        serde_json::json!({
            "chain_id": info.chain_id,
            "token_contract": token.to_string(),
            "steps": steps,
        })
    );
    Ok(())
}
