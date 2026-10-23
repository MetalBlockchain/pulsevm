//! Build signed rehearsal transactions with the audited packing and
//! signing paths, and print the `pulsevm.issueTx` JSON body.
//! Usage:
//!   make_probe_tx newaccount <chain-id> <wif> <ref-num> <ref-prefix> <exp> <name>
//! [auth-pubkey-hex]   make_probe_tx updateauth <chain-id> <wif> <ref-num> <ref-prefix> <exp>
//!     <account> <permission> <parent> <auth-pubkey-compressed-hex>
//!   make_probe_tx newkey
//!   make_probe_tx pubkey <wif>
//!   make_probe_tx setcode <chain-id> <wif> <ref-num> <ref-prefix> <exp> <account> <wasm-file>
//!   make_probe_tx setabi <chain-id> <wif> <ref-num> <ref-prefix> <exp> <account> <abi-json-file>
//!   make_probe_tx raw <chain-id> <wif> <ref-num> <ref-prefix> <exp> <code>
//!     <action> <auth-account> <hexdata>
//!   make_probe_tx cseed <chain-id> <wif> <ref-num> <ref-prefix> <exp> <contract>
//!     <auth-account> <producer> <votes-f64-hex> <key33-hex> <active-0/1>
//!   make_probe_tx cvote <chain-id> <relay-wif> <ref-num> <ref-prefix> <exp>
//!     <relay-account> <contract> <producer> <bp-wif> <height> <chain-id-hex> <members-json-file>
//! `newkey` prints a fresh `<wif> <compressed-pubkey-hex>` pair for traffic
//! authorities. `updateauth` signs with <wif> (which must satisfy the current
//! authority) and installs the given key. `newaccount` authorizes with the
//! signing key unless [auth-pubkey-hex] overrides the installed authority.
//! The `setcode`/`setabi`/`raw`/`cseed` modes deploy contracts and push
//! arbitrary actions to a Leap node (via `leap_send`); `cvote` builds a
//! cutover vote whose signature binds the A-Chain declaration digest, so one
//! BP signature serves both the on-chain tally and the off-chain pair.
use std::str::FromStr;

use pulsevm_core::{
    abi::AbiDefinition,
    authority::{
        Authority,
        KeyWeight,
        PermissionLevel,
    },
    crypto::PrivateKey,
    id::Id,
    name::Name,
    pulse_contract::{
        NewAccount,
        UpdateAuth,
    },
    transaction::{
        Action,
        PackedTransaction,
        Transaction,
        TransactionHeader,
    },
};
use pulsevm_database::TimePointSec;
use pulsevm_serialization::Write as _;

fn key_authority(public_key: pulsevm_core::crypto::PublicKey) -> Authority {
    Authority::new(
        1,
        vec![KeyWeight::new(public_key.into_k1(), 1)],
        vec![],
        vec![],
    )
}

fn authority_from_hex(raw_hex: &str) -> Authority {
    let raw = hex::decode(raw_hex).expect("bad pubkey hex");
    assert_eq!(raw.len(), 33, "compressed pubkey must be 33 bytes");
    let mut packed_key = [0u8; 34];
    packed_key[1..].copy_from_slice(&raw);
    let key = pulsevm_crypto::K1PublicKey::from_packed(&packed_key).expect("bad pubkey bytes");
    Authority::new(1, vec![KeyWeight::new(key, 1)], vec![], vec![])
}

fn issue_body(trx: pulsevm_core::transaction::SignedTransaction) -> serde_json::Value {
    let signatures: Vec<String> = trx.signatures().iter().map(|s| s.to_string()).collect();
    let packed = PackedTransaction::from_signed_transaction(trx).expect("packing works");
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "pulsevm.issueTx",
        "params": {
            "signatures": signatures,
            "compression": 0,
            "packed_context_free_data": "",
            "packed_trx": hex::encode(packed.packed_trx_bytes()),
        }
    })
}

fn header(ref_num: u16, ref_prefix: u32, expiration: u32) -> TransactionHeader {
    TransactionHeader::new(
        TimePointSec::new(expiration),
        ref_num,
        ref_prefix,
        0u32.into(),
        0,
        0u32.into(),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(
        args.len() >= 2,
        "usage: make_probe_tx <newaccount|updateauth|newkey|pubkey|setcode|setabi|raw|cseed|cvote> ..."
    );
    match args[1].as_str() {
        "pubkey" => {
            assert_eq!(args.len(), 3, "usage: make_probe_tx pubkey <wif>");
            let key = PrivateKey::from_str(&args[2]).expect("bad wif");
            println!("{}", hex::encode(key.get_public_key().k1().compressed()));
            return;
        }
        "newkey" => {
            let fresh = pulsevm_crypto::K1PrivateKey::random();
            let compressed = fresh.public_key().to_packed();
            println!("{} {}", fresh.to_string(), hex::encode(&compressed[1..]));
            return;
        }
        "newaccount" => {
            assert!(
                args.len() == 8 || args.len() == 9,
                "usage: make_probe_tx newaccount <chain-id> <wif> <ref-num> <ref-prefix> <exp> <name> [auth-pubkey-hex]"
            );
            let chain_id = Id::from_str(&args[2]).expect("bad chain id");
            let key = PrivateKey::from_str(&args[3]).expect("bad wif");
            let header = header(
                args[4].parse().expect("bad ref num"),
                args[5].parse().expect("bad ref prefix"),
                args[6].parse().expect("bad expiration"),
            );
            let new_account = Name::from_str(&args[7]).expect("bad account name");

            let active = Name::from_str("active").expect("active is a valid name");
            let eosio = Name::from_str("eosio").expect("eosio is a valid name");
            let action_name = Name::from_str("newaccount").expect("newaccount is a valid name");
            let auth = match args.get(8) {
                Some(hex) => authority_from_hex(hex),
                None => key_authority(key.get_public_key()),
            };
            let trx = Transaction::new(
                header,
                vec![],
                vec![Action::new(
                    eosio,
                    action_name,
                    NewAccount {
                        creator: eosio,
                        name: new_account,
                        owner: auth.clone(),
                        active: auth,
                    }
                    .pack()
                    .expect("newaccount packs"),
                    vec![PermissionLevel::new(eosio.as_u64(), active.as_u64())],
                )],
            )
            .sign(&key, &chain_id)
            .expect("signing works");
            println!("{}", issue_body(trx));
        }
        "updateauth" => {
            assert_eq!(
                args.len(),
                11,
                "usage: make_probe_tx updateauth <chain-id> <wif> <ref-num> <ref-prefix> <exp> <account> <permission> <parent> <auth-pubkey-hex>"
            );
            let chain_id = Id::from_str(&args[2]).expect("bad chain id");
            let key = PrivateKey::from_str(&args[3]).expect("bad wif");
            let header = header(
                args[4].parse().expect("bad ref num"),
                args[5].parse().expect("bad ref prefix"),
                args[6].parse().expect("bad expiration"),
            );
            let account = Name::from_str(&args[7]).expect("bad account name");
            let permission = Name::from_str(&args[8]).expect("bad permission name");
            let parent = Name::from_str(&args[9]).expect("bad parent name");
            let installed = authority_from_hex(&args[10]);
            let eosio = Name::from_str("eosio").expect("eosio is a valid name");
            let action_name = Name::from_str("updateauth").expect("updateauth is a valid name");
            let trx = Transaction::new(
                header,
                vec![],
                vec![Action::new(
                    eosio,
                    action_name,
                    UpdateAuth {
                        account,
                        permission,
                        parent,
                        auth: installed,
                    }
                    .pack()
                    .expect("updateauth packs"),
                    vec![PermissionLevel::new(account.as_u64(), permission.as_u64())],
                )],
            )
            .sign(&key, &chain_id)
            .expect("signing works");
            println!("{}", issue_body(trx));
        }
        "setcode" => {
            let (chain_id, key, ref_num, ref_prefix, exp, account, wasm) = setcode_args();
            let mut data = Name::from_str(&account)
                .expect("bad account")
                .as_u64()
                .to_le_bytes()
                .to_vec();
            varuint(0, &mut data);
            varuint(0, &mut data);
            varuint(wasm.len() as u64, &mut data);
            data.extend_from_slice(&wasm);
            build_action(
                &chain_id, &key, ref_num, ref_prefix, exp, "eosio", "setcode", &account, data,
            );
        }
        "setabi" => {
            let (chain_id, key, ref_num, ref_prefix, exp, account, abi_json) = setcode_args();
            // Leap `setabi` carries the packed binary `abi_def`, not the JSON
            // text: `cleos set abi` packs client-side via `abi_json_to_bin`.
            // Submitting raw JSON executes but leaves nothing `get_abi` or
            // `get_table_rows` can unpack, so pack here for cleos parity.
            let abi: AbiDefinition =
                serde_json::from_slice(&abi_json).expect("ABI file must be JSON");
            let packed = abi.pack().expect("ABI packs");
            let mut data = Name::from_str(&account)
                .expect("bad account")
                .as_u64()
                .to_le_bytes()
                .to_vec();
            varuint(packed.len() as u64, &mut data);
            data.extend_from_slice(&packed);
            build_action(
                &chain_id, &key, ref_num, ref_prefix, exp, "eosio", "setabi", &account, data,
            );
        }
        "raw" => {
            let args: Vec<String> = std::env::args().collect();
            assert_eq!(
                args.len(),
                11,
                "usage: make_probe_tx raw <chain-id> <wif> <ref-num> <ref-prefix> <exp> <code> <action> <auth-account> <hexdata>"
            );
            let chain_id = Id::from_str(&args[2]).expect("bad chain id");
            let key = PrivateKey::from_str(&args[3]).expect("bad wif");
            let data = hex::decode(&args[10]).expect("bad hexdata");
            build_action(
                &chain_id,
                &key,
                args[4].parse().expect("bad ref num"),
                args[5].parse().expect("bad ref prefix"),
                args[6].parse().expect("bad expiration"),
                &args[7],
                &args[8],
                &args[9],
                data,
            );
        }
        "cseed" => {
            let args: Vec<String> = std::env::args().collect();
            assert_eq!(
                args.len(),
                13,
                "usage: make_probe_tx cseed <chain-id> <wif> <ref-num> <ref-prefix> <exp> <contract> <auth-account> <producer> <votes-f64-hex> <key33-hex> <active-0/1>"
            );
            let chain_id = Id::from_str(&args[2]).expect("bad chain id");
            let key = PrivateKey::from_str(&args[3]).expect("bad wif");
            let mut data = Name::from_str(&args[9])
                .expect("bad producer")
                .as_u64()
                .to_le_bytes()
                .to_vec();
            // Votes arrive as 8 raw little-endian double bytes in hex (see
            // f64hex in the fixture script): decode, never reinterpret.
            let votes_bytes = hex::decode(&args[10]).expect("bad f64 hex");
            assert_eq!(votes_bytes.len(), 8, "votes must be 8 double bytes");
            data.extend_from_slice(&votes_bytes);
            let raw_key = hex::decode(&args[11]).expect("bad key hex");
            assert_eq!(raw_key.len(), 33, "key must be 33 compressed bytes");
            varuint(raw_key.len() as u64, &mut data);
            data.extend_from_slice(&raw_key);
            data.push(args[12].parse::<u8>().expect("bad active"));
            build_action(
                &chain_id,
                &key,
                args[4].parse().expect("bad ref num"),
                args[5].parse().expect("bad ref prefix"),
                args[6].parse().expect("bad expiration"),
                &args[7],
                "setprod",
                &args[8].clone(),
                data,
            );
        }
        "cvote" => {
            let args: Vec<String> = std::env::args().collect();
            assert_eq!(
                args.len(),
                14,
                "usage: make_probe_tx cvote <chain-id> <relay-wif> <ref-num> <ref-prefix> <exp> <relay-account> <contract> <producer> <bp-wif> <height> <chain-id-hex> <members-json-file>"
            );
            let chain_id = Id::from_str(&args[2]).expect("bad chain id");
            let relay = PrivateKey::from_str(&args[3]).expect("bad relay wif");
            let relay_account = args[7].clone();
            let contract = args[8].clone();
            let producer = args[9].clone();
            let bp = pulsevm_crypto::K1PrivateKey::from_string(&args[10]).expect("bad bp wif");
            let height: u32 = args[11].parse().expect("bad height");
            let source_chain_hex = args[12].clone();
            let members_json = std::fs::read(&args[13]).expect("read members");
            let mut members: Vec<pulsevm_chain_types::HaltDeclarationMember> =
                serde_json::from_slice(&members_json).expect("parse members");
            pulsevm_chain_types::HaltDeclaration::sort_members(&mut members);
            // The vote binds the exact A-Chain declaration digest: one BP
            // signature serves both the on-chain tally and the off-chain pair.
            let unsigned = pulsevm_chain_types::HaltDeclaration {
                version: pulsevm_chain_types::HaltDeclaration::VERSION,
                source_chain_id: source_chain_hex,
                last_height: height,
                validator_set: members,
                signatures: Vec::new(),
            };
            let digest32 = unsigned.digest().expect("digest builds");
            let sig = bp.sign(&digest32);
            let compact = sig.compact65();
            let mut data = Name::from_str(&producer)
                .expect("bad producer")
                .as_u64()
                .to_le_bytes()
                .to_vec();
            // Signature serializes as varuint type (0 = K1) + 65 compact bytes.
            varuint(0, &mut data);
            data.extend_from_slice(&compact);
            build_action(
                &chain_id,
                &relay,
                args[4].parse().expect("bad ref num"),
                args[5].parse().expect("bad ref prefix"),
                args[6].parse().expect("bad expiration"),
                &contract,
                "vote",
                &relay_account,
                data,
            );
        }
        other => panic!(
            "unknown mode {other}: expected newaccount, updateauth, newkey, setcode, setabi, raw, cseed, or cvote"
        ),
    }
}

fn varuint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn build_action(
    chain_id: &Id,
    key: &PrivateKey,
    ref_num: u16,
    ref_prefix: u32,
    exp: u32,
    code: &str,
    action: &str,
    auth_account: &str,
    data: Vec<u8>,
) {
    let header = header(ref_num, ref_prefix, exp);
    let active = Name::from_str("active").expect("active is a valid name");
    let trx = Transaction::new(
        header,
        vec![],
        vec![Action::new(
            Name::from_str(code).expect("bad code"),
            Name::from_str(action).expect("bad action"),
            data,
            vec![PermissionLevel::new(
                Name::from_str(auth_account)
                    .expect("bad auth account")
                    .as_u64(),
                active.as_u64(),
            )],
        )],
    )
    .sign(key, chain_id)
    .expect("signing works");
    println!("{}", issue_body(trx));
}

fn setcode_args() -> (Id, PrivateKey, u16, u32, u32, String, Vec<u8>) {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        9,
        "usage: make_probe_tx setcode|setabi <chain-id> <wif> <ref-num> <ref-prefix> <exp> <account> <file>"
    );
    (
        Id::from_str(&args[2]).expect("bad chain id"),
        PrivateKey::from_str(&args[3]).expect("bad wif"),
        args[4].parse().expect("bad ref num"),
        args[5].parse().expect("bad ref prefix"),
        args[6].parse().expect("bad expiration"),
        args[7].clone(),
        std::fs::read(&args[8]).expect("read file"),
    )
}
