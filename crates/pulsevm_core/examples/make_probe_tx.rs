//! Build signed rehearsal transactions with the audited packing and
//! signing paths, and print the `pulsevm.issueTx` JSON body.
//! Usage:
//!   make_probe_tx newaccount <chain-id> <wif> <ref-num> <ref-prefix> <exp> <name>
//! [auth-pubkey-hex]   make_probe_tx updateauth <chain-id> <wif> <ref-num> <ref-prefix> <exp>
//!     <account> <permission> <parent> <auth-pubkey-compressed-hex>
//!   make_probe_tx newkey
//! `newkey` prints a fresh `<wif> <compressed-pubkey-hex>` pair for traffic
//! authorities. `updateauth` signs with <wif> (which must satisfy the current
//! authority) and installs the given key. `newaccount` authorizes with the
//! signing key unless [auth-pubkey-hex] overrides the installed authority.
use std::str::FromStr;

use pulsevm_core::{
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
        "usage: make_probe_tx <newaccount|updateauth|newkey> ..."
    );
    match args[1].as_str() {
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
        other => panic!("unknown mode {other}: expected newaccount, updateauth, or newkey"),
    }
}
