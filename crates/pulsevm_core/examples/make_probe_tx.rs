//! Build a signed `eosio::newaccount` probe transaction and print the
//! `pulsevm.issueTx` JSON body.
//! Usage: make_probe_tx <chain-id-hex> <wif> <ref-block-num> <ref-prefix-u32>
//!   <expiration-u32> <new-account-name>
//! Rehearsal helper: uses the audited packing and signing paths.
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
    pulse_contract::NewAccount,
    transaction::{
        Action,
        PackedTransaction,
        Transaction,
        TransactionHeader,
    },
};
use pulsevm_database::TimePointSec;
use pulsevm_serialization::Write as _;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        7,
        "usage: make_probe_tx <chain-id> <wif> <ref-num> <ref-prefix> <exp> <name>"
    );
    let chain_id = Id::from_str(&args[1]).expect("bad chain id");
    let key = PrivateKey::from_str(&args[2]).expect("bad wif");
    let ref_num: u16 = args[3].parse().expect("bad ref num");
    let ref_prefix: u32 = args[4].parse().expect("bad ref prefix");
    let expiration: u32 = args[5].parse().expect("bad expiration");
    let new_account = Name::from_str(&args[6]).expect("bad account name");

    let active = Name::from_str("active").expect("active is a valid name");
    let eosio = Name::from_str("eosio").expect("eosio is a valid name");
    let newaccount_action = Name::from_str("newaccount").expect("newaccount is a valid name");
    let auth = Authority::new(
        1,
        vec![KeyWeight::new(key.get_public_key().into_k1(), 1)],
        vec![],
        vec![],
    );
    let trx = Transaction::new(
        TransactionHeader::new(
            TimePointSec::new(expiration),
            ref_num,
            ref_prefix,
            0u32.into(),
            0,
            0u32.into(),
        ),
        vec![],
        vec![Action::new(
            eosio,
            newaccount_action,
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
    let signatures: Vec<String> = trx.signatures().iter().map(|s| s.to_string()).collect();
    let packed = PackedTransaction::from_signed_transaction(trx).expect("packing works");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "pulsevm.issueTx",
        "params": {
            "signatures": signatures,
            "compression": 0,
            "packed_context_free_data": "",
            "packed_trx": hex::encode(packed.packed_trx_bytes()),
        }
    });
    println!("{body}");
}
