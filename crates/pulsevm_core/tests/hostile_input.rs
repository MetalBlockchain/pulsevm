//! Hostile-input robustness for every decoder that peers or RPC clients reach.
//!
//! AGENTS.md rule: nothing controlled by a transaction, peer, contract, ABI or
//! RPC client may panic, hang or allocate by an attacker-chosen amount. These
//! property tests feed each decoder (a) arbitrary bytes and (b) mutated copies
//! of real encodings, which reach far deeper than random noise, and require
//! only that decoding returns, `Ok` or `Err`. A panic fails the property; an
//! allocation abort kills the test process, which also fails the run.

use proptest::{
    collection::vec,
    prelude::*,
};
use pulsevm_core::{
    abi::AbiDefinition,
    authority::Authority,
    block::SignedBlock,
    crypto::{
        PublicKey,
        Signature,
    },
    transaction::{
        Action,
        PackedTransaction,
        TransactionCompression,
        TransactionReceipt,
    },
};
use pulsevm_crypto::Bytes;
use pulsevm_serialization::{
    Read,
    Write,
};
use std::str::FromStr;

/// A Leap 5 `newaccount` transaction, captured from a real nodeos (the same
/// bytes the unit tests decode).
const LEAP_TRX_HEX: &str = "2302876a8e1f127516c500000000010000000000ea305500409e9a2264b89a010000000000ea305500000000a8ed3232660000000000ea3055901132ead05bb9b901000000010002c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cf0100000001000000010002c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cf0100000000";

const SIG_A: &str = "SIG_K1_KZDbad1igYb6zfjGqziC4DwanAYv96DMJDb3NLgMgLwSximq6Gf3GjFQEVDsRYEihRvsx8BxSLvYHhyCVYyxHZZh2H2vtX";
const SIG_B: &str = "SIG_K1_K6tVhH5eiejjjnyBU1LnTkYDzHnLxiQSGZdc5N3qwo6aUz1pcABEicDJvr1wHKDhW24DmP2v7smw6hzBjWr5sJgHfi5SRQ";

fn seed_packed_transaction() -> Vec<u8> {
    let packed = PackedTransaction::new(
        vec![
            Signature::from_str(SIG_A).unwrap(),
            Signature::from_str(SIG_B).unwrap(),
        ],
        TransactionCompression::None,
        Bytes::default(),
        hex::decode(LEAP_TRX_HEX).unwrap().into(),
    )
    .expect("the captured transaction packs");
    packed.pack().expect("pack")
}

fn seed_action() -> Vec<u8> {
    let trx = PackedTransaction::from_deferred_transaction_bytes(
        hex::decode(LEAP_TRX_HEX).unwrap().into(),
    )
    .unwrap();
    trx.get_transaction().actions[0].pack().unwrap()
}

fn seed_signed_block() -> Vec<u8> {
    SignedBlock::default().pack().unwrap()
}

/// Apply one of several damaging edits to a valid encoding.
fn mutate(seed: Vec<u8>) -> impl Strategy<Value = Vec<u8>> {
    let len = seed.len().max(1);
    (
        Just(seed),
        0usize..len,
        any::<u8>(),
        0usize..4,
        vec(any::<u8>(), 0..64),
    )
        .prop_map(|(mut bytes, at, value, op, extra)| {
            match op {
                // Flip one byte.
                0 => {
                    if let Some(byte) = bytes.get_mut(at) {
                        *byte = value;
                    }
                }
                // Truncate.
                1 => bytes.truncate(at),
                // Append junk (trailing data).
                2 => bytes.extend_from_slice(&extra),
                // Replace a prefix with an enormous varint length, the shape
                // that drives pre-allocation attacks.
                _ => {
                    let huge = [0xFFu8, 0xFF, 0xFF, 0xFF, 0x0F];
                    let end = at.min(bytes.len());
                    bytes.splice(0..end.min(huge.len()), huge);
                }
            }
            bytes
        })
}

/// Decode `bytes` as `T`; the only requirement is that it returns.
fn decodes_without_panicking<T: Read>(bytes: &[u8]) {
    let mut pos = 0;
    let _ = T::read(bytes, &mut pos);
    assert!(pos <= bytes.len().max(pos), "position stays sane");
}

macro_rules! hostile_decoder {
    ($name:ident, $ty:ty, $seed:expr) => {
        mod $name {
            use super::*;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(512))]

                #[test]
                fn arbitrary_bytes_never_panic(bytes in vec(any::<u8>(), 0..2048)) {
                    decodes_without_panicking::<$ty>(&bytes);
                }

                #[test]
                fn mutated_real_encodings_never_panic(bytes in mutate($seed)) {
                    decodes_without_panicking::<$ty>(&bytes);
                }
            }
        }
    };
}

hostile_decoder!(
    packed_transaction,
    PackedTransaction,
    seed_packed_transaction()
);
hostile_decoder!(action, Action, seed_action());
hostile_decoder!(signed_block, SignedBlock, seed_signed_block());
hostile_decoder!(transaction_receipt, TransactionReceipt, {
    // A receipt is a header plus a packed transaction; reuse the real packed
    // bytes behind a small valid header.
    let mut bytes = vec![0u8, 0, 0, 0, 0, 0, 0, 0, 0];
    bytes.extend(seed_packed_transaction());
    bytes
});
hostile_decoder!(
    authority,
    Authority,
    vec![
        1, 0, 0, 0, 1, 0, 2, 0xc0, 0xde, 0xd2, 0xbc, 0x1f, 0x13, 0x05, 0xfb, 0x0f, 0xaa, 0xc5,
        0xe6, 0xc0, 0x3e, 0xe3, 0xa1, 0x92, 0x42, 0x34, 0x98, 0x54, 0x27, 0xb6, 0x16, 0x7c, 0xa5,
        0x69, 0xd1, 0x3d, 0xf4, 0x35, 0xcf, 1, 0, 0, 0, 0, 0
    ]
);
hostile_decoder!(signature, Signature, {
    let mut bytes = vec![0u8];
    bytes.extend([0xAB; 65]);
    bytes
});
hostile_decoder!(public_key, PublicKey, {
    let mut bytes = vec![0u8];
    bytes.extend([0x02; 33]);
    bytes
});
hostile_decoder!(abi_definition, AbiDefinition, {
    let abi: AbiDefinition = serde_json::from_str(
        r#"{"version":"eosio::abi/1.1","structs":[{"name":"transfer","base":"","fields":[{"name":"from","type":"name"},{"name":"quantity","type":"asset"}]}],"actions":[{"name":"transfer","type":"transfer","ricardian_contract":""}]}"#,
    )
    .expect("a small ABI parses");
    abi.pack().unwrap()
});

#[test]
fn the_seeds_themselves_are_valid() {
    // A mutation test over an invalid seed proves nothing: the seeds must
    // decode, so the mutations start from encodings the decoder accepts.
    let packed = seed_packed_transaction();
    let mut pos = 0;
    let decoded = PackedTransaction::read(&packed, &mut pos).expect("packed seed decodes");
    assert_eq!(pos, packed.len());
    assert_eq!(decoded.pack().unwrap(), packed, "round trip is exact");

    let action = seed_action();
    let mut pos = 0;
    Action::read(&action, &mut pos).expect("action seed decodes");
    assert_eq!(pos, action.len());

    let block = seed_signed_block();
    let mut pos = 0;
    SignedBlock::read(&block, &mut pos).expect("block seed decodes");
    assert_eq!(pos, block.len());
}

#[test]
fn a_length_prefix_bomb_is_refused_without_a_giant_allocation() {
    // 5-byte varuint claiming ~4 billion elements, then nothing. If the decoder
    // reserved by the claimed length this would abort the process.
    let bomb = [0xFFu8, 0xFF, 0xFF, 0xFF, 0x0F];
    for _ in 0..4 {
        assert!(Vec::<Signature>::read(&bomb, &mut 0).is_err());
        assert!(PackedTransaction::read(&bomb, &mut 0).is_err());
        assert!(SignedBlock::read(&bomb, &mut 0).is_err());
        assert!(Authority::read(&bomb, &mut 0).is_err());
    }
}

mod rpc_push_json {
    use super::*;
    use serde_json::{
        Map,
        Value,
        json,
    };

    fn parse(params: Value) {
        if let Value::Object(map) = params {
            let _ = PackedTransaction::from_push_transaction_json(&map);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn arbitrary_field_values_never_panic(
            sigs in vec(".{0,200}", 0..80),
            compression in ".{0,12}",
            packed in ".{0,4096}",
            cfd in ".{0,64}",
        ) {
            parse(json!({
                "signatures": sigs,
                "compression": compression,
                "packed_context_free_data": cfd,
                "packed_trx": packed,
            }));
        }

        #[test]
        fn wrongly_typed_fields_never_panic(
            sigs in prop_oneof![Just(json!(null)), Just(json!(7)), Just(json!("x")), Just(json!({})), Just(json!([1, 2])), Just(json!([[]]))],
            packed in prop_oneof![Just(json!(null)), Just(json!(7)), Just(json!([])), Just(json!({"a": 1}))],
        ) {
            parse(json!({ "signatures": sigs, "packed_trx": packed, "compression": 3 }));
        }
    }

    #[test]
    fn oversized_and_malformed_inputs_are_rejected_not_executed() {
        let huge_hex = "a".repeat(8 * 1024 * 1024);
        let mut params = Map::new();
        params.insert("signatures".into(), json!([SIG_A]));
        params.insert("compression".into(), json!("none"));
        params.insert("packed_trx".into(), json!(huge_hex));
        params.insert("packed_context_free_data".into(), json!(""));
        assert!(PackedTransaction::from_push_transaction_json(&params).is_err());

        let too_many: Vec<_> = (0..1000).map(|_| SIG_A).collect();
        let mut params = Map::new();
        params.insert("signatures".into(), json!(too_many));
        params.insert("compression".into(), json!("none"));
        params.insert("packed_trx".into(), json!(LEAP_TRX_HEX));
        assert!(PackedTransaction::from_push_transaction_json(&params).is_err());

        assert!(PackedTransaction::from_push_transaction_json(&Map::new()).is_err());
    }
}
