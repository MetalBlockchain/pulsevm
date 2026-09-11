use std::str::FromStr;

use pulsevm_billable_size::BillableSize;
use pulsevm_chain_types::{
    Authority,
    KeyWeight,
    PermissionLevel,
    PermissionLevelWeight,
    WaitWeight,
};
use pulsevm_crypto::AuthorityPublicKey;
use pulsevm_name::Name;
use serde::{
    Serialize,
    de::DeserializeOwned,
};
use serde_json::{
    Value,
    json,
};

mod common;
use common::assert_wire;

const KEY: &str = "PUB_K1_8fsJkG5ka4o1G1wBhySUavHuGqstcjtXMrquxiRWVcYw8ZvZLX";

fn key() -> AuthorityPublicKey {
    AuthorityPublicKey::from_string(KEY).unwrap()
}

#[test]
fn permission_names_parsing_ordering_and_json() {
    let p = PermissionLevel::from_str("alice@active").unwrap();
    assert_eq!(p.actor(), Name::from_str("alice").unwrap().as_u64());
    assert_eq!(p.permission(), Name::from_str("active").unwrap().as_u64());
    assert_eq!(p.to_string(), "alice@active");
    assert!(format!("{p:?}").contains("alice"));
    assert_eq!(PermissionLevel::from((p.actor(), p.permission())), p);
    assert_eq!(
        serde_json::to_value(p).unwrap(),
        json!({"actor":"alice","permission":"active"})
    );
    assert_eq!(
        serde_json::from_value::<PermissionLevel>(json!({"actor":"alice","permission":"active"}))
            .unwrap(),
        p
    );
    for (input, message) in [
        ("alice", "expected format"),
        ("ALICE@active", "invalid actor"),
        ("alice@ACTIVE", "invalid permission"),
        ("alice@active@owner", "invalid permission"),
    ] {
        assert!(
            input
                .parse::<PermissionLevel>()
                .unwrap_err()
                .to_string()
                .contains(message)
        );
    }
    for input in [
        json!({"actor":"alice"}),
        json!({"actor":"INVALID","permission":"active"}),
        json!(7),
    ] {
        assert!(serde_json::from_value::<PermissionLevel>(input).is_err());
    }
    let values = [
        PermissionLevel::new(1, 9),
        PermissionLevel::new(2, 0),
        PermissionLevel::new(2, 1),
    ];
    assert!(values[0] < values[1]);
    assert!(values[1] < values[2]);
    assert_eq!(values[0].cmp(&values[0]), std::cmp::Ordering::Equal);
}

#[test]
fn authority_wire_layout_and_weight_billing_are_stable() {
    let permission = PermissionLevel::new(0x0807060504030201, 0x1817161514131211);
    let mut permission_bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 17, 18, 19, 20, 21, 22, 23, 24];
    assert_wire(&permission, &permission_bytes);
    permission_bytes.extend([0x34, 0x12]);
    let account = PermissionLevelWeight::new(permission, 0x1234);
    assert_wire(&account, &permission_bytes);
    let wait = WaitWeight::new(0x04030201, 0x1234);
    let wait_bytes = [1, 2, 3, 4, 0x34, 0x12];
    assert_wire(&wait, &wait_bytes);
    // Compressed secp256k1 generator, with the static-variant K1 tag first.
    let point = [
        2, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    let key: AuthorityPublicKey = pulsevm_crypto::k1::K1PublicKey::from_compressed(&point)
        .unwrap()
        .into();
    let weighted_key = KeyWeight::new(key, 0x1234);
    let mut key_bytes = vec![0];
    key_bytes.extend(point);
    key_bytes.extend([0x34, 0x12]);
    assert_wire(&weighted_key, &key_bytes);
    let authority = Authority::new(0x04030201, vec![weighted_key], vec![account], vec![wait]);
    let mut bytes = vec![1, 2, 3, 4, 1];
    bytes.extend(key_bytes);
    bytes.push(1);
    bytes.extend(permission_bytes);
    bytes.push(1);
    bytes.extend(wait_bytes);
    assert_wire(&authority, &bytes);
    assert_wire(
        &Authority::new(1, vec![], vec![], vec![]),
        &[1, 0, 0, 0, 0, 0, 0],
    );
    assert_eq!((KeyWeight::OVERHEAD, KeyWeight::VALUE), (0, 8));
    assert_eq!(
        (
            PermissionLevelWeight::OVERHEAD,
            PermissionLevelWeight::VALUE
        ),
        (0, 24)
    );
    assert_eq!((WaitWeight::OVERHEAD, WaitWeight::VALUE), (0, 16));
}

#[test]
fn authority_constructors_accessors_and_formatting() {
    let k = Authority::new_from_public_key(key());
    assert_eq!(k.threshold(), 1);
    assert_eq!(k.keys(), &vec![KeyWeight::new(key(), 1)]);
    assert!(k.accounts().is_empty());
    assert!(k.waits().is_empty());
    assert!(k.validate());
    let permission = PermissionLevel::from_str("alice@active").unwrap();
    let p = Authority::new_from_permission_level(&permission);
    assert_eq!(
        p.accounts(),
        &vec![PermissionLevelWeight::new(permission, 1)]
    );
    assert!(p.validate());
    let a = Authority::new(2, k.keys, p.accounts, vec![WaitWeight::new(10, 1)]);
    for output in [a.to_string(), format!("{a:?}")] {
        for field in [
            "threshold",
            "keys",
            "accounts",
            "waits",
            "wait_sec",
            "weight",
            "alice",
            KEY,
        ] {
            assert!(output.contains(field), "missing {field} in {output}");
        }
    }
}

#[test]
fn authority_requires_positive_reachable_threshold_and_strict_order() {
    let account = |actor, perm| PermissionLevelWeight::new(PermissionLevel::new(actor, perm), 2);
    let valid = Authority::new(
        5,
        vec![KeyWeight::new(key(), 1)],
        vec![account(1, 1)],
        vec![WaitWeight::new(1, 2)],
    );
    assert!(valid.validate());
    for threshold in [0, 6, u32::MAX] {
        assert!(
            !Authority {
                threshold,
                ..valid.clone()
            }
            .validate()
        );
    }
    let mut invalid = valid.clone();
    invalid.keys.push(invalid.keys[0].clone());
    assert!(!invalid.validate());
    for accounts in [
        vec![account(1, 1), account(1, 1)],
        vec![account(2, 1), account(1, 1)],
        vec![account(1, 2), account(1, 1)],
    ] {
        assert!(
            !Authority {
                accounts,
                ..valid.clone()
            }
            .validate()
        );
    }
    assert!(
        Authority {
            accounts: vec![account(1, 1), account(1, 2), account(2, 0)],
            ..valid.clone()
        }
        .validate()
    );
    for waits in [
        vec![WaitWeight::new(0, 10)],
        vec![WaitWeight::new(1, 2), WaitWeight::new(1, 2)],
        vec![WaitWeight::new(2, 2), WaitWeight::new(1, 2)],
    ] {
        assert!(
            !Authority {
                waits,
                ..valid.clone()
            }
            .validate()
        );
    }
    assert!(
        Authority {
            waits: vec![WaitWeight::new(1, 0), WaitWeight::new(2, 4)],
            ..valid
        }
        .validate()
    );
}

#[test]
fn authority_entry_limit_bounds_weight_accumulation() {
    let waits = (1..=65_536).map(|n| WaitWeight::new(n, u16::MAX)).collect();
    let mut a = Authority::new(65_536 * u32::from(u16::MAX), vec![], vec![], waits);
    assert!(a.validate());
    a.threshold += 1;
    assert!(!a.validate());
    a.threshold = 1;
    a.waits.push(WaitWeight::new(65_537, 1));
    assert!(!a.validate());
}

// Exercise both custom visitor paths and every missing/duplicate field rejection.
fn assert_json<T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug>(
    value: T,
    fields: &[(&str, Value)],
) {
    let object: serde_json::Map<String, Value> = fields
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    assert_eq!(
        serde_json::to_value(&value).unwrap(),
        Value::Object(object.clone())
    );
    assert_eq!(
        serde_json::from_value::<T>(Value::Object(object.clone())).unwrap(),
        value
    );
    let seq: Vec<_> = fields.iter().map(|(_, v)| v.clone()).collect();
    assert_eq!(serde_json::from_value::<T>(json!(seq)).unwrap(), value);
    for (index, (field, field_value)) in fields.iter().enumerate() {
        let mut missing = object.clone();
        missing.remove(*field);
        assert!(
            serde_json::from_value::<T>(json!(missing))
                .unwrap_err()
                .to_string()
                .contains("missing field")
        );
        let entries: Vec<_> = fields.iter().map(|(k, v)| format!("{k:?}:{v}")).collect();
        let duplicate = format!("{{{}, {field:?}:{field_value}}}", entries.join(","));
        assert!(
            serde_json::from_str::<T>(&duplicate)
                .unwrap_err()
                .to_string()
                .contains("duplicate field")
        );
        assert!(
            serde_json::from_value::<T>(json!(&seq[..index]))
                .unwrap_err()
                .to_string()
                .contains("invalid length")
        );
    }
    let mut unknown = object;
    unknown.insert("unknown".into(), json!(0));
    assert!(
        serde_json::from_value::<T>(json!(unknown))
            .unwrap_err()
            .to_string()
            .contains("unknown field")
    );
    assert!(serde_json::from_value::<T>(json!(false)).is_err());
}

#[test]
fn custom_authority_json_visitors_cover_maps_sequences_and_errors() {
    let permission = PermissionLevel::from_str("alice@active").unwrap();
    assert_json(
        KeyWeight::new(key(), 7),
        &[("key", json!(KEY)), ("weight", json!(7))],
    );
    assert_json(
        PermissionLevelWeight::new(permission, 7),
        &[
            ("permission", json!({"actor":"alice","permission":"active"})),
            ("weight", json!(7)),
        ],
    );
    assert_json(
        WaitWeight::new(10, 7),
        &[("wait_sec", json!(10)), ("weight", json!(7))],
    );
    assert_json(
        Authority::new(7, vec![KeyWeight::new(key(), 7)], vec![], vec![]),
        &[
            ("threshold", json!(7)),
            ("keys", json!([{"key":KEY,"weight":7}])),
            ("accounts", json!([])),
            ("waits", json!([])),
        ],
    );
}

#[test]
fn authority_json_rejects_bad_keys_and_out_of_range_numbers() {
    for input in [
        json!(["bad-key", 1]),
        json!({"key":"bad-key","weight":1}),
        json!({"key":KEY,"weight":65536}),
        json!({"key":KEY,"weight":-1}),
    ] {
        assert!(serde_json::from_value::<KeyWeight>(input).is_err());
    }
    assert!(
        serde_json::from_value::<WaitWeight>(json!({"wait_sec":4294967296u64,"weight":1})).is_err()
    );
    assert!(
        serde_json::from_value::<Authority>(
            json!({"threshold":-1,"keys":[],"accounts":[],"waits":[]})
        )
        .is_err()
    );
}
