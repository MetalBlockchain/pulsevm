use pulsevm_chain_types::{
    ChainConfigV0,
    ElasticLimitParameters,
    GenesisState,
    Ratio,
};
use pulsevm_error::ChainError;
use serde_json::{
    Value,
    json,
};

mod common;
use common::assert_wire;

fn config() -> ChainConfigV0 {
    ChainConfigV0 {
        max_block_net_usage: 1_048_576,
        target_block_net_usage_pct: 1000,
        max_transaction_net_usage: 524_288,
        base_per_transaction_net_usage: 12,
        net_usage_leeway: 500,
        context_free_discount_net_usage_num: 20,
        context_free_discount_net_usage_den: 100,
        max_block_cpu_usage: 3_000_000_000,
        target_block_cpu_usage_pct: 2500,
        max_transaction_cpu_usage: 1_000_000_000,
        min_transaction_cpu_usage: 100_000,
        max_transaction_lifetime: 3600,
        deferred_trx_expiration_window: 600,
        max_transaction_delay: 3_888_000,
        max_inline_action_size: 4096,
        max_inline_action_depth: 6,
        max_authority_depth: 6,
    }
}

fn invalid(config: ChainConfigV0, message: &str) {
    match config.validate().unwrap_err() {
        ChainError::ActionValidationError(text) => assert!(text.contains(message), "{text}"),
        err => panic!("unexpected error: {err:?}"),
    }
}

#[test]
fn config_percentages_accept_exact_limits_and_reject_neighbors() {
    assert!(config().validate().is_ok());
    for value in [10, 10_000] {
        assert!(
            ChainConfigV0 {
                target_block_net_usage_pct: value,
                target_block_cpu_usage_pct: value,
                ..config()
            }
            .validate()
            .is_ok()
        );
    }
    for value in [0, 9, 10_001, u32::MAX] {
        invalid(
            ChainConfigV0 {
                target_block_net_usage_pct: value,
                ..config()
            },
            "net usage percentage",
        );
        invalid(
            ChainConfigV0 {
                target_block_cpu_usage_pct: value,
                ..config()
            },
            "cpu usage percentage",
        );
    }
}

#[test]
fn config_net_limits_validate_strict_order_and_minimum_gap() {
    let mut c = config();
    c.max_block_net_usage = u64::from(c.max_transaction_net_usage) + 1;
    assert!(c.validate().is_ok());
    c.max_block_net_usage -= 1;
    invalid(c, "less than max block net usage");
    c = config();
    c.base_per_transaction_net_usage = c.max_transaction_net_usage;
    invalid(c, "base net usage per transaction");
    c.base_per_transaction_net_usage = u32::MAX;
    invalid(c, "base net usage per transaction");
    c = config();
    c.max_transaction_net_usage = c.base_per_transaction_net_usage + 10_240;
    assert!(c.validate().is_ok());
    c.max_transaction_net_usage -= 1;
    invalid(c, "at least 10240 bytes larger");
    assert!(
        ChainConfigV0 {
            max_block_net_usage: u64::MAX,
            max_transaction_net_usage: u32::MAX,
            ..config()
        }
        .validate()
        .is_ok()
    );
}

#[test]
fn config_discount_ratio_boundaries() {
    for num in [0, 1, 100] {
        assert!(
            ChainConfigV0 {
                context_free_discount_net_usage_num: num,
                ..config()
            }
            .validate()
            .is_ok()
        );
    }
    invalid(
        ChainConfigV0 {
            context_free_discount_net_usage_den: 0,
            ..config()
        },
        "0 denominator",
    );
    invalid(
        ChainConfigV0 {
            context_free_discount_net_usage_num: 101,
            ..config()
        },
        "cannot exceed 1",
    );
}

#[test]
fn config_cpu_limits_and_authority_depth_boundaries() {
    let mut c = config();
    c.max_transaction_cpu_usage = c.max_block_cpu_usage;
    invalid(c, "less than max block cpu usage");
    c = config();
    c.min_transaction_cpu_usage = c.max_transaction_cpu_usage + 1;
    invalid(c, "min transaction cpu usage cannot exceed");
    c.min_transaction_cpu_usage -= 1;
    assert!(c.validate().is_ok());
    c.max_block_cpu_usage = 2 * c.max_transaction_cpu_usage;
    invalid(c, "difference between");
    c.max_block_cpu_usage += 1;
    assert!(c.validate().is_ok());
    invalid(
        ChainConfigV0 {
            max_authority_depth: 0,
            ..config()
        },
        "at least 1",
    );
    assert!(
        ChainConfigV0 {
            max_authority_depth: 1,
            ..config()
        }
        .validate()
        .is_ok()
    );
}

#[test]
fn config_wire_field_order_and_widths_are_fixed() {
    let c = ChainConfigV0 {
        max_block_net_usage: 1,
        target_block_net_usage_pct: 2,
        max_transaction_net_usage: 3,
        base_per_transaction_net_usage: 4,
        net_usage_leeway: 5,
        context_free_discount_net_usage_num: 6,
        context_free_discount_net_usage_den: 7,
        max_block_cpu_usage: 8,
        target_block_cpu_usage_pct: 9,
        max_transaction_cpu_usage: 10,
        min_transaction_cpu_usage: 11,
        max_transaction_lifetime: 12,
        deferred_trx_expiration_window: 13,
        max_transaction_delay: 14,
        max_inline_action_size: 15,
        max_inline_action_depth: 16,
        max_authority_depth: 17,
    };
    let mut bytes = 1u64.to_le_bytes().to_vec();
    for n in 2u32..=15 {
        bytes.extend(n.to_le_bytes());
    }
    bytes.extend(16u16.to_le_bytes());
    bytes.extend(17u16.to_le_bytes());
    assert_eq!(bytes.len(), 68);
    assert_wire(&c, &bytes);
}

#[test]
fn elastic_parameters_require_periods_and_defined_ratios() {
    let ratio = Ratio {
        numerator: 1,
        denominator: 2,
    };
    let valid = ElasticLimitParameters::new(100, 1000, 1, 10, ratio, ratio);
    assert_eq!(
        (valid.target, valid.max, valid.periods, valid.max_multiplier),
        (100, 1000, 1, 10)
    );
    assert!(valid.validate().is_ok());
    let undefined = Ratio {
        denominator: 0,
        ..ratio
    };
    for (value, message) in [
        (
            ElasticLimitParameters {
                periods: 0,
                ..valid
            },
            "periods",
        ),
        (
            ElasticLimitParameters {
                contract_rate: undefined,
                ..valid
            },
            "contract_rate",
        ),
        (
            ElasticLimitParameters {
                expand_rate: undefined,
                ..valid
            },
            "expand_rate",
        ),
    ] {
        assert!(
            matches!(value.validate(), Err(ChainError::InvalidArgument(text)) if text.contains(message))
        );
    }
}

#[test]
fn ratio_multiplication_truncates_and_checks_intermediate_overflow() {
    for (value, numerator, denominator, expected) in [
        (5, 2, 3, 3),
        (0, u64::MAX, 1, 0),
        (u64::MAX, 0, 1, 0),
        (u64::MAX, 1, 1, u64::MAX),
        (u64::MAX / 2, 2, 2, u64::MAX / 2),
    ] {
        assert_eq!(
            (value
                * Ratio {
                    numerator,
                    denominator
                })
            .unwrap(),
            expected
        );
    }
    // The multiplication must fit even when the final quotient would fit.
    assert!(matches!(
        (u64::MAX / 2 + 1)
            * Ratio {
                numerator: 2,
                denominator: 2
            },
        Err(ChainError::InvalidArgument(_))
    ));
}

fn genesis_json() -> Value {
    json!({
        "initial_timestamp": "2023-01-01T00:00:00",
        "initial_key": "PUB_K1_8fsJkG5ka4o1G1wBhySUavHuGqstcjtXMrquxiRWVcYw8ZvZLX",
        "initial_configuration": {
            "max_block_net_usage": 1048576,
            "target_block_net_usage_pct": 1000,
            "max_transaction_net_usage": 524288,
            "base_per_transaction_net_usage": 12,
            "net_usage_leeway": 500,
            "context_free_discount_net_usage_num": 20,
            "context_free_discount_net_usage_den": 100,
            "max_block_cpu_usage": 3000000000u32,
            "target_block_cpu_usage_pct": 2500,
            "max_transaction_cpu_usage": 1000000000,
            "min_transaction_cpu_usage": 100000,
            "max_transaction_lifetime": 3600,
            "deferred_trx_expiration_window": 600,
            "max_transaction_delay": 3888000,
            "max_inline_action_size": 4096,
            "max_inline_action_depth": 6,
            "max_authority_depth": 6,
            "max_action_return_value_size": 256
        }
    })
}

#[test]
fn genesis_parsing_preserves_configuration_and_optional_defaults() {
    let mut json = genesis_json();
    let original = GenesisState::from_bytes(&serde_json::to_vec(&json).unwrap()).unwrap();
    assert_eq!(original.initial_timestamp_micros, 1_672_531_200_000_000);
    assert_eq!(original.initial_configuration, config());
    assert_eq!(
        original.initial_key_packed(),
        original.initial_key.to_packed()
    );
    let fields = json["initial_configuration"].as_object_mut().unwrap();
    for field in ["max_transaction_delay", "deferred_trx_expiration_window"] {
        fields.remove(field);
    }
    fields.insert("future_field".into(), json!(42));
    let defaulted = GenesisState::from_json(&json.to_string()).unwrap();
    assert_eq!(
        defaulted.initial_configuration,
        ChainConfigV0 {
            max_transaction_delay: 0,
            deferred_trx_expiration_window: 0,
            ..config()
        }
    );
    assert_eq!(defaulted.max_action_return_value_size, 256);
    json["initial_configuration"]["max_transaction_delay"] = json!(0);
    json["initial_configuration"]["deferred_trx_expiration_window"] = json!(0);
    json["initial_configuration"]["max_action_return_value_size"] = json!(256);
    assert_eq!(
        GenesisState::from_json(&json.to_string())
            .unwrap()
            .compute_chain_id(),
        defaulted.compute_chain_id()
    );

    // Historical EOSIO/XPR genesis files omitted the later binary-extension
    // field. Its runtime value still defaults to 256, but its absence must
    // retain the older packed chain-id layout.
    json["initial_configuration"]
        .as_object_mut()
        .unwrap()
        .remove("max_action_return_value_size");
    let legacy = GenesisState::from_json(&json.to_string()).unwrap();
    assert_eq!(legacy.max_action_return_value_size, 256);
    assert!(!legacy.chain_id_includes_max_action_return_value_size);
    assert_ne!(legacy.compute_chain_id(), defaulted.compute_chain_id());
}

#[test]
fn genesis_hash_commits_every_configuration_field_and_timestamp() {
    let json = genesis_json();
    let original = GenesisState::from_json(&json.to_string())
        .unwrap()
        .compute_chain_id();
    for (field, value) in json["initial_configuration"].as_object().unwrap() {
        let mut changed = json.clone();
        changed["initial_configuration"][field] = json!(value.as_u64().unwrap() + 1);
        assert_ne!(
            GenesisState::from_json(&changed.to_string())
                .unwrap()
                .compute_chain_id(),
            original,
            "uncommitted field {field}"
        );
    }
    let mut changed = json;
    changed["initial_timestamp"] = json!("2023-01-01T00:00:00.000001");
    assert_ne!(
        GenesisState::from_json(&changed.to_string())
            .unwrap()
            .compute_chain_id(),
        original
    );
}

#[test]
fn genesis_timestamp_fraction_precision_and_calendar_boundaries() {
    for (timestamp, expected) in [
        ("1970-01-01T00:00:00.5", 500_000),
        ("1970-01-01T00:00:00.0000019", 1),
        ("1969-12-31T23:59:59.5", -500_000),
        ("2000-02-29T00:00:00", 951_782_400_000_000),
        ("2000-03-01T00:00:00", 951_868_800_000_000),
        ("0000-01-01T00:00:00", -62_167_219_200_000_000),
    ] {
        let mut json = genesis_json();
        json["initial_timestamp"] = json!(timestamp);
        assert_eq!(
            GenesisState::from_json(&json.to_string())
                .unwrap()
                .initial_timestamp_micros,
            expected,
            "{timestamp}"
        );
    }
}

#[test]
fn genesis_rejects_malformed_timestamps_with_typed_errors() {
    for timestamp in [
        "",
        "2023-01-01",
        "x-01-01T00:00:00",
        "2023-x-01T00:00:00",
        "2023-01-xT00:00:00",
        "2023-01T00:00:00",
        "2023-01-01-01T00:00:00",
        "2023-00-01T00:00:00",
        "2023-13-01T00:00:00",
        "2023-01-00T00:00:00",
        "2023-01-32T00:00:00",
        "2023-01-01Tx:00:00",
        "2023-01-01T00:x:00",
        "2023-01-01T00:00:x",
        "2023-01-01T00:00",
        "2023-01-01T00:00:00:00",
        "2023-01-01T24:00:00",
        "2023-01-01T00:60:00",
        "2023-01-01T00:00:61",
        "2023-01-01T00:00:00.",
        "2023-01-01T00:00:00.x",
        "2023-01-01T00:00:00.000000x",
        "2023-01-01T00:00:00Z",
        "1000000-01-01T00:00:00",
    ] {
        let mut json = genesis_json();
        json["initial_timestamp"] = json!(timestamp);
        assert!(
            matches!(
                GenesisState::from_json(&json.to_string()),
                Err(ChainError::ParseError(_))
            ),
            "{timestamp}"
        );
    }
}

#[test]
fn genesis_rejects_invalid_utf8_json_missing_fields_and_keys() {
    assert!(
        matches!(GenesisState::from_bytes(&[0xff]), Err(ChainError::ParseError(text)) if text.contains("UTF-8"))
    );
    for text in ["{", "null", "{}", "[]"] {
        assert!(matches!(
            GenesisState::from_json(text),
            Err(ChainError::ParseError(_))
        ));
    }
    for field in ["initial_timestamp", "initial_key", "initial_configuration"] {
        let mut json = genesis_json();
        json.as_object_mut().unwrap().remove(field);
        assert!(matches!(
            GenesisState::from_json(&json.to_string()),
            Err(ChainError::ParseError(_))
        ));
    }
    let mut json = genesis_json();
    json["initial_key"] = json!("not-a-public-key");
    assert!(matches!(
        GenesisState::from_json(&json.to_string()),
        Err(ChainError::GenesisError(_))
    ));
    json = genesis_json();
    json["initial_configuration"]["max_inline_action_depth"] = json!(65536);
    assert!(matches!(
        GenesisState::from_json(&json.to_string()),
        Err(ChainError::ParseError(_))
    ));
}
