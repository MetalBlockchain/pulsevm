use crate::chain::producer_schedule::{
    MAX_PRODUCERS,
    MAX_SCHEDULE_BYTES,
    ProducerKey,
};

use super::*;

fn packed_single_key_authority(h: &Host, producer_name: Name) -> Vec<u8> {
    let mut packed = pulsevm_serialization::VarUint32::from(1).pack().unwrap();
    packed.extend(producer_name.pack().unwrap());
    packed.extend(pulsevm_serialization::VarUint32::from(0).pack().unwrap());
    packed.extend(1u32.pack().unwrap());
    packed.extend(pulsevm_serialization::VarUint32::from(1).pack().unwrap());
    packed.extend(
        AuthorityPublicKey::from(h.key.get_public_key().into_k1())
            .pack()
            .unwrap(),
    );
    packed.extend(1u16.pack().unwrap());
    packed
}

#[test]
fn preactivate_feature_queues_known_digest_and_is_idempotent_when_active() {
    let mut h = Host::new(false);
    let digest = crate::chain::webassembly::GET_BLOCK_NUM_FEATURE_DIGEST;
    h.write(OUT, &digest);
    preactivate_feature(h.env(), ptr(OUT)).unwrap();
    assert_eq!(h.db.preactivated_protocol_features(), [digest]);

    h.write(OUT, &crate::chain::webassembly::GET_SENDER_FEATURE_DIGEST);
    preactivate_feature(h.env(), ptr(OUT)).unwrap();
    assert_eq!(h.db.preactivated_protocol_features(), [digest]);

    h.write(OUT, &[0xff; 32]);
    assert_error(
        preactivate_feature(h.env(), ptr(OUT)),
        "unrecognized protocol feature",
    );
    assert!(preactivate_feature(h.env(), ptr(END - 1)).is_err());
}

#[test]
fn preactivate_feature_rejects_unprivileged_and_context_free_callers() {
    let mut unprivileged = Host::new(false);
    unprivileged
        .db
        .set_privileged(PULSE_NAME.as_u64(), false)
        .unwrap();
    unprivileged
        .env
        .as_mut(&mut unprivileged.store)
        .apply_context_mut()
        .exec_one()
        .unwrap();
    assert_error(
        preactivate_feature(unprivileged.env(), ptr(OUT)),
        "without proper authorization",
    );

    let mut context_free = Host::new(true);
    assert_error(
        preactivate_feature(context_free.env(), ptr(OUT)),
        "context-free action",
    );
}

#[test]
fn producer_schedule_queries_copy_raw_names_with_partial_buffers() {
    let mut h = Host::new(false);
    assert_eq!(get_active_producers(h.env(), ptr(OUT), 8).unwrap(), 0);
    let names = [PULSE_NAME, Name::from_str("second").unwrap()];
    let producers = names
        .iter()
        .map(|name| ProducerKey {
            producer_name: *name,
            block_signing_key: h.key.get_public_key(),
        })
        .collect();
    h.trx.set_producer_schedules(producers, 3, None).unwrap();
    let expected: Vec<u8> = names
        .iter()
        .flat_map(|name| name.as_u64().to_le_bytes())
        .collect();
    assert_eq!(get_active_producers(h.env(), ptr(u32::MAX), 0).unwrap(), 16);
    for size in [1, 7, 8, 15, 16, 17] {
        h.write(OUT, &[0xa5; 18]);
        let copied = size.min(16);
        h.budget(cost::PRODUCER + cost::per_byte(copied.into()));
        assert_eq!(
            get_active_producers(h.env(), ptr(OUT), size).unwrap(),
            copied as i32
        );
        assert_eq!(h.read(OUT, copied as usize), expected[..copied as usize]);
        assert_eq!(h.read(OUT + copied, 1), [0xa5]);
        assert_eq!(h.remaining(), 0);
    }
    h.budget(u64::MAX);
    assert!(get_active_producers(h.env(), ptr(END - 1), 2).is_err());
    let mut cf = Host::new(true);
    assert_error(
        get_active_producers(cf.env(), ptr(OUT), 0),
        "context-free action",
    );
}

#[test]
fn proposed_schedules_validate_size_contents_and_version() {
    let mut h = Host::new(false);
    let producer = ProducerKey {
        producer_name: PULSE_NAME,
        block_signing_key: h.key.get_public_key(),
    };
    let packed = vec![producer.clone()].pack().unwrap();
    h.write(OUT, &packed);
    assert_eq!(
        set_proposed_producers(h.env(), ptr(OUT), packed.len() as u32).unwrap(),
        1
    );
    h.trx
        .set_producer_schedules(vec![producer.clone()], 3, None)
        .unwrap();
    assert_eq!(
        set_proposed_producers(h.env(), ptr(OUT), packed.len() as u32).unwrap(),
        -1
    );
    let duplicates = vec![producer.clone(), producer.clone()].pack().unwrap();
    h.write(OUT, &duplicates);
    assert!(set_proposed_producers(h.env(), ptr(OUT), duplicates.len() as u32).is_err());
    let mut missing = producer.clone();
    missing.producer_name = Name::from_str("missing").unwrap();
    let packed = vec![missing].pack().unwrap();
    h.write(OUT, &packed);
    assert!(set_proposed_producers(h.env(), ptr(OUT), packed.len() as u32).is_err());
    assert!(set_proposed_producers(h.env(), ptr(OUT), MAX_SCHEDULE_BYTES + 1).is_err());
    let count = pulsevm_serialization::VarUint32::from(MAX_PRODUCERS + 1)
        .pack()
        .unwrap();
    h.write(OUT, &count);
    assert!(set_proposed_producers(h.env(), ptr(OUT), count.len() as u32).is_err());
    h.write(OUT, &[0xff]);
    assert!(set_proposed_producers(h.env(), ptr(OUT), 1).is_err());
    assert!(set_proposed_producers(h.env(), ptr(END - 1), 2).is_err());
}

#[test]
fn extended_producer_schedules_support_legacy_and_single_key_authorities() {
    let mut legacy = Host::new(false);
    let producer = ProducerKey {
        producer_name: PULSE_NAME,
        block_signing_key: legacy.key.get_public_key(),
    };
    let packed = vec![producer].pack().unwrap();
    legacy.write(OUT, &packed);
    assert_eq!(
        set_proposed_producers_ex(legacy.env(), 0, ptr(OUT), packed.len() as u32).unwrap(),
        1
    );

    let mut authority = Host::new(false);
    let packed = packed_single_key_authority(&authority, PULSE_NAME);
    authority.write(OUT, &packed);
    assert_eq!(
        set_proposed_producers_ex(authority.env(), 1, ptr(OUT), packed.len() as u32).unwrap(),
        1
    );
}

#[test]
fn extended_producer_schedules_reject_unknown_and_invalid_formats() {
    let mut h = Host::new(false);
    assert_error(
        set_proposed_producers_ex(h.env(), 2, ptr(u32::MAX), 0),
        "format 2 is not supported",
    );

    h.write(OUT, &[0xff]);
    assert_error(
        set_proposed_producers_ex(h.env(), 1, ptr(OUT), 1),
        "failed to read producer authorities",
    );

    let packed = packed_single_key_authority(&h, Name::from_str("missing").unwrap());
    h.write(OUT, &packed);
    assert_error(
        set_proposed_producers_ex(h.env(), 1, ptr(OUT), packed.len() as u32),
        "is not an account",
    );
}

#[test]
fn blockchain_parameters_round_trip_and_validate_buffers() {
    let mut h = Host::new(false);
    let cfg = h.db.chain_config().unwrap();
    let packed = cfg.pack().unwrap();
    let size = packed.len() as u32;
    assert_eq!(
        get_blockchain_parameters_packed(h.env(), ptr(u32::MAX), 0).unwrap(),
        size
    );
    h.write(OUT, &vec![0xa5; packed.len() + 1]);
    assert_eq!(
        get_blockchain_parameters_packed(h.env(), ptr(OUT), size - 1).unwrap(),
        0
    );
    assert_eq!(h.read(OUT, packed.len() + 1), vec![0xa5; packed.len() + 1]);
    assert_eq!(
        get_blockchain_parameters_packed(h.env(), ptr(OUT), size).unwrap(),
        size
    );
    assert_eq!(h.read(OUT, packed.len()), packed);
    set_blockchain_parameters_packed(h.env(), ptr(OUT), size).unwrap();
    assert_eq!(h.db.chain_config().unwrap().pack().unwrap(), packed);
    assert!(set_blockchain_parameters_packed(h.env(), ptr(OUT), 1).is_err());
    assert!(get_blockchain_parameters_packed(h.env(), ptr(END - 1), size).is_err());
    let mut invalid = cfg;
    invalid.max_transaction_cpu_usage = 0;
    let packed = invalid.pack().unwrap();
    h.write(OUT, &packed);
    assert!(set_blockchain_parameters_packed(h.env(), ptr(OUT), packed.len() as u32).is_err());
}

#[test]
fn resource_limits_and_privilege_updates_reach_the_database() {
    let mut h = Host::new(false);
    let account = PULSE_NAME.as_u64();
    assert_eq!(is_privileged(h.env(), account).unwrap(), 1);
    set_privileged(h.env(), account, 0).unwrap();
    assert_eq!(is_privileged(h.env(), account).unwrap(), 0);
    set_privileged(h.env(), account, 1).unwrap();
    assert_eq!(is_privileged(h.env(), account).unwrap(), 1);
    set_resource_limits(h.env(), account, 1_000_000, 20, 30).unwrap();
    get_resource_limits(h.env(), account, ptr(OUT), ptr(OUT + 8), ptr(OUT + 16)).unwrap();
    assert_eq!(h.read(OUT, 8), 1_000_000i64.to_le_bytes());
    assert_eq!(h.read(OUT + 8, 8), 20i64.to_le_bytes());
    assert_eq!(h.read(OUT + 16, 8), 30i64.to_le_bytes());
    set_resource_limits(h.env(), account, -1, -1, -1).unwrap();
    for (ram, net, cpu) in [(-2, 0, 0), (0, -2, 0), (0, 0, -2)] {
        assert!(set_resource_limits(h.env(), account, ram, net, cpu).is_err());
    }
    assert!(get_resource_limits(h.env(), account, ptr(END - 1), ptr(OUT), ptr(OUT + 8)).is_err());
}

#[test]
fn privileged_calls_reject_unprivileged_and_context_free_callers() {
    for cf in [false, true] {
        let mut h = Host::new(cf);
        if !cf {
            h.db.set_privileged(PULSE_NAME.as_u64(), false).unwrap();
            h.env
                .as_mut(&mut h.store)
                .apply_context_mut()
                .exec_one()
                .unwrap();
        }
        let message = if cf {
            "context-free action"
        } else {
            "without proper authorization"
        };
        assert_error(set_proposed_producers(h.env(), ptr(OUT), 0), message);
        assert_error(
            get_blockchain_parameters_packed(h.env(), ptr(OUT), 0),
            message,
        );
        assert_error(
            set_blockchain_parameters_packed(h.env(), ptr(OUT), 0),
            message,
        );
        assert_error(is_privileged(h.env(), PULSE_NAME.as_u64()), message);
        assert_error(set_privileged(h.env(), PULSE_NAME.as_u64(), 1), message);
        assert_error(
            set_resource_limits(h.env(), PULSE_NAME.as_u64(), 0, 0, 0),
            message,
        );
        assert_error(
            get_resource_limits(
                h.env(),
                PULSE_NAME.as_u64(),
                ptr(OUT),
                ptr(OUT + 8),
                ptr(OUT + 16),
            ),
            message,
        );
    }
}
