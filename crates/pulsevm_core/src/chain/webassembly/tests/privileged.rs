use crate::chain::producer_schedule::{
    MAX_PRODUCERS,
    MAX_SCHEDULE_BYTES,
    ProducerKey,
};

use super::*;

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
    h.trx.set_active_schedule(producers, 3).unwrap();
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
        .set_active_schedule(vec![producer.clone()], 3)
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
