use super::*;

#[test]
fn authorization_checks_distinguish_declared_authority_accounts_and_notifications() {
    let mut h = Host::new(false);
    let account = PULSE_NAME.as_u64();
    let missing = Name::from_str("missing").unwrap().as_u64();
    require_auth(h.env(), account).unwrap();
    require_auth2(h.env(), account, ACTIVE_NAME.as_u64()).unwrap();
    assert_eq!(has_auth(h.env(), account).unwrap(), 1);
    assert_eq!(has_auth(h.env(), missing).unwrap(), 0);
    assert!(require_auth(h.env(), missing).is_err());
    assert!(require_auth2(h.env(), account, missing).is_err());
    assert_eq!(is_account(h.env(), account).unwrap(), 1);
    assert_eq!(is_account(h.env(), missing).unwrap(), 0);
    require_recipient(h.env(), account).unwrap();
    require_recipient(h.env(), account).unwrap();
    assert_eq!(h.trx.get_action_trace(2).unwrap().receiver, PULSE_NAME);
    assert!(h.trx.get_action_trace(3).is_err());

    let mut cf = Host::new(true);
    assert_error(require_auth(cf.env(), account), "context-free action");
    assert_error(
        require_auth2(cf.env(), account, ACTIVE_NAME.as_u64()),
        "context-free action",
    );
    assert_error(has_auth(cf.env(), account), "context-free action");
    assert_error(is_account(cf.env(), account), "context-free action");
    assert_error(require_recipient(cf.env(), account), "context-free action");
    assert_error(current_time(cf.env()), "context-free action");
}

#[test]
fn context_free_data_queries_copies_and_rejects_invalid_ranges() {
    let mut h = Host::new(true);
    assert_eq!(
        get_context_free_data(h.env(), 0, ptr(u32::MAX), 0).unwrap(),
        6
    );
    for size in [1, 5, 6, 7] {
        h.write(OUT, &[0xa5; 8]);
        let copied = size.min(6);
        assert_eq!(
            get_context_free_data(h.env(), 0, ptr(OUT), size).unwrap(),
            copied as i32
        );
        assert_eq!(h.read(OUT, copied as usize), b"abcdef"[..copied as usize]);
        assert_eq!(h.read(OUT + copied, 1), [0xa5]);
    }
    assert_eq!(get_context_free_data(h.env(), 1, ptr(OUT), 7).unwrap(), 0);
    assert_eq!(get_context_free_data(h.env(), 2, ptr(OUT), 7).unwrap(), -1);
    assert_error(
        get_context_free_data(h.env(), 0, ptr(END - 1), 2),
        "invalid buffer range",
    );
    assert_error(
        get_context_free_data(h.env(), 0, ptr(OUT), u32::MAX),
        "invalid buffer range",
    );
    let mut aware = Host::new(false);
    assert_error(
        get_context_free_data(aware.env(), 0, ptr(OUT), 6),
        "context-aware action",
    );
}

#[test]
fn transaction_introspection_returns_exact_serialized_bytes() {
    let mut h = Host::new(false);
    let packed = h.transaction.pack().unwrap();
    assert_eq!(transaction_size(h.env()).unwrap(), packed.len() as u32);
    assert_eq!(
        read_transaction(h.env(), ptr(u32::MAX), 0).unwrap(),
        packed.len() as u32
    );
    for size in [1, packed.len() as u32, packed.len() as u32 + 1] {
        h.write(OUT, &vec![0xa5; packed.len() + 2]);
        let copied = size.min(packed.len() as u32);
        assert_eq!(read_transaction(h.env(), ptr(OUT), size).unwrap(), copied);
        assert_eq!(h.read(OUT, copied as usize), packed[..copied as usize]);
        assert_eq!(h.read(OUT + copied, 1), [0xa5]);
    }
    assert_error(
        read_transaction(h.env(), ptr(END - 1), 2),
        "failed to write transaction data",
    );
    assert_eq!(expiration(h.env()).unwrap(), 1_800_000_000);
    assert_eq!(tapos_block_num(h.env()).unwrap(), 42);
    assert_eq!(tapos_block_prefix(h.env()).unwrap(), 0x12345678);
    assert_eq!(
        current_time(h.env()).unwrap(),
        BlockTimestamp::new(1234)
            .to_time_point()
            .time_since_epoch()
            .count() as u64
    );
    assert_eq!(current_receiver(h.env()).unwrap(), PULSE_NAME.as_u64());
    assert_eq!(get_sender(h.env()).unwrap(), 0);
    assert_eq!(action_data_size(h.env()).unwrap(), 11);
    assert_eq!(read_action_data(h.env(), ptr(OUT), 6).unwrap(), 6);
    assert_eq!(h.read(OUT, 6), b"action");
}

#[test]
fn action_queries_validate_type_index_and_buffer_bounds() {
    let mut h = Host::new(false);
    let action = h.action.pack().unwrap();
    assert_eq!(
        get_action(h.env(), 1, 0, ptr(u32::MAX), 0).unwrap(),
        action.len() as i32
    );
    assert_eq!(
        get_action(h.env(), 1, 0, ptr(OUT), action.len() as u32).unwrap(),
        action.len() as i32
    );
    assert_eq!(h.read(OUT, action.len()), action);
    assert_eq!(get_action(h.env(), 1, 1, ptr(OUT), 128).unwrap(), -1);
    assert!(get_action(h.env(), 2, 0, ptr(OUT), 128).is_err());
    assert!(get_action(h.env(), 1, 0, ptr(END - 1), 2).is_err());
    assert!(get_action(h.env(), 1, 0, ptr(OUT), u32::MAX).is_err());
    let cf = h.transaction.context_free_actions[0].pack().unwrap();
    assert_eq!(
        get_action(h.env(), 0, 0, ptr(OUT), cf.len() as u32).unwrap(),
        cf.len() as i32
    );
    assert_eq!(h.read(OUT, cf.len()), cf);
}

#[test]
fn inline_actions_are_scheduled_and_reject_malformed_or_oversized_input() {
    let mut h = Host::new(false);
    let action = h.action.pack().unwrap();
    h.write(OUT, &action);
    send_inline(h.env(), ptr(OUT), action.len() as u32).unwrap();
    assert_eq!(h.trx.get_action_trace(2).unwrap().act, h.action);
    let mut cf = h.action.clone();
    cf.authorization.clear();
    let bytes = cf.pack().unwrap();
    h.write(OUT, &bytes);
    send_context_free_inline(h.env(), ptr(OUT), bytes.len() as u32).unwrap();
    assert_eq!(h.trx.get_action_trace(3).unwrap().act, cf);
    for op in [send_inline, send_context_free_inline] {
        assert_error(op(h.env(), ptr(OUT), 4096), "inline action too big");
        assert_error(
            op(h.env(), ptr(OUT), 1),
            "failed to deserialize inline action",
        );
        assert!(op(h.env(), ptr(END - 1), 2).is_err());
        let mut context_free = Host::new(true);
        assert_error(op(context_free.env(), ptr(OUT), 1), "context-free action");
    }
}

#[test]
fn permission_queries_accept_keys_and_permissions_and_reject_missing_authority() {
    let mut h = Host::new(false);
    let keys = BTreeSet::from([AuthorityPublicKey::from(h.key.get_public_key().into_k1())])
        .pack()
        .unwrap();
    let permissions = BTreeSet::from([PermissionLevel::new(
        PULSE_NAME.as_u64(),
        ACTIVE_NAME.as_u64(),
    )])
    .pack()
    .unwrap();
    let trx = h.transaction.pack().unwrap();
    h.write(0, &trx);
    h.write(1024, &keys);
    h.write(2048, &permissions);
    for (keys_len, perms_len, expected) in [
        (0, 0, 0),
        (keys.len() as u32, 0, 1),
        (0, permissions.len() as u32, 1),
    ] {
        assert_eq!(
            check_permission_authorization(
                h.env(),
                PULSE_NAME.as_u64(),
                ACTIVE_NAME.as_u64(),
                ptr(1024),
                keys_len,
                ptr(2048),
                perms_len,
                0
            )
            .unwrap(),
            expected
        );
        assert_eq!(
            check_transaction_authorization(
                h.env(),
                ptr(0),
                trx.len() as u32,
                ptr(1024),
                keys_len,
                ptr(2048),
                perms_len
            )
            .unwrap(),
            expected
        );
    }
    assert_eq!(
        get_account_creation_time(h.env(), PULSE_NAME.as_u64()).unwrap(),
        h.db.account_creation_time_micros(PULSE_NAME.as_u64())
            .unwrap()
    );
    assert!(get_permission_last_used(h.env(), PULSE_NAME.as_u64(), ACTIVE_NAME.as_u64()).is_ok());
    assert!(
        get_account_creation_time(h.env(), Name::from_str("missing").unwrap().as_u64()).is_err()
    );
    assert!(
        get_permission_last_used(
            h.env(),
            PULSE_NAME.as_u64(),
            Name::from_str("missing").unwrap().as_u64()
        )
        .is_err()
    );
    assert_error(
        check_permission_authorization(
            h.env(),
            PULSE_NAME.as_u64(),
            ACTIVE_NAME.as_u64(),
            ptr(0),
            0,
            ptr(0),
            0,
            i64::MAX as u64 + 1,
        ),
        "delay is too large",
    );
    assert_eq!(
        check_permission_authorization(
            h.env(),
            PULSE_NAME.as_u64(),
            ACTIVE_NAME.as_u64(),
            ptr(1024),
            keys.len() as u32,
            ptr(0),
            0,
            i64::MAX as u64
        )
        .unwrap(),
        1
    );
}

#[test]
fn permission_input_ranges_and_serialization_are_checked() {
    let mut h = Host::new(false);
    let trx = h.transaction.pack().unwrap();
    h.write(0, &trx);
    h.write(1024, &[0xff]);
    for (key_ptr, key_len, perm_ptr, perm_len) in [
        (END - 1, 2, 0, 0),
        (0, 0, END - 1, 2),
        (1024, 1, 0, 0),
        (0, 0, 1024, 1),
    ] {
        assert!(
            check_permission_authorization(
                h.env(),
                PULSE_NAME.as_u64(),
                ACTIVE_NAME.as_u64(),
                ptr(key_ptr),
                key_len,
                ptr(perm_ptr),
                perm_len,
                0
            )
            .is_err()
        );
        assert!(
            check_transaction_authorization(
                h.env(),
                ptr(0),
                trx.len() as u32,
                ptr(key_ptr),
                key_len,
                ptr(perm_ptr),
                perm_len
            )
            .is_err()
        );
    }
    assert!(
        check_transaction_authorization(h.env(), ptr(END - 1), 2, ptr(0), 0, ptr(0), 0).is_err()
    );
    assert!(check_transaction_authorization(h.env(), ptr(1024), 1, ptr(0), 0, ptr(0), 0).is_err());
    assert!(
        check_permission_authorization(h.env(), 0, 0, ptr(OUT), u32::MAX, ptr(OUT), u32::MAX, 0)
            .is_err()
    );
    let mut cf = Host::new(true);
    assert_error(
        check_permission_authorization(cf.env(), 0, 0, ptr(0), 0, ptr(0), 0, 0),
        "context-free action",
    );
    assert_error(
        check_transaction_authorization(cf.env(), ptr(0), 0, ptr(0), 0, ptr(0), 0),
        "context-free action",
    );
    assert_error(
        get_account_creation_time(cf.env(), 0),
        "context-free action",
    );
    assert_error(
        get_permission_last_used(cf.env(), 0, 0),
        "context-free action",
    );
}

#[test]
fn assertions_handle_success_messages_codes_and_exit() {
    let mut h = Host::new(false);
    eosio_assert(h.env(), 1, ptr(u32::MAX)).unwrap();
    pulse_assert(h.env(), 1, ptr(u32::MAX), u32::MAX).unwrap();
    pulse_assert_message(h.env(), 1, ptr(u32::MAX), u32::MAX).unwrap();
    pulse_assert_code(h.env(), 1, 42).unwrap();
    h.write(OUT, b"hello\0ignored");
    assert_error(
        eosio_assert(h.env(), 0, ptr(OUT)),
        "eosio assert failed: hello",
    );
    assert_error(eosio_assert(h.env(), 0, ptr(0)), "no message");
    assert_error(eosio_assert(h.env(), 0, ptr(END)), "eosio assert failed");
    h.write(END - 2, b"hi");
    assert_error(
        eosio_assert(h.env(), 0, ptr(END - 2)),
        "eosio assert failed: hi",
    );
    assert_error(
        pulse_assert(h.env(), 0, ptr(OUT), 5),
        "pulse assert failed: hello",
    );
    assert_error(pulse_assert(h.env(), 0, ptr(OUT), 0), "no message");
    h.write(OUT, &[0xff]);
    assert_eq!(
        pulse_assert(h.env(), 0, ptr(OUT), 1).unwrap_err().message(),
        "pulse assert failed"
    );
    h.write(OUT, &vec![b'a'; 1025]);
    assert_eq!(
        pulse_assert_message(h.env(), 0, ptr(OUT), 1025)
            .unwrap_err()
            .message(),
        format!("assertion failure with message: {}", "a".repeat(1024))
    );
    assert!(pulse_assert_message(h.env(), 0, ptr(END - 1024), 1025).is_err());
    assert_error(
        pulse_assert_code(h.env(), 0, u64::MAX),
        "18446744073709551615",
    );
    assert_error(abort(h.env()), "abort called");
    let exit = pulse_exit(h.env(), 17).unwrap_err();
    assert_eq!(
        exit.downcast_ref::<crate::wasm_runtime::WasmExit>()
            .unwrap()
            .code,
        17
    );
}
