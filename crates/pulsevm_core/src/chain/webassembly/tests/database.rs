use super::*;

#[test]
fn primary_table_lifecycle_and_iterator_boundaries() {
    let mut h = Host::new(false);
    let code = PULSE_NAME.as_u64();
    assert_eq!(db_find_i64(h.env(), code, 7, 8, 11).unwrap(), -1);
    assert_eq!(db_end_i64(h.env(), code, 7, 8).unwrap(), -1);
    h.write(OUT, b"first");
    let a = db_store_i64(h.env(), 7, 8, code, 11, ptr(OUT), 5).unwrap();
    h.write(OUT, b"second");
    let b = db_store_i64(h.env(), 7, 8, code, 22, ptr(OUT), 6).unwrap();
    let end = db_end_i64(h.env(), code, 7, 8).unwrap();
    assert!(end < -1);
    assert_eq!(db_find_i64(h.env(), code, 7, 8, 11).unwrap(), a);
    assert_eq!(db_find_i64(h.env(), code, 7, 8, 33).unwrap(), end);
    assert_eq!(db_lowerbound_i64(h.env(), code, 7, 8, 11).unwrap(), a);
    assert_eq!(db_upperbound_i64(h.env(), code, 7, 8, 11).unwrap(), b);
    assert_eq!(db_next_i64(h.env(), a, ptr(OUT)).unwrap(), b);
    assert_eq!(h.read(OUT, 8), 22u64.to_le_bytes());
    assert_eq!(db_next_i64(h.env(), b, ptr(OUT)).unwrap(), end);
    assert_eq!(db_previous_i64(h.env(), end, ptr(OUT)).unwrap(), b);
    assert_eq!(db_previous_i64(h.env(), a, ptr(OUT)).unwrap(), -1);
    assert_eq!(db_get_i64(h.env(), a, ptr(OUT), 0).unwrap(), 5);
    assert_eq!(db_get_i64(h.env(), a, ptr(OUT), 3).unwrap(), 3);
    assert_eq!(h.read(OUT, 3), b"fir");
    h.write(OUT, b"updated");
    db_update_i64(h.env(), a, 0, ptr(OUT), 7).unwrap();
    assert_eq!(db_get_i64(h.env(), a, ptr(OUT), 7).unwrap(), 7);
    assert_eq!(h.read(OUT, 7), b"updated");
    assert!(db_store_i64(h.env(), 7, 8, code, 33, ptr(END - 1), 2).is_err());
    assert!(db_update_i64(h.env(), a, 0, ptr(END - 1), 2).is_err());
    assert!(db_get_i64(h.env(), a, ptr(END - 1), 2).is_err());
    db_remove_i64(h.env(), a).unwrap();
    assert_eq!(db_find_i64(h.env(), code, 7, 8, 11).unwrap(), end);
    assert!(db_get_i64(h.env(), a, ptr(OUT), 7).is_err());
    db_remove_i64(h.env(), b).unwrap();
}

// Every secondary family shares the same observable iterator protocol but has
// its own host wrapper and key encoding. Exercise the wrappers, not just the DB.
macro_rules! secondary_test {
    ($test:ident, $a:expr, $b:expr, [$store:ident, $update:ident, $remove:ident, $find_secondary:ident, $find_primary:ident, $lower:ident, $upper:ident, $end:ident, $next:ident, $previous:ident] $(, $len:expr)?) => {
        #[test]
        fn $test() {
            let mut h = Host::new(false);
            let code = PULSE_NAME.as_u64();
            let key_a = $a;
            let key_b = $b;
            h.write(OUT, &key_a);
            h.write(1025, &99u64.to_le_bytes());
            assert_eq!($end(h.env(), code, 7, 8).unwrap(), -1);
            assert_eq!($find_secondary(h.env(), code, 7, 8, ptr(OUT), $($len,)? ptr(1025)).unwrap(), -1);
            assert_eq!(h.read(1025, 8), 99u64.to_le_bytes());
            let a = $store(h.env(), 7, 8, code, 11, ptr(OUT) $(, $len)?).unwrap();
            h.write(OUT, &key_b);
            let b = $store(h.env(), 7, 8, code, 22, ptr(OUT) $(, $len)?).unwrap();
            let end = $end(h.env(), code, 7, 8).unwrap();
            assert!(end < -1);
            h.write(OUT, &key_a);
            assert_eq!($find_secondary(h.env(), code, 7, 8, ptr(OUT), $($len,)? ptr(1025)).unwrap(), a);
            assert_eq!(h.read(1025, 8), 11u64.to_le_bytes());
            assert_eq!($find_primary(h.env(), code, 7, 8, ptr(OUT), $($len,)? 22).unwrap(), b);
            assert_eq!(h.read(OUT, key_b.len()), key_b);
            h.write(OUT, &key_a);
            assert_eq!($lower(h.env(), code, 7, 8, ptr(OUT), $($len,)? ptr(1025)).unwrap(), a);
            assert_eq!(h.read(1025, 8), 11u64.to_le_bytes());
            assert_eq!($upper(h.env(), code, 7, 8, ptr(OUT), $($len,)? ptr(1025)).unwrap(), b);
            assert_eq!(h.read(OUT, key_b.len()), key_b);
            assert_eq!(h.read(1025, 8), 22u64.to_le_bytes());
            assert_eq!($next(h.env(), a, ptr(1025)).unwrap(), b);
            assert_eq!($next(h.env(), b, ptr(1025)).unwrap(), end);
            assert_eq!($previous(h.env(), end, ptr(1025)).unwrap(), b);
            assert_eq!($previous(h.env(), a, ptr(1025)).unwrap(), -1);
            h.write(OUT, &key_b);
            $update(h.env(), a, code, ptr(OUT) $(, $len)?).unwrap();
            assert_eq!($find_secondary(h.env(), code, 7, 8, ptr(OUT), $($len,)? ptr(1025)).unwrap(), a);
            assert_eq!(h.read(1025, 8), 11u64.to_le_bytes());
            assert!($store(h.env(), 7, 8, code, 33, ptr(END - 1) $(, $len)?).is_err());
            assert!($update(h.env(), a, code, ptr(END - 1) $(, $len)?).is_err());
            $remove(h.env(), a).unwrap();
            assert_eq!($find_secondary(h.env(), code, 7, 8, ptr(OUT), $($len,)? ptr(1025)).unwrap(), b);
            $remove(h.env(), b).unwrap();
            let mut cf = Host::new(true);
            assert_error($store(cf.env(), 7, 8, code, 11, ptr(OUT) $(, $len)?), "context-free action");
        }
    };
}

secondary_test!(
    idx64_lifecycle,
    10u64.to_le_bytes(),
    20u64.to_le_bytes(),
    [
        db_idx64_store,
        db_idx64_update,
        db_idx64_remove,
        db_idx64_find_secondary,
        db_idx64_find_primary,
        db_idx64_lowerbound,
        db_idx64_upperbound,
        db_idx64_end,
        db_idx64_next,
        db_idx64_previous
    ]
);
secondary_test!(
    idx128_lifecycle,
    10u128.to_le_bytes(),
    20u128.to_le_bytes(),
    [
        db_idx128_store,
        db_idx128_update,
        db_idx128_remove,
        db_idx128_find_secondary,
        db_idx128_find_primary,
        db_idx128_lowerbound,
        db_idx128_upperbound,
        db_idx128_end,
        db_idx128_next,
        db_idx128_previous
    ]
);
secondary_test!(
    idx256_lifecycle,
    [0x10; 32],
    [0x20; 32],
    [
        db_idx256_store,
        db_idx256_update,
        db_idx256_remove,
        db_idx256_find_secondary,
        db_idx256_find_primary,
        db_idx256_lowerbound,
        db_idx256_upperbound,
        db_idx256_end,
        db_idx256_next,
        db_idx256_previous
    ],
    2
);
secondary_test!(
    idx_double_lifecycle,
    1.0f64.to_bits().to_le_bytes(),
    2.0f64.to_bits().to_le_bytes(),
    [
        db_idx_double_store,
        db_idx_double_update,
        db_idx_double_remove,
        db_idx_double_find_secondary,
        db_idx_double_find_primary,
        db_idx_double_lowerbound,
        db_idx_double_upperbound,
        db_idx_double_end,
        db_idx_double_next,
        db_idx_double_previous
    ]
);
secondary_test!(
    idx_long_double_lifecycle,
    0x3fff0000000000000000000000000000u128.to_le_bytes(),
    0x40000000000000000000000000000000u128.to_le_bytes(),
    [
        db_idx_long_double_store,
        db_idx_long_double_update,
        db_idx_long_double_remove,
        db_idx_long_double_find_secondary,
        db_idx_long_double_find_primary,
        db_idx_long_double_lowerbound,
        db_idx_long_double_upperbound,
        db_idx_long_double_end,
        db_idx_long_double_next,
        db_idx_long_double_previous
    ]
);
