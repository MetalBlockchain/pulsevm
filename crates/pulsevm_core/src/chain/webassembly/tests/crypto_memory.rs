use super::*;

type Hash =
    fn(FunctionEnvMut<WasmContext>, WasmPtr<u8>, u32, WasmPtr<u8>) -> Result<(), RuntimeError>;

macro_rules! hash_test {
    ($test:ident, $hash:ident, $assert:ident, $price:expr, $expected:literal) => {
        #[test]
        fn $test() {
            let mut h = Host::new(false);
            let expected = hex::decode($expected).unwrap();
            h.write(11, b"abc");
            h.write(OUT - 1, &vec![0xa5; expected.len() + 2]);
            h.budget($price);
            $hash(h.env(), ptr(11), 3, ptr(OUT)).unwrap();
            assert_eq!(h.read(OUT, expected.len()), expected);
            assert_eq!(h.read(OUT - 1, 1), [0xa5]);
            assert_eq!(h.read(OUT + expected.len() as u32, 1), [0xa5]);
            assert_eq!(h.remaining(), 0);
            h.budget($price);
            $assert(h.env(), ptr(11), 3, ptr(OUT)).unwrap();
            assert_eq!(h.remaining(), 0);
            h.budget(u64::MAX);
            h.write(OUT, &[0]);
            assert!($assert(h.env(), ptr(11), 3, ptr(OUT)).is_err());
            for op in [$hash as Hash, $assert as Hash] {
                assert!(op(h.env(), ptr(END - 2), 3, ptr(OUT)).is_err());
                assert!(op(h.env(), ptr(11), 3, ptr(END - 1)).is_err());
                assert!(op(h.env(), ptr(11), u32::MAX, ptr(OUT)).is_err());
                h.write(OUT, &vec![0xa5; expected.len()]);
                h.budget($price - 1);
                assert!(op(h.env(), ptr(11), 3, ptr(OUT)).is_err());
                assert_eq!(h.remaining(), 0);
                assert_eq!(h.read(OUT, expected.len()), vec![0xa5; expected.len()]);
                h.budget(u64::MAX);
            }
        }
    };
}

hash_test!(
    sha1_known_vector_and_bounds,
    sha1,
    assert_sha1,
    cost::sha1(3),
    "a9993e364706816aba3e25717850c26c9cd0d89d"
);
hash_test!(
    sha224_known_vector_and_bounds,
    sha224,
    assert_sha224,
    cost::sha256(3),
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
);
hash_test!(
    sha256_known_vector_and_bounds,
    sha256,
    assert_sha256,
    cost::sha256(3),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
);
hash_test!(
    sha512_known_vector_and_bounds,
    sha512,
    assert_sha512,
    cost::sha512(3),
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
);
hash_test!(
    ripemd160_known_vector_and_bounds,
    ripemd160,
    assert_ripemd160,
    cost::ripemd160(3),
    "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
);

#[test]
fn key_recovery_checks_packing_truncation_mismatch_and_malformed_input() {
    let mut h = Host::new(false);
    let digest = Digest::hash(b"host-recovery-test");
    let signature = h.key.sign(&digest).unwrap().pack().unwrap();
    let key = AuthorityPublicKey::from(h.key.get_public_key().into_k1())
        .pack()
        .unwrap();
    h.write(0, digest.as_bytes());
    h.write(64, &signature);
    h.write(256, &key);
    h.budget(cost::RECOVER_KEY);
    assert_recover_key(
        h.env(),
        ptr(0),
        ptr(64),
        signature.len() as u32,
        ptr(256),
        key.len() as u32,
    )
    .unwrap();
    assert_eq!(h.remaining(), 0);
    for size in [
        0,
        1,
        key.len() as u32 - 1,
        key.len() as u32,
        key.len() as u32 + 1,
    ] {
        h.budget(cost::RECOVER_KEY);
        h.write(OUT, &[0xa5; 64]);
        assert_eq!(
            recover_key(
                h.env(),
                ptr(0),
                ptr(64),
                signature.len() as u32,
                ptr(OUT),
                size
            )
            .unwrap(),
            key.len() as i32
        );
        let copied = (size as usize).min(key.len());
        assert_eq!(h.read(OUT, copied), key[..copied]);
        assert_eq!(h.read(OUT + copied as u32, 1), [0xa5]);
        assert_eq!(h.remaining(), 0);
    }
    h.budget(u64::MAX);
    let other = AuthorityPublicKey::from(
        PrivateKey::new_k1_from_string("other-test-key")
            .unwrap()
            .get_public_key()
            .into_k1(),
    )
    .pack()
    .unwrap();
    h.write(256, &other);
    assert_error(
        assert_recover_key(
            h.env(),
            ptr(0),
            ptr(64),
            signature.len() as u32,
            ptr(256),
            other.len() as u32,
        ),
        "does not match",
    );
    h.write(256, &[0xff]);
    assert_error(
        assert_recover_key(
            h.env(),
            ptr(0),
            ptr(64),
            signature.len() as u32,
            ptr(256),
            1,
        ),
        "failed to read public key",
    );
    h.write(64, &[0xff]);
    assert_error(
        recover_key(h.env(), ptr(0), ptr(64), 1, ptr(OUT), 34),
        "failed to read signature",
    );
    assert_error(
        assert_recover_key(h.env(), ptr(0), ptr(64), 1, ptr(256), 34),
        "failed to read signature",
    );
    h.write(64, &signature);
    assert!(
        recover_key(
            h.env(),
            ptr(END - 31),
            ptr(64),
            signature.len() as u32,
            ptr(OUT),
            34
        )
        .is_err()
    );
    assert!(
        recover_key(
            h.env(),
            ptr(0),
            ptr(64),
            signature.len() as u32,
            ptr(END - 1),
            34
        )
        .is_err()
    );
}

#[test]
fn memory_copy_move_fill_and_compare_preserve_byte_semantics() {
    let mut h = Host::new(false);
    h.write(10, b"abcdef");
    assert_eq!(memcpy(h.env(), ptr(OUT), ptr(10), 6).unwrap().offset(), OUT);
    assert_eq!(h.read(OUT, 6), b"abcdef");
    assert_eq!(memmove(h.env(), ptr(12), ptr(10), 4).unwrap().offset(), 12);
    assert_eq!(h.read(10, 6), b"ababcd");
    memmove(h.env(), ptr(10), ptr(12), 4).unwrap();
    assert_eq!(h.read(10, 6), b"abcdcd");
    memmove(h.env(), ptr(10), ptr(10), 6).unwrap();
    assert_eq!(h.read(10, 6), b"abcdcd");
    assert_eq!(memset(h.env(), ptr(OUT), 0x1ff, 6).unwrap().offset(), OUT);
    assert_eq!(h.read(OUT, 6), [0xff; 6]);
    assert_eq!(memcmp(h.env(), ptr(OUT), ptr(10), 6).unwrap(), 1);
    assert_eq!(memcmp(h.env(), ptr(10), ptr(OUT), 6).unwrap(), -1);
    assert_eq!(memcmp(h.env(), ptr(10), ptr(10), 6).unwrap(), 0);
    h.budget(0);
    assert_eq!(
        memcpy(h.env(), ptr(u32::MAX), ptr(u32::MAX), 0)
            .unwrap()
            .offset(),
        u32::MAX
    );
    assert_eq!(
        memmove(h.env(), ptr(u32::MAX), ptr(u32::MAX), 0)
            .unwrap()
            .offset(),
        u32::MAX
    );
    assert_eq!(
        memset(h.env(), ptr(u32::MAX), 0, 0).unwrap().offset(),
        u32::MAX
    );
    assert_eq!(memcmp(h.env(), ptr(u32::MAX), ptr(u32::MAX), 0).unwrap(), 0);
}

#[test]
fn memory_rejects_overlap_and_invalid_ranges_before_writes() {
    let mut h = Host::new(false);
    h.write(OUT, &[0xa5; 16]);
    for (dest, src) in [(10, 10), (10, 11), (11, 10)] {
        assert_error(memcpy(h.env(), ptr(dest), ptr(src), 2), "non-aliasing");
    }
    for op in [memcpy, memmove] {
        assert!(op(h.env(), ptr(OUT), ptr(END - 1), 2).is_err());
        assert!(op(h.env(), ptr(END - 1), ptr(OUT), 2).is_err());
        assert_eq!(h.read(OUT, 16), [0xa5; 16]);
        h.budget(cost::memory(2));
        op(h.env(), ptr(OUT), ptr(10), 2).unwrap();
        assert_eq!(h.remaining(), 0);
        h.budget(u64::MAX);
        h.write(OUT, &[0xa5; 16]);
    }
    assert!(memset(h.env(), ptr(END - 1), 0, 2).is_err());
    assert!(memcmp(h.env(), ptr(END - 1), ptr(OUT), 2).is_err());
    assert!(memcmp(h.env(), ptr(OUT), ptr(END - 1), 2).is_err());
    assert!(memmove(h.env(), ptr(OUT), ptr(10), u32::MAX).is_err());
}

#[test]
fn console_intrinsics_charge_even_when_output_is_disabled() {
    let mut h = Host::new(false);
    h.write(OUT, &[0xa5; 16]);
    macro_rules! check {
        ($op:ident($($arg:expr),*), $price:expr) => {
            h.budget($price);
            $op(h.env(), $($arg),*).unwrap();
            assert_eq!(h.remaining(), 0);
            h.budget($price - 1);
            assert!($op(h.env(), $($arg),*).is_err());
            assert_eq!(h.remaining(), 0);
        };
    }
    check!(prints(ptr(OUT)), cost::CONSOLE);
    check!(prints_l(ptr(OUT), 3), cost::CONSOLE + cost::per_byte(3));
    check!(printi(i64::MIN), cost::CONSOLE);
    check!(printui(u64::MAX), cost::CONSOLE);
    check!(printi128(ptr(OUT)), cost::CONSOLE);
    check!(printui128(ptr(OUT)), cost::CONSOLE);
    check!(printsf(-1.5), cost::CONSOLE);
    check!(printdf(1.5), cost::CONSOLE);
    check!(printqf(OUT), cost::CONSOLE);
    check!(printn(PULSE_NAME.as_u64()), cost::CONSOLE);
    check!(printhex(OUT, 3), cost::CONSOLE + cost::per_byte(3));
    assert_eq!(h.read(OUT, 16), [0xa5; 16]);
}
