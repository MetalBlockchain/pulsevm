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
fn mod_exp_uses_activated_crypto_primitives_and_checks_output_capacity() {
    let mut h = Host::new(false);
    h.write(10, &[5]);
    h.write(20, &[3]);
    h.write(30, &[13]);
    h.write(OUT, &[0xa5; 2]);

    h.budget(cost::mod_exp(1, 1, 1));
    assert!(mod_exp(h.env(), ptr(10), 1, ptr(20), 1, ptr(30), 1, ptr(OUT), 2,).is_err());

    h.db.preactivate_protocol_feature(CRYPTO_PRIMITIVES_FEATURE_DIGEST)
        .unwrap();
    h.db.activate_protocol_features(&[CRYPTO_PRIMITIVES_FEATURE_DIGEST], 2)
        .unwrap();
    h.budget(cost::mod_exp(1, 1, 1));
    assert_eq!(
        mod_exp(h.env(), ptr(10), 1, ptr(20), 1, ptr(30), 1, ptr(OUT), 2,).unwrap(),
        0
    );
    assert_eq!(h.read(OUT, 2), [8, 0xa5]);
    assert_eq!(h.remaining(), 0);

    h.write(OUT, &[0xa5]);
    h.budget(cost::mod_exp(1, 1, 1));
    assert_eq!(
        mod_exp(h.env(), ptr(10), 1, ptr(20), 1, ptr(30), 1, ptr(OUT), 0,).unwrap(),
        1
    );
    assert_eq!(h.read(OUT, 1), [0xa5]);

    h.write(30, &[0]);
    h.budget(cost::mod_exp(1, 1, 1));
    assert_eq!(
        mod_exp(h.env(), ptr(10), 1, ptr(20), 1, ptr(30), 1, ptr(OUT), 1,).unwrap(),
        0
    );
    assert_eq!(h.read(OUT, 1), [0]);

    // Results retain the modulus width, including leading zero bytes.
    h.write(10, &[2]);
    h.write(20, &[5]);
    h.write(30, &[3, 232]);
    h.write(OUT, &[0xa5; 2]);
    h.budget(cost::mod_exp(1, 1, 2));
    assert_eq!(
        mod_exp(h.env(), ptr(10), 1, ptr(20), 1, ptr(30), 2, ptr(OUT), 2,).unwrap(),
        0
    );
    assert_eq!(h.read(OUT, 2), [0, 32]);

    h.budget(u64::MAX);
    assert!(
        mod_exp(
            h.env(),
            ptr(END - 1),
            2,
            ptr(20),
            1,
            ptr(30),
            1,
            ptr(OUT),
            1,
        )
        .is_err()
    );
}

#[test]
fn alt_bn128_mul_uses_activated_crypto_primitives_and_matches_antelope_vector() {
    let mut h = Host::new(false);
    let point = hex::decode(concat!(
        "007c43fcd125b2b13e2521e395a81727710a46b34fe279adbf1b94c72f7f9136",
        "0db2f980370fb8962751c6ff064f4516a6a93d563388518bb77ab9a6b30755be"
    ))
    .unwrap();
    let scalar =
        hex::decode("0312ed43559cf8ecbab5221256a56e567aac5035308e3f1d54954d8b97cd1c9b").unwrap();
    let expected = hex::decode(concat!(
        "2d66cdeca5e1715896a5a924c50a149be87ddd2347b862150fbb0fd7d0b1833c",
        "11c76319ebefc5379f7aa6d85d40169a612597637242a4bbb39e5cd3b844becd"
    ))
    .unwrap();
    h.write(10, &point);
    h.write(80, &scalar);
    h.write(OUT, &[0xa5; 65]);

    h.budget(cost::ALT_BN128_MUL);
    assert!(alt_bn128_mul(h.env(), ptr(10), 64, ptr(80), 32, ptr(OUT), 64).is_err());

    h.db.preactivate_protocol_feature(CRYPTO_PRIMITIVES_FEATURE_DIGEST)
        .unwrap();
    h.db.activate_protocol_features(&[CRYPTO_PRIMITIVES_FEATURE_DIGEST], 2)
        .unwrap();
    h.budget(cost::ALT_BN128_MUL);
    assert_eq!(
        alt_bn128_mul(h.env(), ptr(10), 64, ptr(80), 32, ptr(OUT), 65).unwrap(),
        0
    );
    assert_eq!(h.read(OUT, 64), expected);
    assert_eq!(h.read(OUT + 64, 1), [0xa5]);
    assert_eq!(h.remaining(), 0);

    // Invalid lengths and off-curve points return Antelope's failure value
    // without changing guest memory.
    h.write(OUT, &[0xa5; 64]);
    h.write(10, &[0; 64]);
    h.budget(cost::ALT_BN128_MUL);
    assert_eq!(
        alt_bn128_mul(h.env(), ptr(10), 63, ptr(80), 32, ptr(OUT), 64).unwrap(),
        1
    );
    assert_eq!(h.read(OUT, 64), [0xa5; 64]);
    h.write(10, &[0; 64]);
    // (0, 0) is Antelope's identity encoding and scalar multiplication keeps it.
    h.budget(cost::ALT_BN128_MUL);
    assert_eq!(
        alt_bn128_mul(h.env(), ptr(10), 64, ptr(80), 32, ptr(OUT), 64).unwrap(),
        0
    );
    assert_eq!(h.read(OUT, 64), [0; 64]);

    h.write(10, &[0; 64]);
    h.write(10, &[1; 64]);
    h.write(OUT, &[0xa5; 64]);
    h.budget(cost::ALT_BN128_MUL);
    assert_eq!(
        alt_bn128_mul(h.env(), ptr(10), 64, ptr(80), 32, ptr(OUT), 64).unwrap(),
        1
    );
    assert_eq!(h.read(OUT, 64), [0xa5; 64]);

    h.write(10, &point);
    h.budget(u64::MAX);
    assert_eq!(
        alt_bn128_mul(h.env(), ptr(10), 64, ptr(80), 32, ptr(OUT), 63).unwrap(),
        1
    );
    assert!(alt_bn128_mul(h.env(), ptr(END - 63), 64, ptr(80), 32, ptr(OUT), 64).is_err());
}

#[test]
fn alt_bn128_add_uses_activated_crypto_primitives_and_matches_antelope_vector() {
    let mut h = Host::new(false);
    let lhs = hex::decode(concat!(
        "222480c9f95409bfa4ac6ae890b9c150bc88542b87b352e92950c340458b0c09",
        "2976efd698cf23b414ea622b3f720dd9080d679042482ff3668cb2e32cad8ae2"
    ))
    .unwrap();
    let rhs = hex::decode(concat!(
        "1bd20beca3d8d28e536d2b5bd3bf36d76af68af5e6c96ca6e5519ba9ff8f5332",
        "2a53edf6b48bcf5cb1c0b4ad1d36dfce06a79dcd6526f1c386a14d8ce4649844"
    ))
    .unwrap();
    let expected = hex::decode(concat!(
        "16c7c4042e3a725ddbacf197c519c3dcad2bc87dfd9ac7e1e1631154ee0b7d9c",
        "19cd640dd28c9811ebaaa095a16b16190d08d6906c4f926fce581985fe35be0e"
    ))
    .unwrap();
    h.write(10, &lhs);
    h.write(80, &rhs);
    h.write(OUT, &[0xa5; 65]);

    h.budget(cost::ALT_BN128_ADD);
    assert!(alt_bn128_add(h.env(), ptr(10), 64, ptr(80), 64, ptr(OUT), 64).is_err());

    h.db.preactivate_protocol_feature(CRYPTO_PRIMITIVES_FEATURE_DIGEST)
        .unwrap();
    h.db.activate_protocol_features(&[CRYPTO_PRIMITIVES_FEATURE_DIGEST], 2)
        .unwrap();
    h.budget(cost::ALT_BN128_ADD);
    assert_eq!(
        alt_bn128_add(h.env(), ptr(10), 64, ptr(80), 64, ptr(OUT), 65).unwrap(),
        0
    );
    assert_eq!(h.read(OUT, 64), expected);
    assert_eq!(h.read(OUT + 64, 1), [0xa5]);
    assert_eq!(h.remaining(), 0);

    // The identity point is encoded as (0, 0); adding it preserves the point.
    h.write(10, &[0; 64]);
    h.budget(cost::ALT_BN128_ADD);
    assert_eq!(
        alt_bn128_add(h.env(), ptr(10), 64, ptr(80), 64, ptr(OUT), 64).unwrap(),
        0
    );
    assert_eq!(h.read(OUT, 64), rhs);

    h.write(10, &[1; 64]);
    h.write(OUT, &[0xa5; 64]);
    h.budget(cost::ALT_BN128_ADD);
    assert_eq!(
        alt_bn128_add(h.env(), ptr(10), 64, ptr(80), 64, ptr(OUT), 64).unwrap(),
        1
    );
    assert_eq!(h.read(OUT, 64), [0xa5; 64]);
    h.budget(u64::MAX);
    assert_eq!(
        alt_bn128_add(h.env(), ptr(10), 64, ptr(80), 64, ptr(OUT), 63).unwrap(),
        1
    );
    assert!(alt_bn128_add(h.env(), ptr(END - 63), 64, ptr(80), 64, ptr(OUT), 64).is_err());
}

#[test]
fn alt_bn128_pair_uses_activated_crypto_primitives_and_matches_antelope_vectors() {
    let mut h = Host::new(false);
    // Standard generator pair: a single pairing is not one.
    let single = hex::decode(concat!(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
        "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
        "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
        "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"
    ))
    .unwrap();
    // Leap's two-pair vector whose product pairing is one.
    let paired = hex::decode(concat!(
        "0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd2",
        "16da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba",
        "2e89718ad33c8bed92e210e81d1853435399a271913a6520736a4729cf0d51eb",
        "01a9e2ffa2e92599b68e44de5bcf354fa2642bd4f26b259daa6f7ce3ed57aeb3",
        "14a9a87b789a58af499b314e13c3d65bede56c07ea2d418d6874857b70763713",
        "178fb49a2d6cd347dc58973ff49613a20757d0fcc22079f9abd10c3baee24590",
        "1b9e027bd5cfc2cb5db82d4dc9677ac795ec500ecd47deee3b5da006d6d049b8",
        "11d7511c78158de484232fc68daf8a45cf217d1c2fae693ff5871e8752d73b21",
        "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
        "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
        "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
        "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"
    ))
    .unwrap();
    h.write(10, &single);
    h.write(10 + single.len() as u32, &paired);

    h.budget(cost::alt_bn128_pair(192));
    assert!(alt_bn128_pair(h.env(), ptr(10), 192).is_err());

    h.db.preactivate_protocol_feature(CRYPTO_PRIMITIVES_FEATURE_DIGEST)
        .unwrap();
    h.db.activate_protocol_features(&[CRYPTO_PRIMITIVES_FEATURE_DIGEST], 2)
        .unwrap();
    h.budget(cost::alt_bn128_pair(192));
    assert_eq!(alt_bn128_pair(h.env(), ptr(10), 192).unwrap(), 1);
    assert_eq!(h.remaining(), 0);

    h.budget(cost::alt_bn128_pair(paired.len() as u64));
    assert_eq!(
        alt_bn128_pair(h.env(), ptr(10 + single.len() as u32), paired.len() as u32).unwrap(),
        0
    );
    assert_eq!(h.remaining(), 0);

    h.budget(cost::alt_bn128_pair(0));
    assert_eq!(alt_bn128_pair(h.env(), ptr(10), 0).unwrap(), 0);
    h.budget(cost::alt_bn128_pair(191));
    assert_eq!(alt_bn128_pair(h.env(), ptr(10), 191).unwrap(), 1);

    h.write(10, &[1; 192]);
    h.budget(cost::alt_bn128_pair(192));
    assert_eq!(alt_bn128_pair(h.env(), ptr(10), 192).unwrap(), 1);
    h.budget(u64::MAX);
    assert!(alt_bn128_pair(h.env(), ptr(END - 191), 192).is_err());
}

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
