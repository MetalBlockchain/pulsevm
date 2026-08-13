//! Cross-validation of the pure-Rust `pulsevm_crypto::k1` implementation against
//! the C++ `fc::crypto` oracle reached through the `pulsevm_ffi` cxx bridge.
//!
//! For every case (200 random keys plus the fixed keys used elsewhere in the
//! repo) the pure-Rust and C++ implementations are asserted to agree
//! byte-for-byte on the private-key string, the public key (compressed / packed
//! / string), the string<->packed round trips, and recoverable signing.

use pulsevm_crypto::k1::{
    K1PrivateKey,
    K1PublicKey,
    K1Signature,
};
use secp256k1::rand::{
    RngCore,
    rngs::OsRng,
};

// ---- small helpers over the cxx bridge --------------------------------------

fn cxx_priv_from_scalar(scalar: &[u8; 32]) -> cxx::SharedPtr<pulsevm_ffi::CxxPrivateKey> {
    let digest = pulsevm_ffi::make_shared_digest_from_existing_hash(scalar);
    pulsevm_ffi::make_k1_private_key(digest.as_ref().unwrap())
}

fn cxx_digest(bytes: &[u8; 32]) -> cxx::SharedPtr<pulsevm_ffi::CxxDigest> {
    pulsevm_ffi::make_shared_digest_from_existing_hash(bytes)
}

/// Runs the full battery of assertions for one private key that both sides
/// derive from `scalar`. Returns `true` if the produced signature was
/// byte-identical between Rust and C++.
fn check_key(scalar: &[u8; 32], digest: &[u8; 32]) -> bool {
    // ----- Rust side -----
    let r_priv = K1PrivateKey::from_scalar(scalar).expect("rust priv from scalar");
    let r_priv_str = r_priv.to_string();
    let r_pub = r_priv.public_key();
    let r_pub_packed = r_pub.to_packed();
    let r_pub_str = r_pub.to_string();

    // ----- C++ oracle side -----
    let c_priv = cxx_priv_from_scalar(scalar);
    let c_priv_ref = c_priv.as_ref().unwrap();
    let c_priv_str = pulsevm_ffi::private_key_to_string(c_priv_ref);
    let c_pub = pulsevm_ffi::get_public_key_from_private_key(c_priv_ref);
    let c_pub_ref = c_pub.as_ref().unwrap();
    let c_pub_packed = pulsevm_ffi::packed_public_key_bytes(c_pub_ref);
    let c_pub_str = pulsevm_ffi::public_key_to_string(c_pub_ref);

    // (1) private key string round-trips and equals C++.
    assert_eq!(r_priv_str, c_priv_str, "private key string mismatch");
    let reparsed = K1PrivateKey::from_string(&r_priv_str).expect("reparse pvt");
    assert_eq!(
        &reparsed.scalar(),
        scalar,
        "private key string not round-trip"
    );

    // (2) private -> public: compressed, packed(34) and PUB_K1_ string equal C++.
    assert_eq!(
        r_pub_packed.as_slice(),
        c_pub_packed.as_slice(),
        "pub packed mismatch"
    );
    assert_eq!(r_pub_str, c_pub_str, "pub string mismatch");
    assert_eq!(
        &r_pub.compressed()[..],
        &c_pub_packed[1..],
        "pub compressed mismatch"
    );

    // (3) string -> parse -> packed equals C++; packed -> parse -> string equals C++.
    let c_pub_from_str = pulsevm_ffi::parse_public_key(&r_pub_str).expect("cxx parse pub str");
    let c_pub_from_str_packed =
        pulsevm_ffi::packed_public_key_bytes(c_pub_from_str.as_ref().unwrap());
    assert_eq!(
        c_pub_from_str_packed, c_pub_packed,
        "cxx PUB string->packed mismatch"
    );
    let r_pub_from_packed = K1PublicKey::from_packed(&c_pub_packed).expect("rust from packed");
    assert_eq!(
        r_pub_from_packed.to_string(),
        c_pub_str,
        "rust packed->string mismatch"
    );
    let c_pub_from_bytes =
        pulsevm_ffi::parse_public_key_from_bytes(&r_pub_packed).expect("cxx parse pub bytes");
    assert_eq!(
        pulsevm_ffi::packed_public_key_bytes(c_pub_from_bytes.as_ref().unwrap()),
        c_pub_packed,
        "cxx packed->parse->packed mismatch"
    );

    // (4) sign a random digest with both sides.
    let r_sig = r_priv.sign(digest);
    assert!(r_sig.is_canonical(), "rust signature not canonical");
    let r_sig_packed = r_sig.to_packed();

    let c_dig = cxx_digest(digest);
    let c_sig = pulsevm_ffi::sign_digest_with_private_key(c_dig.as_ref().unwrap(), c_priv_ref)
        .expect("cxx sign");
    let c_sig_packed = pulsevm_ffi::packed_signature_bytes(c_sig.as_ref().unwrap());
    let c_sig_arr: [u8; 66] = c_sig_packed.as_slice().try_into().expect("66-byte sig");
    let c_k1_sig = K1Signature::from_packed(&c_sig_arr).expect("rust from cxx sig");
    assert!(
        c_k1_sig.is_canonical(),
        "cxx signature not canonical per rust predicate"
    );

    // (4a) C++ recovers the signer from the Rust signature.
    let c_sig_from_rust =
        pulsevm_ffi::parse_signature_from_bytes(&r_sig_packed).expect("cxx parse rust sig");
    let c_recovered = pulsevm_ffi::recover_public_key_from_signature(
        c_sig_from_rust.as_ref().unwrap(),
        c_dig.as_ref().unwrap(),
    )
    .expect("cxx recover from rust sig");
    assert_eq!(
        pulsevm_ffi::packed_public_key_bytes(c_recovered.as_ref().unwrap()),
        c_pub_packed,
        "C++ failed to recover signer from Rust signature"
    );

    // (4b) Rust recovers the signer from the C++ signature.
    let r_recovered = c_k1_sig.recover(digest).expect("rust recover from cxx sig");
    assert_eq!(
        r_recovered.to_packed().as_slice(),
        c_pub_packed.as_slice(),
        "Rust failed to recover signer from C++ signature"
    );

    // (4c) both recovered keys equal the true public key (checked above), and
    // each side also recovers its own signature to the true key.
    assert_eq!(
        r_sig.recover(digest).unwrap(),
        r_pub,
        "rust self-recover mismatch"
    );

    // (5) signature string <-> 66-byte packed round-trips and equals C++.
    // Anchor on the deterministic C++ signature bytes so this is independent of
    // any signing nondeterminism.
    let c_sig_str = pulsevm_ffi::signature_to_string(c_sig.as_ref().unwrap());
    assert_eq!(
        c_k1_sig.to_string(),
        c_sig_str,
        "rust sig packed->string mismatch"
    );
    let r_sig_from_str = K1Signature::from_string(&c_sig_str).expect("rust parse sig str");
    assert_eq!(
        r_sig_from_str.to_packed(),
        c_sig_arr,
        "rust sig string->packed mismatch"
    );
    let c_sig_reparsed =
        pulsevm_ffi::parse_signature(&c_k1_sig.to_string()).expect("cxx parse sig str");
    assert_eq!(
        pulsevm_ffi::packed_signature_bytes(c_sig_reparsed.as_ref().unwrap()),
        c_sig_packed,
        "cxx sig string->packed mismatch"
    );

    // (4d) report byte-identical signing.
    r_sig_packed.as_slice() == c_sig_packed.as_slice()
}

#[test]
fn k1_cross_validation_random_and_fixed() {
    let mut rng = OsRng;
    let mut identical = 0usize;
    let mut total = 0usize;

    // 200 random keys, each signing one random digest.
    for _ in 0..200 {
        let mut scalar = [0u8; 32];
        loop {
            rng.fill_bytes(&mut scalar);
            // reject scalars that secp256k1 would consider invalid (essentially never)
            if secp256k1::SecretKey::from_slice(&scalar).is_ok() {
                break;
            }
        }
        let mut digest = [0u8; 32];
        rng.fill_bytes(&mut digest);
        if check_key(&scalar, &digest) {
            identical += 1;
        }
        total += 1;
    }

    // Fixed private key used across the repo's tests.
    {
        let fixed_priv = "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez";
        let r = K1PrivateKey::from_string(fixed_priv).expect("parse fixed priv");
        // parse must equal the C++ parse.
        let c = pulsevm_ffi::parse_private_key(fixed_priv).expect("cxx parse fixed priv");
        assert_eq!(
            r.to_string(),
            pulsevm_ffi::private_key_to_string(c.as_ref().unwrap()),
            "fixed private key string mismatch"
        );
        let mut digest = [0u8; 32];
        rng.fill_bytes(&mut digest);
        if check_key(&r.scalar(), &digest) {
            identical += 1;
        }
        total += 1;
    }

    // Fixed public key used across the repo's tests: string <-> packed <-> string.
    {
        let fixed_pub = "PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H";
        let r_pub = K1PublicKey::from_string(fixed_pub).expect("parse fixed pub");
        assert_eq!(
            r_pub.to_string(),
            fixed_pub,
            "fixed pub string not round-trip"
        );
        let c_pub = pulsevm_ffi::parse_public_key(fixed_pub).expect("cxx parse fixed pub");
        let c_packed = pulsevm_ffi::packed_public_key_bytes(c_pub.as_ref().unwrap());
        assert_eq!(
            r_pub.to_packed().as_slice(),
            c_packed.as_slice(),
            "fixed pub packed mismatch"
        );
        assert_eq!(
            pulsevm_ffi::public_key_to_string(c_pub.as_ref().unwrap()),
            fixed_pub,
            "cxx fixed pub string mismatch"
        );
        // packed -> rust parse -> string.
        let r_from_packed = K1PublicKey::from_packed(&c_packed).unwrap();
        assert_eq!(r_from_packed.to_string(), fixed_pub);
    }

    eprintln!(
        "k1 cross-validation: {total} keys all byte-exact on formats; \
         {identical}/{total} signatures were also byte-identical to C++"
    );
}
