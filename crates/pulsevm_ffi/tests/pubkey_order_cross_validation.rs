//! Cross-validate the pure-Rust public-key ordering used by Authority::validate
//! (strictly-ascending `keys`) against the C++ `public_key_type::cmp` reached
//! through the bridge. The salvaged native Authority compares keys by their
//! 34-byte packed form as unsigned bytes; this proves that matches C++ so the
//! consensus sort check does not diverge.
//!
//! Run with the C++ toolchain env and the arena-shadow feature:
//!   cargo test -p pulsevm_ffi --features arena-shadow \
//!     --test pubkey_order_cross_validation

use pulsevm_crypto::k1::K1PrivateKey;

/// The native ordering the salvaged Authority uses.
fn native_cmp(a: &[u8; 34], b: &[u8; 34]) -> i32 {
    match a.cmp(b) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

#[test]
fn native_pubkey_order_matches_cxx() {
    // Deterministic spread of keys from fixed seeds (no rng dependency in the
    // test); seed strings vary the scalar so packed bytes cover the high-bit
    // range that a signed/unsigned mismatch would expose.
    let keys: Vec<[u8; 34]> = (0u32..200)
        .map(|i| {
            let sk =
                K1PrivateKey::from_seed_string(&format!("order-check-seed-{i}")).expect("seed key");
            sk.public_key().to_packed()
        })
        .collect();

    let mut checked = 0u64;
    for a in &keys {
        for b in &keys {
            let native = native_cmp(a, b);

            let ca = pulsevm_ffi::parse_public_key_from_bytes(a).expect("parse a");
            let cb = pulsevm_ffi::parse_public_key_from_bytes(b).expect("parse b");
            let cxx = ca.cmp(&cb).signum();

            assert_eq!(
                native, cxx,
                "ordering mismatch: native={native} cxx={cxx}\n a={a:02x?}\n b={b:02x?}"
            );
            checked += 1;
        }
    }
    println!("pubkey ordering: {checked} pairs, native == cxx");
}
