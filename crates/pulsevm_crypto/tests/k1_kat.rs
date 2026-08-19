//! Known-answer regression test for the pure-Rust `k1` implementation.
//!
//! `k1_kat.txt` was frozen from the C++ `fc::crypto` oracle (see
//! `pulsevm_database/tests/capture_golden_kat.rs`). Each record's identity fields
//! (private/public key strings, packed public key) were asserted equal to C++
//! at capture time, and C++ was made to recover the signer from the frozen
//! (deterministic RFC6979) signature. Replaying it here keeps signing,
//! recovery, the string/packed codecs, and the public-key ordering used by
//! `Authority::validate` pinned after the C++ bridge is gone.
//!
//! Regenerate with `PULSEVM_CAPTURE_KAT=1 cargo test -p pulsevm_database
//! --test capture_golden_kat` while the bridge exists.

use pulsevm_crypto::k1::{
    K1PrivateKey,
    K1PublicKey,
    K1Signature,
};

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex {s:?}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex byte"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[test]
fn k1_matches_frozen_oracle_vectors() {
    let text = include_str!("k1_kat.txt");
    let mut packed_keys: Vec<[u8; 34]> = Vec::new();
    let mut order: Option<Vec<usize>> = None;
    let mut checked = 0u64;

    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("#order") {
            order = Some(
                rest.split_whitespace()
                    .map(|t| t.parse().unwrap())
                    .collect(),
            );
            continue;
        }
        if line.starts_with('#') {
            continue;
        }

        let (lhs, rhs) = line
            .split_once("=>")
            .unwrap_or_else(|| panic!("line {}: no '=>'", lineno + 1));
        let mut l = lhs.split_whitespace();
        let seed = unhex(l.next().expect("seed"));
        let digest_v = unhex(l.next().expect("digest"));
        let mut r = rhs.split_whitespace();
        let priv_str = r.next().expect("priv_str");
        let pub_packed_hex = r.next().expect("pub_packed");
        let pub_str = r.next().expect("pub_str");
        let sig_packed_hex = r.next().expect("sig_packed");

        let scalar: [u8; 32] = seed.as_slice().try_into().expect("32-byte seed");
        let digest: [u8; 32] = digest_v.as_slice().try_into().expect("32-byte digest");

        // private key: derivation, string form, string round-trip.
        let sk = K1PrivateKey::from_scalar(&scalar).expect("priv from scalar");
        assert_eq!(sk.to_string(), priv_str, "line {}: priv str", lineno + 1);
        assert_eq!(
            K1PrivateKey::from_string(priv_str)
                .expect("reparse priv")
                .scalar(),
            scalar,
            "line {}: priv string round-trip",
            lineno + 1
        );

        // public key: packed, string, and both codec directions.
        let pk = sk.public_key();
        assert_eq!(
            hex(&pk.to_packed()),
            pub_packed_hex,
            "line {}: pub packed",
            lineno + 1
        );
        assert_eq!(pk.to_string(), pub_str, "line {}: pub str", lineno + 1);
        let packed = unhex(pub_packed_hex);
        assert_eq!(
            K1PublicKey::from_packed(&packed)
                .expect("from packed")
                .to_string(),
            pub_str,
            "line {}: packed->string",
            lineno + 1
        );
        assert_eq!(
            hex(&K1PublicKey::from_string(pub_str)
                .expect("from string")
                .to_packed()),
            pub_packed_hex,
            "line {}: string->packed",
            lineno + 1
        );

        // signing: deterministic bytes, canonical, recovers the signer, and the
        // signature string codec round-trips.
        let sig = sk.sign(&digest);
        assert!(sig.is_canonical(), "line {}: sig not canonical", lineno + 1);
        assert_eq!(
            hex(&sig.to_packed()),
            sig_packed_hex,
            "line {}: sig packed",
            lineno + 1
        );
        assert_eq!(
            sig.recover(&digest).expect("recover"),
            pk,
            "line {}: recovered signer",
            lineno + 1
        );
        let sig_bytes = unhex(sig_packed_hex);
        let sig2 = K1Signature::from_packed(&sig_bytes).expect("sig from packed");
        assert_eq!(
            K1Signature::from_string(&sig2.to_string())
                .expect("sig from string")
                .to_packed(),
            sig2.to_packed(),
            "line {}: sig string round-trip",
            lineno + 1
        );

        packed_keys.push(pk.to_packed());
        checked += 1;
    }

    assert!(checked > 0, "golden file had no vectors");

    // The native ordering (`Authority::validate`'s strictly-ascending key check)
    // compares the 34-byte packed key as unsigned bytes. It must reproduce the
    // frozen C++ `public_key_type::cmp` order exactly.
    let order = order.expect("golden file missing #order line");
    let mut native: Vec<usize> = (0..packed_keys.len()).collect();
    native.sort_by(|&i, &j| packed_keys[i].cmp(&packed_keys[j]));
    assert_eq!(
        native, order,
        "native packed-bytes order diverges from C++ cmp order"
    );

    eprintln!(
        "k1 KAT: {checked} vectors + {}-key ordering replayed",
        packed_keys.len()
    );
}
