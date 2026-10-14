use pulsevm_crypto::{
    AuthorityPublicKey,
    ML_DSA_TRANSACTION_CONTEXT,
    MlDsaParameterSet,
    MlDsaPrivateKey,
    MlDsaPublicKey,
    MlDsaSignature,
};
use pulsevm_serialization::{
    NumBytes,
    Read,
    Write,
};

const PARAMETERS: [MlDsaParameterSet; 3] = [
    MlDsaParameterSet::MlDsa44,
    MlDsaParameterSet::MlDsa65,
    MlDsaParameterSet::MlDsa87,
];

#[test]
fn ml_dsa_wycheproof_interoperability_and_noncanonical_hints() {
    // Independent FIPS 204 verification vectors, including the repeated-hint
    // regression CVE-2026-24850. Sources and SHA-256 are frozen in the fixture.
    let groups: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/ml_dsa_wycheproof.json")).unwrap();
    for group in groups.as_array().unwrap() {
        let parameters = group["parameters"].as_str().unwrap().parse().unwrap();
        let key = MlDsaPublicKey::from_bytes(
            parameters,
            &hex::decode(group["publicKey"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        for test in group["tests"].as_array().unwrap() {
            let message = hex::decode(test["msg"].as_str().unwrap()).unwrap();
            let signature = hex::decode(test["sig"].as_str().unwrap()).unwrap();
            let context =
                hex::decode(test.get("ctx").and_then(|v| v.as_str()).unwrap_or("")).unwrap();
            assert_eq!(
                key.verify(&message, &context, &signature),
                test["result"] == "valid",
                "{} case {}: {}",
                group["parameters"],
                test["tcId"],
                test["comment"]
            );
        }
    }
}

#[test]
fn ml_dsa_fixed_wire_json_and_secret_seed_round_trips() {
    let mut previous = None;
    for parameters in PARAMETERS {
        let private = MlDsaPrivateKey::from_seed(parameters, [19; 32]);
        let restored = MlDsaPrivateKey::from_string(&private.to_string()).unwrap();
        assert_eq!(restored.public_key(), private.public_key());
        assert!(!format!("{private:?}").contains(&private.to_string()));
        let key = AuthorityPublicKey::from(private.public_key());
        assert!(previous.as_ref().is_none_or(|previous| previous < &key));
        previous = Some(key.clone());
        let packed = key.pack().unwrap();
        assert_eq!(packed[0], parameters.tag());
        assert_eq!(packed.len(), 1 + parameters.public_key_len());
        assert_eq!(packed.len(), key.num_bytes());
        assert_eq!(AuthorityPublicKey::from_packed(&packed).unwrap(), key);
        assert_eq!(
            AuthorityPublicKey::from_string(&key.to_string()).unwrap(),
            key
        );
        assert_eq!(
            serde_json::from_str::<AuthorityPublicKey>(&serde_json::to_string(&key).unwrap())
                .unwrap(),
            key
        );
        assert!(AuthorityPublicKey::from_packed(&packed[..packed.len() - 1]).is_err());
        let mut stream = packed.clone();
        stream.push(42);
        assert!(AuthorityPublicKey::from_packed(&stream).is_err());
        let mut noncanonical = vec![parameters.tag() | 0x80, 0];
        noncanonical.extend_from_slice(&packed[1..]);
        assert!(AuthorityPublicKey::from_packed(&noncanonical).is_err());
        let mut position = 0;
        assert_eq!(
            AuthorityPublicKey::read(&stream, &mut position).unwrap(),
            key
        );
        assert_eq!(position, packed.len());

        let signature = private
            .sign(b"message", ML_DSA_TRANSACTION_CONTEXT)
            .unwrap();
        let packed = signature.to_packed();
        assert_eq!(
            packed.len(),
            1 + parameters.public_key_len() + parameters.signature_len()
        );
        assert_eq!(MlDsaSignature::from_packed(&packed).unwrap(), signature);
        assert_eq!(
            MlDsaSignature::from_string(&signature.to_string()).unwrap(),
            signature
        );
        assert!(MlDsaSignature::from_packed(&packed[..packed.len() - 1]).is_err());
        assert!(MlDsaSignature::from_packed(&[packed, vec![0]].concat()).is_err());
        assert!(signature.verify(b"message", ML_DSA_TRANSACTION_CONTEXT));
        assert!(!signature.verify(b"message!", ML_DSA_TRANSACTION_CONTEXT));
        assert!(!signature.verify(b"message", b""));
        assert!(
            !MlDsaPrivateKey::from_seed(parameters, [20; 32])
                .public_key()
                .verify(b"message", ML_DSA_TRANSACTION_CONTEXT, signature.as_bytes())
        );
        assert!(private.sign(b"message", &[0; 255]).is_ok());
        assert!(private.sign(b"message", &[0; 256]).is_err());
        assert!(
            !private
                .public_key()
                .verify(b"message", &[0; 256], signature.as_bytes())
        );
    }
}

#[test]
fn ml_dsa_parsers_reject_unknown_tags_lengths_checksums_and_oversized_base58() {
    assert!(MlDsaParameterSet::from_tag(6).is_err());
    assert!(MlDsaSignature::from_packed(&[]).is_err());
    for parameters in PARAMETERS {
        assert!(
            MlDsaPublicKey::from_bytes(parameters, &vec![0; parameters.public_key_len() - 1])
                .is_err()
        );
        assert!(
            MlDsaPublicKey::from_bytes(parameters, &vec![0; parameters.public_key_len() + 1])
                .is_err()
        );
        let key = MlDsaPrivateKey::from_seed(parameters, [1; 32]).public_key();
        assert!(
            MlDsaSignature::new(key.clone(), &vec![0; parameters.signature_len() - 1]).is_err()
        );
        let mut text = key.to_string();
        let last = text.pop().unwrap();
        text.push(if last == '1' { '2' } else { '1' });
        assert!(MlDsaPublicKey::from_string(&text).is_err());
    }
    assert!(MlDsaPublicKey::from_string(&format!("PUB_MLDSA44_{}", "1".repeat(100_000))).is_err());
}
