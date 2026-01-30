#[cfg(test)]
mod private_key_tests {
    use std::str::FromStr;

    use pulsevm_core::crypto::{PrivateKey, PublicKey, Signature};

    #[test]
    fn test_signature_parsing() {
        let signature = Signature::from_str("SIG_K1_K9pFVXCf4A6HDm4k7A7wnhqxSxvxC43cVEJh5PoZmKVcyvHQBrYsWMcaBKjbJBrS2at6qsKSYunuZ6gE67fkHaQv9c4HPA")
            .expect("Failed to create signature");
        assert!(!signature.to_string().is_empty());
        assert_eq!(
            signature.to_string(),
            "SIG_K1_K9pFVXCf4A6HDm4k7A7wnhqxSxvxC43cVEJh5PoZmKVcyvHQBrYsWMcaBKjbJBrS2at6qsKSYunuZ6gE67fkHaQv9c4HPA"
        );
    }
}
