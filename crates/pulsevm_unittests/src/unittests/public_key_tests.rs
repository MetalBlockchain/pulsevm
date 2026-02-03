#[cfg(test)]
mod private_key_tests {
    use std::str::FromStr;

    use pulsevm_core::crypto::{PrivateKey, PublicKey};

    #[test]
    fn test_public_key_parsing() {
        let public_key =
            PublicKey::from_str("PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H")
                .expect("Failed to create private key");
        assert!(!public_key.to_string().is_empty());
        assert_eq!(
            public_key.to_string(),
            "PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H"
        );
    }
}
