#[cfg(test)]
mod private_key_tests {
    use std::str::FromStr;

    use pulsevm_core::crypto::PrivateKey;

    #[test]
    fn test_private_key_parsing() {
        let private_key = PrivateKey::from_str("PVT_K1_2pfDJ4TeHJRTNbcAX6Ra5fZrGzGpvjRbody9uD3pgQQnZP31rv").expect("Failed to create private key");
        assert!(!private_key.to_string().is_empty());
        assert_eq!(private_key.to_string(), "PVT_K1_2pfDJ4TeHJRTNbcAX6Ra5fZrGzGpvjRbody9uD3pgQQnZP31rv");

        let private_key = PrivateKey::new_k1_from_string("hello world").expect("Failed to create private key from string");
        assert!(!private_key.to_string().is_empty());
        assert_eq!(private_key.to_string(), "PVT_K1_2QcGxuiethzLk2We9hTQVN9Ua9mipFdqvGLQRZzArzyC5AgTs8");
    }
}