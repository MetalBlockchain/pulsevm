//! Chain id parsing: MetalGo renders 32-byte chain ids as base58 in logs
//! and explorers, while manifests store the canonical 64-character hex.
//! Accept both on input so operators can paste either form; evidence
//! always stores hex.

use std::fmt;

/// Parse failure for [`parse_chain_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainIdError(pub String);

impl fmt::Display for ChainIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ChainIdError {}

/// Parse a chain id in either accepted form — 64 hexadecimal characters,
/// raw base58, or CB58 (base58 with a 4-byte checksum, the MetalGo
/// log/explorer rendering: the checksum is the last four bytes of the
/// SHA-256 of the payload and is verified, not skipped) — into raw bytes.
/// Anything else fails closed: a mistyped id must never silently become a
/// different chain.
pub fn parse_chain_id(text: &str) -> Result<[u8; 32], ChainIdError> {
    let text = text.trim();
    if text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let raw = hex::decode(text)
            .map_err(|error| ChainIdError(format!("chain id hex invalid: {error}")))?;
        let mut id = [0u8; 32];
        id.copy_from_slice(&raw);
        return Ok(id);
    }
    let raw = bs58::decode(text)
        .into_vec()
        .map_err(|error| ChainIdError(format!("chain id base58 invalid: {error}")))?;
    if raw.len() == 32 {
        let mut id = [0u8; 32];
        id.copy_from_slice(&raw);
        return Ok(id);
    }
    if raw.len() == 36 {
        use sha2::Digest as _;
        let checksum = &sha2::Sha256::digest(&raw[..32]);
        if raw[32..] != checksum[28..] {
            return Err(ChainIdError(
                "chain id checksum mismatch: not a valid CB58 chain id".to_string(),
            ));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&raw[..32]);
        return Ok(id);
    }
    Err(ChainIdError(format!(
        "chain id decodes to {} bytes, want 32 (or 36 with CB58 checksum)",
        raw.len()
    )))
}

/// Canonical manifest form of a parsed chain id.
pub fn chain_id_hex(id: &[u8; 32]) -> String {
    hex::encode(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_hex_and_base58_for_the_same_id() {
        let raw = [0xabu8; 32];
        let as_hex = hex::encode(raw);
        let as_b58 = bs58::encode(raw).into_string();
        assert_eq!(parse_chain_id(&as_hex).unwrap(), raw);
        assert_eq!(parse_chain_id(&as_b58).unwrap(), raw);
        assert_eq!(parse_chain_id(&format!("  {as_b58}  ")).unwrap(), raw);
        assert_eq!(chain_id_hex(&raw), as_hex);
    }

    #[test]
    fn rejects_short_long_and_non_alphabet_input() {
        assert!(parse_chain_id(&"ab".repeat(31)).is_err());
        assert!(parse_chain_id(&"ab".repeat(33)).is_err());
        assert!(parse_chain_id("not a chain id!!").is_err());
        // 64 hex chars with a non-hex letter fails, not misread.
        let mut bad = "ab".repeat(32);
        bad.replace_range(0..1, "z");
        assert!(parse_chain_id(&bad).is_err());
    }

    #[test]
    fn accepts_cb58_with_a_verified_checksum() {
        // The rehearsal runner's chain id in log rendering.
        let rendered = "7gssBA1cd8G3nVf8HE92479NPAE2ovw4jAUn3diwUsb1vGrtC";
        let parsed = parse_chain_id(rendered).unwrap();
        assert_eq!(
            hex::encode(parsed),
            "0f2f534836e40cef06c3d88e5fe4bb807331664834cd1abf077114dfc96ed974"
        );
        // A flipped checksum byte fails instead of binding a wrong chain.
        let mut bad = rendered.to_string();
        bad.replace_range(0..1, if &rendered[0..1] == "7" { "8" } else { "7" });
        assert!(parse_chain_id(&bad).is_err());
    }
}
