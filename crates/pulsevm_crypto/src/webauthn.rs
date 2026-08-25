use base64::{
    Engine as _,
    engine::general_purpose::{
        URL_SAFE,
        URL_SAFE_NO_PAD,
    },
};
use serde_json::Value;
use sha2::{
    Digest as _,
    Sha256,
};

use crate::{
    R1Signature,
    k1::{
        encode_b58_checked,
        ripemd_checksum,
    },
};

/// A WebAuthn assertion carried by Antelope's `SIG_WA_` signature variant.
///
/// The payload is `compact_r1_signature`, `authenticatorData`, and the raw
/// client-data JSON, exactly as packed by `fc::crypto::webauthn::signature`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WebAuthnSignature {
    compact: [u8; 65],
    auth_data: Vec<u8>,
    client_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnError(pub String);

impl core::fmt::Display for WebAuthnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WebAuthnError {}

impl WebAuthnSignature {
    pub fn new(compact: [u8; 65], auth_data: Vec<u8>, client_json: String) -> Self {
        Self {
            compact,
            auth_data,
            client_json,
        }
    }

    pub fn compact65(&self) -> [u8; 65] {
        self.compact
    }

    pub fn auth_data(&self) -> &[u8] {
        &self.auth_data
    }

    pub fn client_json(&self) -> &str {
        &self.client_json
    }

    /// Recover and validate the WebAuthn public-key tuple for an Antelope
    /// transaction digest. This mirrors Leap's `webauthn::public_key` recovery:
    /// the challenge, HTTPS origin, RP-ID hash, authenticator flags, and P-256
    /// compact signature are all committed before an authority can match.
    pub fn recover(&self, digest: &[u8; 32]) -> Result<RecoveredWebAuthnKey, WebAuthnError> {
        let value: Value = serde_json::from_str(&self.client_json)
            .map_err(|_| WebAuthnError("failed to parse WebAuthn client-data JSON".into()))?;
        let object = value
            .as_object()
            .ok_or_else(|| WebAuthnError("WebAuthn client data is not an object".into()))?;
        let challenge = object
            .get("challenge")
            .and_then(Value::as_str)
            .ok_or_else(|| WebAuthnError("WebAuthn client data has no string challenge".into()))?;
        let origin = object
            .get("origin")
            .and_then(Value::as_str)
            .ok_or_else(|| WebAuthnError("WebAuthn client data has no string origin".into()))?;
        let assertion_type = object
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| WebAuthnError("WebAuthn client data has no string type".into()))?;
        if assertion_type != "webauthn.get" {
            return Err(WebAuthnError(
                "WebAuthn signature type is not an assertion".into(),
            ));
        }
        let challenge = URL_SAFE_NO_PAD
            .decode(challenge)
            .or_else(|_| URL_SAFE.decode(challenge))
            .map_err(|_| WebAuthnError("invalid WebAuthn challenge encoding".into()))?;
        if challenge.as_slice() != digest {
            return Err(WebAuthnError("wrong WebAuthn challenge".into()));
        }

        let origin_body = origin
            .strip_prefix("https://")
            .ok_or_else(|| WebAuthnError("WebAuthn origin must begin with https://".into()))?;
        // Leap removes an optional port with `rfind(':')`. Restricting the
        // search to the origin body preserves its normal host[:port] behavior.
        let rpid = match origin_body.rfind(':') {
            Some(port) => &origin_body[..port],
            None => origin_body,
        };

        if self.auth_data.len() < 37 {
            return Err(WebAuthnError(
                "WebAuthn authenticator data is shorter than 37 bytes".into(),
            ));
        }
        let rpid_hash = Sha256::digest(rpid.as_bytes());
        if self.auth_data[..32] != rpid_hash[..] {
            return Err(WebAuthnError(
                "WebAuthn RP-ID hash does not match origin".into(),
            ));
        }
        let flags = self.auth_data[32];
        let user_presence = if flags & 0x04 != 0 {
            2
        } else if flags & 0x01 != 0 {
            1
        } else {
            0
        };

        let client_hash = Sha256::digest(self.client_json.as_bytes());
        let mut signed_data = Vec::with_capacity(self.auth_data.len() + client_hash.len());
        signed_data.extend_from_slice(&self.auth_data);
        signed_data.extend_from_slice(&client_hash);
        let signed_digest: [u8; 32] = Sha256::digest(&signed_data).into();
        let point = R1Signature::from_compact65(&self.compact)
            .recover(&signed_digest)
            .map_err(|e| WebAuthnError(e.to_string()))?;

        Ok(RecoveredWebAuthnKey {
            point,
            user_presence,
            rpid: rpid.to_owned(),
        })
    }

    /// Packed Antelope signature, including static-variant tag `2`.
    pub fn to_packed(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(68 + self.auth_data.len() + self.client_json.len());
        out.push(2);
        self.write_payload(&mut out);
        out
    }

    pub fn from_packed(bytes: &[u8]) -> Result<Self, WebAuthnError> {
        let mut pos = 0;
        if take_byte(bytes, &mut pos)? != 2 {
            return Err(WebAuthnError("unexpected packed signature type".into()));
        }
        let value = Self::read_payload(bytes, &mut pos)?;
        if pos != bytes.len() {
            return Err(WebAuthnError("trailing bytes in WebAuthn signature".into()));
        }
        Ok(value)
    }

    pub fn read_payload(bytes: &[u8], pos: &mut usize) -> Result<Self, WebAuthnError> {
        let compact: [u8; 65] = take(bytes, pos, 65)?.try_into().unwrap();
        let auth_len = usize::try_from(read_varuint(bytes, pos)?)
            .map_err(|_| WebAuthnError("WebAuthn auth-data length is too large".into()))?;
        let auth_data = take(bytes, pos, auth_len)?.to_vec();
        let json_len = usize::try_from(read_varuint(bytes, pos)?)
            .map_err(|_| WebAuthnError("WebAuthn client-data length is too large".into()))?;
        let client_json = String::from_utf8(take(bytes, pos, json_len)?.to_vec())
            .map_err(|_| WebAuthnError("WebAuthn client-data is not UTF-8".into()))?;
        Ok(Self::new(compact, auth_data, client_json))
    }

    pub fn write_payload(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.compact);
        write_varuint(self.auth_data.len() as u64, out);
        out.extend_from_slice(&self.auth_data);
        write_varuint(self.client_json.len() as u64, out);
        out.extend_from_slice(self.client_json.as_bytes());
    }

    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        let mut payload = Vec::new();
        self.write_payload(&mut payload);
        format!("SIG_WA_{}", encode_b58_checked(&payload, b"WA"))
    }

    pub fn from_string(value: &str) -> Result<Self, WebAuthnError> {
        let data = value
            .strip_prefix("SIG_WA_")
            .ok_or_else(|| WebAuthnError("invalid WebAuthn signature prefix".into()))?;
        let bytes = bs58::decode(data)
            .into_vec()
            .map_err(|_| WebAuthnError("invalid WebAuthn base58 data".into()))?;
        if bytes.len() < 5 {
            return Err(WebAuthnError("WebAuthn base58 data is too short".into()));
        }
        let (payload, checksum) = bytes.split_at(bytes.len() - 4);
        if ripemd_checksum(payload, b"WA") != checksum {
            return Err(WebAuthnError("WebAuthn signature checksum mismatch".into()));
        }
        let mut pos = 0;
        let signature = Self::read_payload(payload, &mut pos)?;
        if pos != payload.len() {
            return Err(WebAuthnError("trailing WebAuthn signature bytes".into()));
        }
        Ok(signature)
    }
}

impl core::fmt::Display for WebAuthnSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl core::fmt::Debug for WebAuthnSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "WebAuthnSignature({})", self.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredWebAuthnKey {
    pub point: [u8; 33],
    pub user_presence: u8,
    pub rpid: String,
}

fn take<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], WebAuthnError> {
    let end = pos
        .checked_add(len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| WebAuthnError("truncated WebAuthn signature".into()))?;
    let result = &bytes[*pos..end];
    *pos = end;
    Ok(result)
}

fn take_byte(bytes: &[u8], pos: &mut usize) -> Result<u8, WebAuthnError> {
    Ok(take(bytes, pos, 1)?[0])
}

fn read_varuint(bytes: &[u8], pos: &mut usize) -> Result<u64, WebAuthnError> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = take_byte(bytes, pos)?;
        let part = (byte & 0x7f) as u64;
        if shift == 63 && part > 1 {
            return Err(WebAuthnError("WebAuthn varuint overflows u64".into()));
        }
        value |= part << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(WebAuthnError("WebAuthn varuint is too long".into()))
}

fn write_varuint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::{
        Engine as _,
        engine::general_purpose::URL_SAFE_NO_PAD,
    };
    use p256::ecdsa::SigningKey;
    use sha2::{
        Digest as _,
        Sha256,
    };

    use super::WebAuthnSignature;

    #[test]
    fn webauthn_signature_validates_and_round_trips() {
        let signing_key = SigningKey::from_bytes((&[13u8; 32]).into()).unwrap();
        let digest = [7u8; 32];
        let client_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.test"}}"#,
            URL_SAFE_NO_PAD.encode(digest),
        );
        let mut auth_data = vec![0u8; 37];
        auth_data[..32].copy_from_slice(&Sha256::digest(b"example.test"));
        auth_data[32] = 0x05;
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(client_json.as_bytes()));
        let signed_digest: [u8; 32] = Sha256::digest(signed).into();
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&signed_digest)
            .unwrap();
        let mut compact = [0u8; 65];
        compact[0] = 31 + recovery_id.to_byte();
        compact[1..].copy_from_slice(&signature.to_bytes());

        let signature = WebAuthnSignature::new(compact, auth_data, client_json);
        let key = signature.recover(&digest).unwrap();
        assert_eq!(key.user_presence, 2);
        assert_eq!(key.rpid, "example.test");
        assert_eq!(
            key.point.as_slice(),
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        );
        assert_eq!(
            WebAuthnSignature::from_packed(&signature.to_packed()).unwrap(),
            signature
        );
        assert_eq!(
            WebAuthnSignature::from_string(&signature.to_string()).unwrap(),
            signature
        );
    }
}
