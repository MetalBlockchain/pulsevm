use std::{
    fmt::{
        self,
        Debug,
        Display,
    },
    hash::{
        Hash,
        Hasher,
    },
    str::FromStr,
};

use pulsevm_crypto::{
    AuthorityPublicKey,
    Digest,
    FixedBytes,
    K1Signature,
    R1Signature,
    WebAuthnSignature,
};
use pulsevm_error::ChainError;
use pulsevm_serialization::{
    NumBytes,
    Read,
    ReadError,
    Write,
    WriteError,
};
use serde::{
    Deserialize,
    Serialize,
};

use crate::crypto::PublicKey;

/// A recoverable Antelope transaction signature.
///
/// K1 and R1 are fixed-size variants. WebAuthn includes browser assertion data
/// and is consequently variable-size on the wire.
#[derive(Clone)]
pub struct Signature {
    inner: SignatureInner,
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum SignatureInner {
    K1(K1Signature),
    R1(R1Signature),
    WebAuthn(WebAuthnSignature),
}

impl Signature {
    pub fn new(inner: K1Signature) -> Self {
        Signature {
            inner: SignatureInner::K1(inner),
        }
    }

    pub fn new_r1(inner: R1Signature) -> Self {
        Signature {
            inner: SignatureInner::R1(inner),
        }
    }

    pub fn new_webauthn(inner: WebAuthnSignature) -> Self {
        Signature {
            inner: SignatureInner::WebAuthn(inner),
        }
    }

    /// Recover the signing key, enforcing fc's canonical-signature predicate on
    /// K1 signatures.
    ///
    /// This is the consensus entry point: transaction authorization and block
    /// header verification both come through here, and both must reject a
    /// non-canonical signature the way nodeos does. See
    /// [`Self::recover_authority_key_non_canonical`] for the contract-intrinsic
    /// path, which deliberately does not.
    pub fn recover_authority_key(&self, digest: &Digest) -> Result<AuthorityPublicKey, ChainError> {
        self.recover_authority_key_inner(digest, true)
    }

    /// Recover the signing key *without* the K1 canonical check, matching fc's
    /// `check_canonical = false`.
    ///
    /// Only the `recover_key` / `assert_recover_key` intrinsics should use this:
    /// contracts recover keys from signatures supplied by arbitrary parties, and
    /// must see the same accept/reject behaviour as nodeos. R1 and WebAuthn are
    /// unaffected — they have no equivalent predicate — so this differs from the
    /// checked form only for K1.
    pub fn recover_authority_key_non_canonical(
        &self,
        digest: &Digest,
    ) -> Result<AuthorityPublicKey, ChainError> {
        self.recover_authority_key_inner(digest, false)
    }

    fn recover_authority_key_inner(
        &self,
        digest: &Digest,
        check_canonical: bool,
    ) -> Result<AuthorityPublicKey, ChainError> {
        match &self.inner {
            SignatureInner::K1(signature) => if check_canonical {
                signature.recover(digest.as_bytes())
            } else {
                signature.recover_non_canonical(digest.as_bytes())
            }
            .map(AuthorityPublicKey::K1)
            .map_err(|e| ChainError::TransactionError(e.to_string())),
            SignatureInner::R1(signature) => signature
                .recover(digest.as_bytes())
                .map(AuthorityPublicKey::R1)
                .map_err(|e| ChainError::TransactionError(e.to_string())),
            SignatureInner::WebAuthn(signature) => signature
                .recover(digest.as_bytes())
                .map(|key| AuthorityPublicKey::WebAuthn {
                    point: key.point,
                    user_presence: key.user_presence,
                    rpid: key.rpid,
                })
                .map_err(|e| ChainError::TransactionError(e.to_string())),
        }
    }

    pub fn recover_public_key(&self, digest: &Digest) -> Result<PublicKey, ChainError> {
        match self.recover_authority_key(digest)? {
            AuthorityPublicKey::K1(key) => Ok(PublicKey::new(key)),
            AuthorityPublicKey::R1(_) | AuthorityPublicKey::WebAuthn { .. } => {
                Err(ChainError::TransactionError(
                    "R1/WebAuthn signatures are not valid for this K1-only intrinsic".into(),
                ))
            }
        }
    }

    fn to_string(&self) -> String {
        match &self.inner {
            SignatureInner::K1(signature) => signature.to_string(),
            SignatureInner::R1(signature) => signature.to_string(),
            SignatureInner::WebAuthn(signature) => signature.to_string(),
        }
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for Signature {}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SigVisitor;

        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string representing a signature")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Signature::from_str(v).map_err(|e| E::custom(e.to_string()))
            }
        }

        deserializer.deserialize_str(SigVisitor)
    }
}

impl NumBytes for Signature {
    fn num_bytes(&self) -> usize {
        match &self.inner {
            SignatureInner::K1(_) | SignatureInner::R1(_) => 66,
            SignatureInner::WebAuthn(signature) => signature.packed_len(),
        }
    }
}

impl Read for Signature {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let tag = *bytes.get(*pos).ok_or(ReadError::NotEnoughBytes)?;
        let inner = match tag {
            0 => SignatureInner::K1({
                let packed = FixedBytes::<66>::read(bytes, pos)?;
                K1Signature::from_packed(packed.as_ref())
                    .map_err(|e| ReadError::CustomError(e.to_string()))?
            }),
            1 => SignatureInner::R1({
                let packed = FixedBytes::<66>::read(bytes, pos)?;
                R1Signature::from_packed(packed.as_ref())
                    .map_err(|e| ReadError::CustomError(e.to_string()))?
            }),
            2 => {
                *pos += 1;
                SignatureInner::WebAuthn(
                    WebAuthnSignature::read_payload(bytes, pos)
                        .map_err(|e| ReadError::CustomError(e.to_string()))?,
                )
            }
            tag => {
                return Err(ReadError::CustomError(format!(
                    "unsupported packed signature type {tag}"
                )));
            }
        };
        Ok(Signature { inner })
    }
}

impl Write for Signature {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        match &self.inner {
            SignatureInner::K1(signature) => {
                FixedBytes::<66>(signature.to_packed()).write(bytes, pos)
            }
            SignatureInner::R1(signature) => {
                FixedBytes::<66>(signature.to_packed()).write(bytes, pos)
            }
            SignatureInner::WebAuthn(signature) => {
                let packed = signature.to_packed();
                let end = pos
                    .checked_add(packed.len())
                    .filter(|end| *end <= bytes.len())
                    .ok_or(WriteError::NotEnoughSpace)?;
                bytes[*pos..end].copy_from_slice(&packed);
                *pos = end;
                Ok(())
            }
        }
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::from_str(
            "SIG_K1_111111111111111111111111111111111111111111111111111111111111111116uk5ne",
        )
        .unwrap()
    }
}

impl FromStr for Signature {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = if s.starts_with("SIG_K1_") {
            SignatureInner::K1(K1Signature::from_string(s).map_err(|e| {
                ChainError::TransactionError(format!("failed to parse K1 signature: {e}"))
            })?)
        } else if s.starts_with("SIG_R1_") {
            SignatureInner::R1(R1Signature::from_string(s).map_err(|e| {
                ChainError::TransactionError(format!("failed to parse R1 signature: {e}"))
            })?)
        } else if s.starts_with("SIG_WA_") {
            SignatureInner::WebAuthn(WebAuthnSignature::from_string(s).map_err(|e| {
                ChainError::TransactionError(format!("failed to parse WebAuthn signature: {e}"))
            })?)
        } else {
            return Err(ChainError::TransactionError(
                "unsupported signature type".into(),
            ));
        };
        Ok(Signature { inner })
    }
}

#[cfg(test)]
mod tests {
    use base64::{
        Engine as _,
        engine::general_purpose::URL_SAFE_NO_PAD,
    };
    use p256::ecdsa::SigningKey;
    use pulsevm_serialization::{
        Read,
        Write,
    };
    use sha2::{
        Digest as _,
        Sha256,
    };

    use super::Signature;
    use pulsevm_crypto::{
        AuthorityPublicKey,
        Digest,
        R1Signature,
        WebAuthnSignature,
    };

    #[test]
    fn r1_signature_recovers_an_r1_authority_key() {
        let signing_key = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
        let digest = Digest([99u8; 32]);
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(digest.as_bytes())
            .unwrap();
        let (signature, recovery_id) = match signature.normalize_s() {
            Some(signature) => (signature, (recovery_id.to_byte() ^ 1).try_into().unwrap()),
            None => (signature, recovery_id),
        };
        let mut compact = [0u8; 65];
        compact[0] = 31 + recovery_id.to_byte();
        compact[1..].copy_from_slice(&signature.to_bytes());

        let signature = Signature::new_r1(R1Signature::from_compact65(&compact));
        let AuthorityPublicKey::R1(key) = signature.recover_authority_key(&digest).unwrap() else {
            panic!("R1 signature recovered to a non-R1 authority key");
        };
        assert_eq!(
            key.as_slice(),
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
        );
    }

    #[test]
    fn webauthn_signature_uses_variable_length_wire_format() {
        let signing_key = SigningKey::from_bytes((&[17u8; 32]).into()).unwrap();
        let digest = Digest([3u8; 32]);
        let client_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.test"}}"#,
            URL_SAFE_NO_PAD.encode(digest.as_bytes()),
        );
        let mut auth_data = vec![0u8; 37];
        auth_data[..32].copy_from_slice(&Sha256::digest(b"example.test"));
        auth_data[32] = 0x01;
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&Sha256::digest(client_json.as_bytes()));
        let signed_digest: [u8; 32] = Sha256::digest(signed_data).into();
        let (signed, recovery_id) = signing_key
            .sign_prehash_recoverable(&signed_digest)
            .unwrap();
        let mut compact = [0u8; 65];
        compact[0] = 31 + recovery_id.to_byte();
        compact[1..].copy_from_slice(&signed.to_bytes());

        let signature =
            Signature::new_webauthn(WebAuthnSignature::new(compact, auth_data, client_json));
        let packed = signature.pack().unwrap();
        assert!(packed.len() > 66);
        let decoded = Signature::read(&packed, &mut 0).unwrap();
        let AuthorityPublicKey::WebAuthn {
            point,
            user_presence,
            rpid,
        } = decoded.recover_authority_key(&digest).unwrap()
        else {
            panic!("WebAuthn signature recovered to the wrong key type");
        };
        assert_eq!(user_presence, 1);
        assert_eq!(rpid, "example.test");
        assert_eq!(
            point.as_slice(),
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        );
    }
}
