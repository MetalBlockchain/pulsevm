//! PulseVM's FIPS 204 pure ML-DSA encoding. See `docs/ml-dsa.md`.

use std::fmt;

use ml_dsa::{
    EncodedVerifyingKey,
    Keypair,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    MlDsaParams,
    SigningKey,
    VerifyingKey,
};
use secp256k1::rand::RngCore;
use zeroize::Zeroizing;

use crate::k1::{
    decode_b58_checked,
    encode_b58_checked,
};

/// FIPS 204 context for signing the existing chain-bound transaction digest.
pub const ML_DSA_TRANSACTION_CONTEXT: &[u8] = b"PulseVM transaction";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MlDsaParameterSet {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsaParameterSet {
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    pub const fn signature_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    pub const fn tag(self) -> u8 {
        match self {
            Self::MlDsa44 => 3,
            Self::MlDsa65 => 4,
            Self::MlDsa87 => 5,
        }
    }

    pub fn from_tag(tag: u8) -> Result<Self, MlDsaError> {
        match tag {
            3 => Ok(Self::MlDsa44),
            4 => Ok(Self::MlDsa65),
            5 => Ok(Self::MlDsa87),
            _ => Err(MlDsaError("unsupported ML-DSA parameter set".into())),
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::MlDsa44 => "MLDSA44",
            Self::MlDsa65 => "MLDSA65",
            Self::MlDsa87 => "MLDSA87",
        }
    }
}

impl std::str::FromStr for MlDsaParameterSet {
    type Err = MlDsaError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "MLDSA44" => Ok(Self::MlDsa44),
            "MLDSA65" => Ok(Self::MlDsa65),
            "MLDSA87" => Ok(Self::MlDsa87),
            _ => Err(MlDsaError("expected MLDSA44, MLDSA65, or MLDSA87".into())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlDsaError(pub String);

impl fmt::Display for MlDsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MlDsaError {}

/// Fixed-length public key; construction checks size without expanding a lattice.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MlDsaPublicKey {
    parameters: MlDsaParameterSet,
    bytes: Box<[u8]>,
}

impl MlDsaPublicKey {
    pub fn from_bytes(parameters: MlDsaParameterSet, bytes: &[u8]) -> Result<Self, MlDsaError> {
        if bytes.len() != parameters.public_key_len() {
            return Err(MlDsaError("invalid ML-DSA public key length".into()));
        }
        Ok(Self {
            parameters,
            bytes: bytes.into(),
        })
    }

    pub fn parameters(&self) -> MlDsaParameterSet {
        self.parameters
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn verify(&self, message: &[u8], context: &[u8], signature: &[u8]) -> bool {
        if context.len() > 255 || signature.len() != self.parameters.signature_len() {
            return false;
        }
        match self.parameters {
            MlDsaParameterSet::MlDsa44 => {
                verify::<MlDsa44>(&self.bytes, message, context, signature)
            }
            MlDsaParameterSet::MlDsa65 => {
                verify::<MlDsa65>(&self.bytes, message, context, signature)
            }
            MlDsaParameterSet::MlDsa87 => {
                verify::<MlDsa87>(&self.bytes, message, context, signature)
            }
        }
    }

    pub fn from_string(value: &str) -> Result<Self, MlDsaError> {
        let (parameters, payload) = parse_prefix(value, "PUB")?;
        let bytes = decode_checked(payload, parameters.public_key_len(), parameters)?;
        Self::from_bytes(parameters, &bytes)
    }
}

impl fmt::Display for MlDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PUB_{}_{}",
            self.parameters.suffix(),
            encode_b58_checked(&self.bytes, self.parameters.suffix().as_bytes())
        )
    }
}

impl fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Non-recoverable signature envelope: fixed-size public key then signature.
/// The tag supplies the parameter set, with no attacker-controlled length fields.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MlDsaSignature {
    public_key: MlDsaPublicKey,
    bytes: Box<[u8]>,
}

impl MlDsaSignature {
    pub fn new(public_key: MlDsaPublicKey, bytes: &[u8]) -> Result<Self, MlDsaError> {
        if bytes.len() != public_key.parameters.signature_len() {
            return Err(MlDsaError("invalid ML-DSA signature length".into()));
        }
        Ok(Self {
            public_key,
            bytes: bytes.into(),
        })
    }

    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn verify(&self, message: &[u8], context: &[u8]) -> bool {
        self.public_key.verify(message, context, &self.bytes)
    }

    pub fn packed_len(&self) -> usize {
        1 + self.public_key.as_bytes().len() + self.bytes.len()
    }

    pub fn to_packed(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.packed_len());
        bytes.push(self.public_key.parameters.tag());
        bytes.extend_from_slice(self.public_key.as_bytes());
        bytes.extend_from_slice(&self.bytes);
        bytes
    }

    pub fn from_packed(bytes: &[u8]) -> Result<Self, MlDsaError> {
        let (&tag, payload) = bytes
            .split_first()
            .ok_or_else(|| MlDsaError("truncated ML-DSA signature".into()))?;
        let parameters = MlDsaParameterSet::from_tag(tag)?;
        if payload.len() != parameters.public_key_len() + parameters.signature_len() {
            return Err(MlDsaError(
                "invalid ML-DSA signature envelope length".into(),
            ));
        }
        let (key, signature) = payload.split_at(parameters.public_key_len());
        Self::new(MlDsaPublicKey::from_bytes(parameters, key)?, signature)
    }

    pub fn from_string(value: &str) -> Result<Self, MlDsaError> {
        let (parameters, payload) = parse_prefix(value, "SIG")?;
        let bytes = decode_checked(
            payload,
            parameters.public_key_len() + parameters.signature_len(),
            parameters,
        )?;
        let mut packed = Vec::with_capacity(bytes.len() + 1);
        packed.push(parameters.tag());
        packed.extend_from_slice(&bytes);
        Self::from_packed(&packed)
    }
}

impl fmt::Display for MlDsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let packed = self.to_packed();
        write!(
            f,
            "SIG_{}_{}",
            self.public_key.parameters.suffix(),
            encode_b58_checked(&packed[1..], self.public_key.parameters.suffix().as_bytes())
        )
    }
}

impl fmt::Debug for MlDsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A secret 32-byte FIPS 204 seed, erased on drop and omitted from Debug.
#[derive(Clone)]
pub struct MlDsaPrivateKey {
    parameters: MlDsaParameterSet,
    seed: Zeroizing<[u8; 32]>,
}

impl MlDsaPrivateKey {
    pub fn random(parameters: MlDsaParameterSet) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        secp256k1::rand::thread_rng().fill_bytes(seed.as_mut());
        Self::from_seed(parameters, *seed)
    }

    pub fn from_seed(parameters: MlDsaParameterSet, seed: [u8; 32]) -> Self {
        Self {
            parameters,
            seed: Zeroizing::new(seed),
        }
    }

    pub fn public_key(&self) -> MlDsaPublicKey {
        fn derive<P: MlDsaParams>(seed: &[u8; 32]) -> Box<[u8]> {
            let seed = Zeroizing::new(ml_dsa::Seed::from(*seed));
            SigningKey::<P>::from_seed(&seed)
                .verifying_key()
                .encode()
                .as_slice()
                .into()
        }
        let bytes = match self.parameters {
            MlDsaParameterSet::MlDsa44 => derive::<MlDsa44>(&self.seed),
            MlDsaParameterSet::MlDsa65 => derive::<MlDsa65>(&self.seed),
            MlDsaParameterSet::MlDsa87 => derive::<MlDsa87>(&self.seed),
        };
        MlDsaPublicKey {
            parameters: self.parameters,
            bytes,
        }
    }

    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<MlDsaSignature, MlDsaError> {
        if context.len() > 255 {
            return Err(MlDsaError("ML-DSA context exceeds 255 bytes".into()));
        }
        fn sign<P: MlDsaParams>(
            parameters: MlDsaParameterSet,
            seed: &[u8; 32],
            message: &[u8],
            context: &[u8],
        ) -> Result<MlDsaSignature, MlDsaError> {
            let seed = Zeroizing::new(ml_dsa::Seed::from(*seed));
            let key = SigningKey::<P>::from_seed(&seed);
            let signature = key
                .expanded_key()
                .sign_deterministic(message, context)
                .map_err(|e| MlDsaError(e.to_string()))?;
            Ok(MlDsaSignature {
                public_key: MlDsaPublicKey {
                    parameters,
                    bytes: key.verifying_key().encode().as_slice().into(),
                },
                bytes: signature.encode().as_slice().into(),
            })
        }
        match self.parameters {
            MlDsaParameterSet::MlDsa44 => {
                sign::<MlDsa44>(self.parameters, &self.seed, message, context)
            }
            MlDsaParameterSet::MlDsa65 => {
                sign::<MlDsa65>(self.parameters, &self.seed, message, context)
            }
            MlDsaParameterSet::MlDsa87 => {
                sign::<MlDsa87>(self.parameters, &self.seed, message, context)
            }
        }
    }

    pub fn from_string(value: &str) -> Result<Self, MlDsaError> {
        let (parameters, payload) = parse_prefix(value, "PVT")?;
        let bytes = Zeroizing::new(decode_checked(payload, 32, parameters)?);
        let seed = bytes
            .as_slice()
            .try_into()
            .map_err(|_| MlDsaError("invalid ML-DSA seed length".into()))?;
        Ok(Self::from_seed(parameters, seed))
    }
}

impl fmt::Display for MlDsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PVT_{}_{}",
            self.parameters.suffix(),
            encode_b58_checked(self.seed.as_slice(), self.parameters.suffix().as_bytes())
        )
    }
}

impl fmt::Debug for MlDsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaPrivateKey")
            .field("parameters", &self.parameters)
            .finish_non_exhaustive()
    }
}

fn verify<P: MlDsaParams>(key: &[u8], message: &[u8], context: &[u8], signature: &[u8]) -> bool {
    // Decode the signature first: canonical hint ordering and norm checks fail
    // cheaply, before the key expands its public lattice matrix.
    let Ok(signature) = ml_dsa::Signature::<P>::try_from(signature) else {
        return false;
    };
    let Ok(key) = EncodedVerifyingKey::<P>::try_from(key) else {
        return false;
    };
    VerifyingKey::<P>::decode(&key).verify_with_context(message, context, &signature)
}

fn parse_prefix<'a>(
    value: &'a str,
    kind: &str,
) -> Result<(MlDsaParameterSet, &'a str), MlDsaError> {
    for parameters in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ] {
        if let Some(payload) = value.strip_prefix(&format!("{kind}_{}_", parameters.suffix())) {
            return Ok((parameters, payload));
        }
    }
    Err(MlDsaError("unsupported ML-DSA prefix".into()))
}

fn decode_checked(
    value: &str,
    len: usize,
    parameters: MlDsaParameterSet,
) -> Result<Vec<u8>, MlDsaError> {
    // A base58 string cannot exceed this bound for len + checksum bytes.
    if value.len() > (len + 4) * 138 / 100 + 1 {
        return Err(MlDsaError(
            "ML-DSA base58 input exceeds its fixed size".into(),
        ));
    }
    decode_b58_checked(value, len, parameters.suffix().as_bytes())
        .map_err(|e| MlDsaError(e.to_string()))
}
