//! The boundary between PulseVM and the thing that holds the validator's BLS key.
//!
//! When a contract emits a cross-chain message, PulseVM constructs the
//! [`UnsignedMessage`] but the *signature* over it is produced by the validator's
//! BLS key. Where that key lives depends on deployment:
//!
//! * **Local / dev / single-node** — the key is available to the process, so we
//!   sign in-process with real `blst` ([`LocalBlsSigner`]). This is genuine
//!   end-to-end BLS: the resulting signature verifies under [`super::verify`] and
//!   under a real MetalGo validator.
//! * **Production rpcchainvm** — the secret key stays inside MetalGo and never
//!   reaches the VM (PulseVM only receives the *public* key at `Initialize`, see
//!   `vm.proto` `public_key`). Signing then happens over gRPC against MetalGo's
//!   warp signer service. That transport implements the same [`WarpSigner`] trait
//!   so the rest of the VM is identical regardless of where the key lives.
//!
//! Modeling this as a trait keeps the key-custody decision out of the messaging
//! logic: [`crate::chain::warp`] only ever asks a `WarpSigner` to sign.

use pulsevm_crypto::bls::{
    self,
    PublicKey,
    SecretKey,
    Signature,
};

use super::message::UnsignedMessage;

/// Failure to obtain a signature for an unsigned warp message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarpSignerError {
    /// The remote signer (MetalGo) was unreachable or returned an error.
    Transport(String),
    /// The signer returned bytes that were not a valid BLS signature.
    MalformedSignature,
}

impl core::fmt::Display for WarpSignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WarpSignerError::Transport(m) => write!(f, "warp signer transport error: {m}"),
            WarpSignerError::MalformedSignature => write!(f, "warp signer returned bad signature"),
        }
    }
}

impl std::error::Error for WarpSignerError {}

/// Something that can sign an [`UnsignedMessage`] with the local validator's BLS
/// key. Validators sign the *serialized unsigned message bytes* (not the id) —
/// the same preimage [`super::verify`] checks against.
pub trait WarpSigner: Send + Sync {
    /// Sign the unsigned message, returning the BLS signature over its bytes.
    fn sign(&self, message: &UnsignedMessage) -> Result<Signature, WarpSignerError>;

    /// The BLS public key corresponding to the signing key. Used to place this
    /// validator in the canonical set and to sanity-check produced signatures.
    fn public_key(&self) -> PublicKey;
}

/// A [`WarpSigner`] that holds the secret key and signs in-process with `blst`.
///
/// Used on local/dev networks and wherever MetalGo makes the signing key
/// available to the plugin. Produces real, verifiable BLS signatures.
pub struct LocalBlsSigner {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl LocalBlsSigner {
    pub fn new(secret_key: SecretKey) -> Self {
        let public_key = secret_key.public_key();
        LocalBlsSigner {
            secret_key,
            public_key,
        }
    }

    /// Derive a signer deterministically from input keying material. Convenient
    /// for tests and reproducible local clusters.
    pub fn from_ikm(ikm: &[u8]) -> Result<Self, WarpSignerError> {
        let sk = SecretKey::from_ikm(ikm)
            .map_err(|e| WarpSignerError::Transport(e.to_string()))?;
        Ok(Self::new(sk))
    }
}

impl WarpSigner for LocalBlsSigner {
    fn sign(&self, message: &UnsignedMessage) -> Result<Signature, WarpSignerError> {
        Ok(self.secret_key.sign(&message.to_bytes()))
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }
}

/// Assert that a signature produced for `message` verifies under `public_key`.
/// A defensive check used after signing to catch a misbehaving remote signer
/// before a bad signature is ever put in the outbox.
pub fn verify_own_signature(
    public_key: &PublicKey,
    message: &UnsignedMessage,
    signature: &Signature,
) -> bool {
    bls::verify(public_key, signature, &message.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_signer_produces_verifiable_signature() {
        let signer = LocalBlsSigner::from_ikm(&[42u8; 32]).unwrap();
        let msg = UnsignedMessage::new(1, [5u8; 32], b"hello world".to_vec());
        let sig = signer.sign(&msg).unwrap();
        assert!(verify_own_signature(&signer.public_key(), &msg, &sig));
    }

    #[test]
    fn signature_is_bound_to_message() {
        let signer = LocalBlsSigner::from_ikm(&[1u8; 32]).unwrap();
        let msg = UnsignedMessage::new(1, [0u8; 32], b"a".to_vec());
        let other = UnsignedMessage::new(1, [0u8; 32], b"b".to_vec());
        let sig = signer.sign(&msg).unwrap();
        assert!(!verify_own_signature(&signer.public_key(), &other, &sig));
    }
}
