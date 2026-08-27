//! The VM-facing entry point for cross-chain messaging.
//!
//! [`WarpManager`] is what the WASM host functions call. It binds the two things
//! that are constant for a running chain — this chain's Avalanche `network_id`
//! and blockchain id — to the swappable boundaries (the local BLS signer and the
//! source-chain validator lookup), and exposes the two operations a contract
//! needs:
//!
//! * [`WarpManager::emit`] — turn a contract's `(source_address, payload)` into an
//!   [`UnsignedMessage`] addressed from this chain. The caller records it so the
//!   node signs it and a relayer can carry it onward.
//! * [`WarpManager::verify`] — check a fully-signed inbound [`Message`] against the
//!   source subnet's validator set and hand the contract back the authenticated
//!   payload.
//!
//! Aggregating validator signatures into the [`Message`] is the relayer's job,
//! not the VM's — the VM only *produces* unsigned messages and *verifies* signed
//! ones. That split matches AvalancheGo.

use std::sync::Arc;

use pulsevm_error::ChainError;

use super::{
    message::{
        Message,
        UnsignedMessage,
    },
    payload::AddressedCall,
    signer::WarpSigner,
    validator_source::ValidatorSetSource,
    verify::{
        self,
        DEFAULT_QUORUM_NUMERATOR,
        QUORUM_DENOMINATOR,
    },
};

/// An authenticated inbound message, handed to a contract after verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMessage {
    /// The 32-byte blockchain id the message came from.
    pub source_chain_id: [u8; 32],
    /// The sending address on the source chain (from the `AddressedCall`).
    pub source_address: Vec<u8>,
    /// The application payload the destination contract consumes.
    pub payload: Vec<u8>,
    /// The message id (sha256 of the unsigned bytes) — a contract uses this as a
    /// replay-protection key, since verification itself is stateless.
    pub id: [u8; 32],
}

/// Binds a chain's identity to the signer and validator-lookup boundaries.
#[derive(Clone)]
pub struct WarpManager {
    network_id: u32,
    source_chain_id: [u8; 32],
    signer: Option<Arc<dyn WarpSigner>>,
    validators: Arc<dyn ValidatorSetSource>,
    quorum_num: u64,
    quorum_den: u64,
}

impl WarpManager {
    /// Build a manager for a chain. `signer` is `None` on nodes that don't hold a
    /// signing key (non-validators, or where MetalGo signs remotely and the
    /// transport is attached separately).
    pub fn new(
        network_id: u32,
        source_chain_id: [u8; 32],
        signer: Option<Arc<dyn WarpSigner>>,
        validators: Arc<dyn ValidatorSetSource>,
    ) -> Self {
        WarpManager {
            network_id,
            source_chain_id,
            signer,
            validators,
            quorum_num: DEFAULT_QUORUM_NUMERATOR,
            quorum_den: QUORUM_DENOMINATOR,
        }
    }

    /// Override the quorum fraction (defaults to 67%).
    pub fn with_quorum(mut self, numerator: u64, denominator: u64) -> Self {
        self.quorum_num = numerator;
        self.quorum_den = denominator;
        self
    }

    pub fn network_id(&self) -> u32 {
        self.network_id
    }

    pub fn source_chain_id(&self) -> [u8; 32] {
        self.source_chain_id
    }

    /// Whether this node can sign warp messages locally.
    pub fn can_sign(&self) -> bool {
        self.signer.is_some()
    }

    /// Build an unsigned, addressed cross-chain message from this chain.
    ///
    /// The payload is wrapped in an [`AddressedCall`] naming `source_address`
    /// (for PulseVM, the emitting account), then placed in an [`UnsignedMessage`]
    /// stamped with this chain's network and blockchain id.
    pub fn emit(&self, source_address: Vec<u8>, payload: Vec<u8>) -> UnsignedMessage {
        let call = AddressedCall::new(source_address, payload);
        UnsignedMessage::new(self.network_id, self.source_chain_id, call.to_bytes())
    }

    /// Sign an unsigned message with the local key, if this node has one. Returns
    /// the raw BLS signature bytes (a relayer aggregates these across validators).
    pub fn sign(&self, message: &UnsignedMessage) -> Result<[u8; 96], ChainError> {
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| ChainError::WarpError("node has no warp signing key".into()))?;
        let sig = signer
            .sign(message)
            .map_err(|e| ChainError::WarpError(e.to_string()))?;
        Ok(sig.to_bytes())
    }

    /// Verify a fully-signed inbound message and extract its authenticated
    /// payload. Stateless: replay protection is the calling contract's job, keyed
    /// on [`VerifiedMessage::id`].
    pub fn verify(&self, message_bytes: &[u8]) -> Result<VerifiedMessage, ChainError> {
        let message = Message::from_bytes(message_bytes)
            .map_err(|e| ChainError::WarpError(format!("malformed message: {e}")))?;

        // A message signed for a different Avalanche network must never verify
        // here, even if the signature math happened to line up.
        if message.unsigned.network_id != self.network_id {
            return Err(ChainError::WarpError(format!(
                "message network id {} does not match local network id {}",
                message.unsigned.network_id, self.network_id
            )));
        }

        let source_chain_id = message.unsigned.source_chain_id;
        let validators = self
            .validators
            .validator_set(&source_chain_id)
            .ok_or_else(|| {
                ChainError::WarpError(format!(
                    "unknown source chain {}",
                    hex::encode(source_chain_id)
                ))
            })?;

        verify::verify_message_with_quorum(
            &message,
            &validators,
            self.quorum_num,
            self.quorum_den,
        )
        .map_err(|e| ChainError::WarpError(e.to_string()))?;

        let call = AddressedCall::from_bytes(&message.unsigned.payload)
            .map_err(|e| ChainError::WarpError(format!("malformed addressed call: {e}")))?;

        Ok(VerifiedMessage {
            source_chain_id,
            source_address: call.source_address,
            payload: call.payload,
            id: message.unsigned.id(),
        })
    }
}

#[cfg(test)]
mod tests {
    use pulsevm_crypto::bls::{
        self,
        SecretKey,
    };

    use super::*;
    use crate::chain::warp::{
        message::BitSetSignature,
        signer::LocalBlsSigner,
        validator::{
            CanonicalValidatorSet,
            SignerBitset,
            Validator,
        },
        validator_source::StaticValidatorSource,
    };

    // Chain A (source) and chain B (destination) ids.
    const CHAIN_A: [u8; 32] = [0xAA; 32];
    const NETWORK: u32 = 1000;

    /// A validator set for chain A of three equally-weighted signers.
    fn chain_a_validators() -> (Vec<SecretKey>, CanonicalValidatorSet) {
        let sks: Vec<SecretKey> = (0u8..3)
            .map(|i| SecretKey::from_ikm(&[i + 1; 32]).unwrap())
            .collect();
        let set = CanonicalValidatorSet::new(
            sks.iter()
                .map(|sk| Validator {
                    public_key: sk.public_key(),
                    weight: 10,
                })
                .collect(),
        );
        (sks, set)
    }

    /// Relayer step: given an unsigned message and the source validators, have
    /// all of them sign and aggregate into a signed `Message`.
    fn relayer_sign(
        unsigned: &UnsignedMessage,
        sks: &[SecretKey],
        set: &CanonicalValidatorSet,
    ) -> Message {
        let msg_bytes = unsigned.to_bytes();
        let mut idxs = Vec::new();
        let mut sigs = Vec::new();
        for (canonical_idx, v) in set.validators().iter().enumerate() {
            let sk = sks
                .iter()
                .find(|s| s.public_key().to_bytes() == v.public_key.to_bytes())
                .unwrap();
            idxs.push(canonical_idx);
            sigs.push(sk.sign(&msg_bytes));
        }
        let agg = bls::aggregate_signatures(&sigs).unwrap();
        Message::new(
            unsigned.clone(),
            BitSetSignature {
                signers: SignerBitset::from_indices(&idxs).as_bytes().to_vec(),
                signature: agg.to_bytes(),
            },
        )
    }

    fn dest_manager(source_set: CanonicalValidatorSet) -> WarpManager {
        let mut src = StaticValidatorSource::new();
        src.insert(CHAIN_A, source_set);
        WarpManager::new(NETWORK, [0xBB; 32], None, Arc::new(src))
    }

    #[test]
    fn end_to_end_emit_sign_verify() {
        let (sks, set) = chain_a_validators();

        // Source chain A emits a message from account "pulse.token".
        let signer = Arc::new(LocalBlsSigner::new(sks[0].clone())) as Arc<dyn WarpSigner>;
        let source_mgr = WarpManager::new(
            NETWORK,
            CHAIN_A,
            Some(signer),
            Arc::new(StaticValidatorSource::new()),
        );
        let unsigned = source_mgr.emit(b"pulse.token".to_vec(), b"mint(bob,100)".to_vec());
        assert_eq!(unsigned.source_chain_id, CHAIN_A);
        assert_eq!(unsigned.network_id, NETWORK);

        // Relayer collects validator signatures.
        let signed = relayer_sign(&unsigned, &sks, &set);

        // Destination chain B verifies and extracts the payload.
        let dest = dest_manager(set);
        let verified = dest.verify(&signed.to_bytes()).unwrap();
        assert_eq!(verified.source_chain_id, CHAIN_A);
        assert_eq!(verified.source_address, b"pulse.token");
        assert_eq!(verified.payload, b"mint(bob,100)");
        assert_eq!(verified.id, unsigned.id());
    }

    #[test]
    fn verify_rejects_wrong_network() {
        let (sks, set) = chain_a_validators();
        let source_mgr = WarpManager::new(
            9999, // different network
            CHAIN_A,
            None,
            Arc::new(StaticValidatorSource::new()),
        );
        let unsigned = source_mgr.emit(b"a".to_vec(), b"b".to_vec());
        let signed = relayer_sign(&unsigned, &sks, &set);

        let dest = dest_manager(set);
        let err = dest.verify(&signed.to_bytes()).unwrap_err();
        assert!(matches!(err, ChainError::WarpError(_)));
    }

    #[test]
    fn verify_rejects_unknown_source_chain() {
        let (sks, set) = chain_a_validators();
        let source_mgr =
            WarpManager::new(NETWORK, [0xCC; 32], None, Arc::new(StaticValidatorSource::new()));
        let unsigned = source_mgr.emit(b"a".to_vec(), b"b".to_vec());
        let signed = relayer_sign(&unsigned, &sks, &set);

        // Destination only knows CHAIN_A, not 0xCC.
        let dest = dest_manager(set);
        assert!(dest.verify(&signed.to_bytes()).is_err());
    }

    #[test]
    fn verify_rejects_insufficient_stake() {
        let (sks, set) = chain_a_validators();
        let source_mgr =
            WarpManager::new(NETWORK, CHAIN_A, None, Arc::new(StaticValidatorSource::new()));
        let unsigned = source_mgr.emit(b"a".to_vec(), b"b".to_vec());

        // Only one of three validators signs -> 33% < 67%.
        let msg_bytes = unsigned.to_bytes();
        let sig = sks
            .iter()
            .find(|s| s.public_key().to_bytes() == set.validators()[0].public_key.to_bytes())
            .unwrap()
            .sign(&msg_bytes);
        let signed = Message::new(
            unsigned.clone(),
            BitSetSignature {
                signers: SignerBitset::from_indices(&[0]).as_bytes().to_vec(),
                signature: sig.to_bytes(),
            },
        );

        let dest = dest_manager(set);
        assert!(dest.verify(&signed.to_bytes()).is_err());
    }

    #[test]
    fn sign_requires_key() {
        let mgr = WarpManager::new(NETWORK, CHAIN_A, None, Arc::new(StaticValidatorSource::new()));
        let unsigned = mgr.emit(b"a".to_vec(), b"b".to_vec());
        assert!(mgr.sign(&unsigned).is_err());
        assert!(!mgr.can_sign());
    }

    #[test]
    fn local_signature_is_valid_over_emitted_message() {
        let sk = SecretKey::from_ikm(&[42u8; 32]).unwrap();
        let pk = sk.public_key();
        let signer = Arc::new(LocalBlsSigner::new(sk)) as Arc<dyn WarpSigner>;
        let mgr = WarpManager::new(
            NETWORK,
            CHAIN_A,
            Some(signer),
            Arc::new(StaticValidatorSource::new()),
        );
        let unsigned = mgr.emit(b"acct".to_vec(), b"data".to_vec());
        let sig_bytes = mgr.sign(&unsigned).unwrap();
        let sig = bls::Signature::from_bytes(&sig_bytes).unwrap();
        assert!(bls::verify(&pk, &sig, &unsigned.to_bytes()));
    }
}
