use std::collections::BTreeSet;

use pulsevm_crypto::{
    AuthorityPublicKey,
    Bytes,
};
use pulsevm_error::ChainError;
use pulsevm_proc_macros::{
    NumBytes,
    Read,
    Write,
};
use pulsevm_serialization::Write;
use serde::Serialize;
use sha2::Digest as Sha2Digest;

use crate::{
    chain::{
        id::Id,
        transaction::transaction::Transaction,
    },
    crypto::{
        PrivateKey,
        PublicKey,
        Signature,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Serialize, Default)]
pub struct SignedTransaction {
    transaction: Transaction,
    signatures: BTreeSet<Signature>,
    context_free_data: Vec<Bytes>,
}

impl SignedTransaction {
    #[inline]
    pub fn new(
        transaction: Transaction,
        signatures: BTreeSet<Signature>,
        context_free_data: Vec<Bytes>,
    ) -> Self {
        Self {
            transaction,
            signatures,
            context_free_data,
        }
    }

    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub fn signatures(&self) -> &BTreeSet<Signature> {
        &self.signatures
    }

    pub fn context_free_data(&self) -> &Vec<Bytes> {
        &self.context_free_data
    }

    /// Leap's `tx_duplicate_sig`.
    ///
    /// `transaction::get_signature_keys` asserts
    /// `allow_duplicate_keys || successful_insertion` on every recovery, and
    /// both of the paths that reach here want the strict form -- the flag exists
    /// upstream for callers that do not, and there are none here.
    fn duplicate_signature_key() -> ChainError {
        ChainError::TransactionError(
            "transaction includes more than one signature signed using the same key".to_string(),
        )
    }

    #[must_use]
    #[inline]
    pub fn recovered_keys(&self, chain_id: &Id) -> Result<BTreeSet<PublicKey>, ChainError> {
        let mut recovered_keys: BTreeSet<PublicKey> = BTreeSet::new();
        let digest = self
            .transaction
            .signing_digest(chain_id, &self.context_free_data)?;
        let digest = pulsevm_crypto::Digest(digest);

        for signature in self.signatures.iter() {
            let public_key = signature.recover_public_key(&digest)?;
            // Collapsing a duplicate silently is what let extra signatures ride
            // along: `all_keys_used()` still passed, while the NET billed for
            // them did not shrink. Reject instead, as Leap does.
            if !recovered_keys.insert(public_key) {
                return Err(Self::duplicate_signature_key());
            }
        }

        Ok(recovered_keys)
    }

    /// Recover all public-key variants supported by transaction signatures.
    #[must_use]
    #[inline]
    pub fn recovered_authority_keys(
        &self,
        chain_id: &Id,
    ) -> Result<BTreeSet<AuthorityPublicKey>, ChainError> {
        let mut recovered_keys = BTreeSet::new();
        let digest = self
            .transaction
            .signing_digest(chain_id, &self.context_free_data)?;
        let digest = pulsevm_crypto::Digest(digest);

        for signature in &self.signatures {
            // As in `recovered_keys`: a duplicate must be an error, not a
            // silent collapse. Failing here also stops the recovery loop at the
            // offending signature rather than paying for every remaining one.
            if !recovered_keys.insert(signature.recover_authority_key(&digest)?) {
                return Err(Self::duplicate_signature_key());
            }
        }

        Ok(recovered_keys)
    }

    #[inline]
    pub fn sign(mut self, private_key: &PrivateKey, chain_id: &Id) -> Result<Self, ChainError> {
        let digest = self
            .transaction
            .signing_digest(chain_id, &self.context_free_data)?;
        let signature = private_key.sign(&pulsevm_crypto::Digest(digest))?;
        self.signatures.insert(signature);
        Ok(self)
    }
}

#[inline]
pub fn signing_digest(
    chain_id: &Id,
    trx_bytes: &Vec<u8>,
    cfd_bytes: &Vec<Bytes>,
) -> Result<[u8; 32], ChainError> {
    let cf_hash = if cfd_bytes.is_empty() {
        [0u8; 32]
    } else {
        let cfd_bytes = cfd_bytes.pack().map_err(|e| {
            ChainError::SerializationError(format!("failed to pack transaction: {}", e))
        })?;
        sha2::Sha256::digest(&cfd_bytes).into()
    };

    // main signing hash
    let mut hasher = sha2::Sha256::new();
    hasher.update(&chain_id.0);
    hasher.update(trx_bytes);
    hasher.update(&cf_hash);

    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        str::FromStr,
    };

    use pulsevm_database::TimePointSec;

    use pulsevm_crypto::K1Signature;
    use secp256k1::{
        Message,
        SECP256K1,
        SecretKey,
    };

    use crate::{
        crypto::{
            PrivateKey,
            Signature,
        },
        id::Id,
        transaction::{
            SignedTransaction,
            Transaction,
            TransactionHeader,
        },
    };

    /// A transaction with no actions, signed by `keys`.
    fn transaction_signed_by(sigs: BTreeSet<Signature>) -> (SignedTransaction, Id) {
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let tx = SignedTransaction::new(
            Transaction::new(
                TransactionHeader::new(TimePointSec::new(100), 1, 2, 4.into(), 3, 5.into()),
                vec![],
                vec![],
            ),
            sigs,
            vec![],
        );
        (tx, chain_id)
    }

    /// Two *distinct* canonical signatures over the same digest from the same
    /// key, which is what an attacker padding a transaction actually produces.
    ///
    /// `PrivateKey::sign` grinds a deterministic RFC6979 nonce, so it cannot
    /// yield two different signatures on its own; `..._with_noncedata` varies
    /// the nonce while staying inside RFC6979, exactly the case libsecp256k1
    /// documents it for.
    fn two_signatures_same_key(digest: &[u8; 32]) -> (Signature, Signature) {
        let secret = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let msg = Message::from_digest(*digest);

        let mut made = Vec::new();
        for seed in 0u8..64 {
            let sig = SECP256K1.sign_ecdsa_recoverable_with_noncedata(&msg, &secret, &[seed; 32]);
            let (recid, compact) = sig.serialize_compact();
            let mut bytes = [0u8; 65];
            bytes[0] = 31 + i32::from(recid) as u8;
            bytes[1..].copy_from_slice(&compact);
            let k1 = K1Signature::from_compact65(&bytes);
            // Only canonical ones, so this test stays valid once the canonical
            // check lands on the recovery path.
            if k1.is_canonical() {
                made.push(Signature::new(k1));
                if made.len() == 2 {
                    break;
                }
            }
        }
        assert_eq!(made.len(), 2, "expected two canonical signatures");
        (made[0].clone(), made[1].clone())
    }

    /// Leap throws `tx_duplicate_sig` here. Collapsing the duplicate into a
    /// `BTreeSet` instead meant `all_keys_used()` still passed while the NET
    /// billed for the extra signatures did not shrink -- the amplification half
    /// of the signature-malleability censorship vector.
    #[test]
    fn duplicate_recovered_keys_are_rejected() {
        let (tx, chain_id) = transaction_signed_by(BTreeSet::new());
        let digest = tx
            .transaction
            .signing_digest(&chain_id, &tx.context_free_data)
            .unwrap();

        let (first, second) = two_signatures_same_key(&digest);
        assert_ne!(
            first, second,
            "the two signatures must be distinct on the wire"
        );

        let mut sigs = BTreeSet::new();
        sigs.insert(first);
        sigs.insert(second);
        assert_eq!(sigs.len(), 2, "both must survive wire-level dedup");

        let (padded, chain_id) = transaction_signed_by(sigs);

        let err = padded
            .recovered_authority_keys(&chain_id)
            .expect_err("two signatures recovering one key must be rejected");
        assert!(
            err.to_string()
                .contains("more than one signature signed using the same key"),
            "expected a duplicate-signature error, got: {err}"
        );

        // The K1-only path must agree.
        let err = padded
            .recovered_keys(&chain_id)
            .expect_err("recovered_keys must reject duplicates too");
        assert!(
            err.to_string()
                .contains("more than one signature signed using the same key"),
            "expected a duplicate-signature error, got: {err}"
        );
    }

    /// The check must not fire on a legitimately multi-signed transaction --
    /// two *different* keys is the normal multisig case.
    #[test]
    fn distinct_keys_are_still_accepted() {
        let (tx, chain_id) = transaction_signed_by(BTreeSet::new());

        let signed = tx
            .clone()
            .sign(&PrivateKey::random(), &chain_id)
            .unwrap()
            .sign(&PrivateKey::random(), &chain_id)
            .unwrap();
        assert_eq!(signed.signatures().len(), 2);

        let keys = signed
            .recovered_authority_keys(&chain_id)
            .expect("two distinct keys must be accepted");
        assert_eq!(keys.len(), 2, "both keys must be recovered");
    }

    /// A single signature is the overwhelmingly common case and must be
    /// untouched.
    #[test]
    fn a_single_signature_is_unaffected() {
        let (tx, chain_id) = transaction_signed_by(BTreeSet::new());
        let key = PrivateKey::random();
        let signed = tx.sign(&key, &chain_id).unwrap();

        let keys = signed.recovered_authority_keys(&chain_id).unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn test_signing_digest() {
        let private_key =
            PrivateKey::from_str("PVT_K1_2pjSqJxTbRHq8h8aHHTux81Ypscb36Q2syB8UJbZcUmxbfZdnT")
                .unwrap();
        let public_key = private_key.get_public_key();
        let tx = SignedTransaction::new(
            Transaction::new(
                TransactionHeader::new(TimePointSec::new(100), 1, 2, 4.into(), 3, 5.into()),
                vec![],
                vec![],
            ),
            BTreeSet::new(),
            vec![],
        );
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let signing_digest = tx
            .transaction
            .signing_digest(&chain_id, &tx.context_free_data)
            .unwrap();
        let hex_digest = hex::encode(signing_digest);
        assert_eq!(
            hex_digest,
            "667bb523586b34e4bff2913b421ddd356e0c9db5bc83c93fd65092d18bcdeeac"
        );
        let signed_tx = tx.sign(&private_key, &chain_id).unwrap();
        assert_eq!(signed_tx.signatures.len(), 1);
        let recovered_keys = signed_tx.recovered_keys(&chain_id).unwrap();
        assert_eq!(recovered_keys.len(), 1);
        assert!(recovered_keys.contains(&public_key));
    }
}
