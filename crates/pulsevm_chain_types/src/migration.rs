//! XPR halt commitment: the old network's signed promise to stop at H.
//!
//! Customer continuity rests on the swap, not on either chain alone: the XPR
//! producers commit to never authoring past H, the new network verifies that
//! commitment against the old schedule's keys before authoring H+1, and the
//! replay terminates. This module defines the commitment wire format and its
//! verification. Both commitment versions verify against the attached
//! weighted roster under the strict two-thirds quorum; a roster-less
//! (single-key) commitment is rejected everywhere. The restore gate
//! additionally requires the two-step pair (declaration + confirmation +
//! on-chain ceremony): a manifest without it restores nothing.

use pulsevm_crypto::{
    Digest,
    k1::{
        K1PublicKey,
        K1Signature,
    },
};
use pulsevm_error::ChainError;
use serde::{
    Deserialize,
    Serialize,
};

/// Domain separator for the signed halt message (versioned with the format).
pub const HALT_DOMAIN: &[u8] = b"PULSEVM-XPR-HALT-v1";
/// Domain separator for version 2, which additionally binds the migration
/// checkpoint hash so a commitment cannot be replayed onto another export.
pub const HALT_DOMAIN_V2: &[u8] = b"PULSEVM-XPR-HALT-v2";

/// One producer's signature over the halt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaltSignature {
    /// Producer name (informational; authorization rides on the key).
    pub producer: String,
    /// Signing key in `PUB_K1_` or legacy `EOS` form.
    pub key: String,
    /// `SIG_K1_` signature over [`halt_digest`] for this halt.
    pub signature: String,
}

/// The old network's commitment to freeze at a terminal block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaltCommitment {
    pub version: u16,
    /// Terminal height: no valid source block may number above this.
    pub halt_height: u32,
    /// 64-hex id of the terminal block.
    pub halt_block_id: String,
    /// 64-hex SHA-256 of the migration checkpoint this halt is bound to.
    /// `None` for version 1 commitments; required for version 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_sha256: Option<String>,
    /// Old-schedule producer keys a commitment signature may come from.
    pub producer_keys: Vec<String>,
    pub signatures: Vec<HaltSignature>,
}

impl HaltCommitment {
    pub const VERSION: u16 = 1;
    pub const VERSION_V2: u16 = 2;

    /// Canonical message: domain || height-be64 || block-id.
    pub fn message_bytes(halt_height: u32, halt_block_id: &[u8; 32]) -> Vec<u8> {
        let mut message = Vec::with_capacity(HALT_DOMAIN.len() + 4 + 32);
        message.extend_from_slice(HALT_DOMAIN);
        message.extend_from_slice(&halt_height.to_be_bytes());
        message.extend_from_slice(halt_block_id);
        message
    }

    /// Signing digest for a halt.
    pub fn digest(halt_height: u32, halt_block_id: &[u8; 32]) -> [u8; 32] {
        *Digest::hash(Self::message_bytes(halt_height, halt_block_id)).as_bytes()
    }

    /// Canonical version 2 message: v2 domain || height || block-id || checkpoint.
    pub fn message_bytes_v2(
        halt_height: u32,
        halt_block_id: &[u8; 32],
        checkpoint_sha256: &[u8; 32],
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(HALT_DOMAIN_V2.len() + 4 + 32 + 32);
        message.extend_from_slice(HALT_DOMAIN_V2);
        message.extend_from_slice(&halt_height.to_be_bytes());
        message.extend_from_slice(halt_block_id);
        message.extend_from_slice(checkpoint_sha256);
        message
    }

    /// Signing digest for a checkpoint-bound version 2 halt.
    pub fn digest_v2(
        halt_height: u32,
        halt_block_id: &[u8; 32],
        checkpoint_sha256: &[u8; 32],
    ) -> [u8; 32] {
        *Digest::hash(Self::message_bytes_v2(
            halt_height,
            halt_block_id,
            checkpoint_sha256,
        ))
        .as_bytes()
    }

    /// Shared terminal-block check: version, height, and id must match.
    /// Returns the decoded committed block id.
    fn check_terminal(
        &self,
        expected_height: u32,
        expected_block_id: &[u8; 32],
    ) -> Result<[u8; 32], ChainError> {
        if self.version != Self::VERSION {
            return Err(ChainError::InternalError(format!(
                "unsupported halt commitment version {}",
                self.version
            )));
        }
        if self.halt_height != expected_height {
            return Err(ChainError::InternalError(format!(
                "halt commitment height {} does not match terminal height {}",
                self.halt_height, expected_height
            )));
        }
        let committed_id = decode_hex_32(&self.halt_block_id).map_err(|e| {
            ChainError::InternalError(format!("halt commitment block id invalid: {e}"))
        })?;
        if committed_id != *expected_block_id {
            return Err(ChainError::InternalError(
                "halt commitment block id does not match the terminal block".into(),
            ));
        }
        Ok(committed_id)
    }

    /// Verify this commitment against the expected terminal block: version,
    /// height, and id must match, every signature must come from a listed
    /// producer key, and at least one signature must recover to its claimed
    /// key over the halt digest.
    pub fn verify(
        &self,
        expected_height: u32,
        expected_block_id: &[u8; 32],
    ) -> Result<(), ChainError> {
        let committed_id = self.check_terminal(expected_height, expected_block_id)?;
        let schedule: Vec<K1PublicKey> = self
            .producer_keys
            .iter()
            .map(|key| {
                K1PublicKey::from_string(key).map_err(|e| {
                    ChainError::InternalError(format!("halt producer key invalid: {e:?}"))
                })
            })
            .collect::<Result<_, _>>()?;
        let digest = Self::digest(self.halt_height, &committed_id);
        let mut valid = 0u32;
        for entry in &self.signatures {
            let claimed = K1PublicKey::from_string(&entry.key).map_err(|e| {
                ChainError::InternalError(format!("halt signature key invalid: {e:?}"))
            })?;
            if !schedule.contains(&claimed) {
                return Err(ChainError::InternalError(format!(
                    "halt signature from producer {} is not in the committed schedule",
                    entry.producer
                )));
            }
            let signature = K1Signature::from_string(&entry.signature).map_err(|e| {
                ChainError::InternalError(format!("halt signature malformed: {e:?}"))
            })?;
            let recovered = signature.recover(&digest).map_err(|e| {
                ChainError::InternalError(format!("halt signature unrecoverable: {e:?}"))
            })?;
            if recovered != claimed {
                return Err(ChainError::InternalError(format!(
                    "halt signature from producer {} does not verify",
                    entry.producer
                )));
            }
            valid += 1;
        }
        if valid == 0 {
            return Err(ChainError::InternalError(
                "halt commitment carries no valid producer signature".into(),
            ));
        }
        Ok(())
    }

    /// Verify this commitment against a weighted producer roster (the
    /// on-chain ceremony): version, height, and id must match, every
    /// signature must recover to a rostered key over the halt digest, and the
    /// signers' combined weight must reach two thirds of the roster weight.
    /// Each producer's weight counts once no matter how often it signed.
    /// Integer cross-multiplication (`signed * 3 >= total * 2`, in u128) sets
    /// the threshold with no float rounding; an empty or all-zero roster
    /// fails closed.
    pub fn verify_weighted_quorum(
        &self,
        expected_height: u32,
        expected_block_id: &[u8; 32],
        roster: &[HaltRosterEntry],
    ) -> Result<(), ChainError> {
        let committed_id = self.check_terminal(expected_height, expected_block_id)?;
        let total: u128 = roster.iter().map(|entry| entry.weight.0).sum();
        if roster.is_empty() || total == 0 {
            return Err(ChainError::InternalError(
                "halt commitment roster carries no weight".into(),
            ));
        }
        let digest = Self::digest(self.halt_height, &committed_id);
        let mut signed: std::collections::HashSet<K1PublicKey> = std::collections::HashSet::new();
        for entry in &self.signatures {
            let claimed = K1PublicKey::from_string(&entry.key).map_err(|e| {
                ChainError::InternalError(format!("halt signature key invalid: {e:?}"))
            })?;
            if !roster.iter().any(|rostered| rostered.key == claimed) {
                return Err(ChainError::InternalError(format!(
                    "halt signature from producer {} is not in the committed schedule",
                    entry.producer
                )));
            }
            let signature = K1Signature::from_string(&entry.signature).map_err(|e| {
                ChainError::InternalError(format!("halt signature malformed: {e:?}"))
            })?;
            let recovered = signature.recover(&digest).map_err(|e| {
                ChainError::InternalError(format!("halt signature unrecoverable: {e:?}"))
            })?;
            if recovered != claimed {
                return Err(ChainError::InternalError(format!(
                    "halt signature from producer {} does not verify",
                    entry.producer
                )));
            }
            signed.insert(claimed);
        }
        let signed_weight: u128 = roster
            .iter()
            .filter(|entry| signed.contains(&entry.key))
            .map(|entry| entry.weight.0)
            .sum();
        if signed_weight * 3 < total * 2 {
            return Err(ChainError::InternalError(format!(
                "halt commitment weight {signed_weight} below two-thirds quorum of {total}"
            )));
        }
        Ok(())
    }

    /// Shared version 2 terminal-block check: version, height, id, and the
    /// checkpoint binding must all match. Returns the decoded block id and
    /// checkpoint hash.
    fn check_terminal_v2(
        &self,
        expected_height: u32,
        expected_block_id: &[u8; 32],
        expected_checkpoint: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), ChainError> {
        if self.version != Self::VERSION_V2 {
            return Err(ChainError::InternalError(format!(
                "unsupported halt commitment version {} (expected {})",
                self.version,
                Self::VERSION_V2
            )));
        }
        if self.halt_height != expected_height {
            return Err(ChainError::InternalError(format!(
                "halt commitment height {} does not match terminal height {}",
                self.halt_height, expected_height
            )));
        }
        let committed_id = decode_hex_32(&self.halt_block_id).map_err(|e| {
            ChainError::InternalError(format!("halt commitment block id invalid: {e}"))
        })?;
        if committed_id != *expected_block_id {
            return Err(ChainError::InternalError(
                "halt commitment block id does not match the terminal block".into(),
            ));
        }
        let Some(bound) = self.checkpoint_sha256.as_deref() else {
            return Err(ChainError::InternalError(
                "version 2 halt commitment carries no checkpoint binding".into(),
            ));
        };
        let committed_checkpoint = decode_hex_32(bound).map_err(|e| {
            ChainError::InternalError(format!("halt commitment checkpoint binding invalid: {e}"))
        })?;
        if committed_checkpoint != *expected_checkpoint {
            return Err(ChainError::InternalError(
                "halt commitment checkpoint binding does not match the migration checkpoint".into(),
            ));
        }
        Ok((committed_id, committed_checkpoint))
    }

    /// Verify a version 2 checkpoint-bound commitment: same single-key rule
    /// as [`Self::verify`], but signatures must be over the v2 digest that
    /// binds the migration checkpoint hash.
    pub fn verify_v2(
        &self,
        expected_height: u32,
        expected_block_id: &[u8; 32],
        expected_checkpoint: &[u8; 32],
    ) -> Result<(), ChainError> {
        let (committed_id, committed_checkpoint) =
            self.check_terminal_v2(expected_height, expected_block_id, expected_checkpoint)?;
        let schedule: Vec<K1PublicKey> = self
            .producer_keys
            .iter()
            .map(|key| {
                K1PublicKey::from_string(key).map_err(|e| {
                    ChainError::InternalError(format!("halt producer key invalid: {e:?}"))
                })
            })
            .collect::<Result<_, _>>()?;
        let digest = Self::digest_v2(self.halt_height, &committed_id, &committed_checkpoint);
        let mut valid = 0u32;
        for entry in &self.signatures {
            let claimed = K1PublicKey::from_string(&entry.key).map_err(|e| {
                ChainError::InternalError(format!("halt signature key invalid: {e:?}"))
            })?;
            if !schedule.contains(&claimed) {
                return Err(ChainError::InternalError(format!(
                    "halt signature from producer {} is not in the committed schedule",
                    entry.producer
                )));
            }
            let signature = K1Signature::from_string(&entry.signature).map_err(|e| {
                ChainError::InternalError(format!("halt signature malformed: {e:?}"))
            })?;
            let recovered = signature.recover(&digest).map_err(|e| {
                ChainError::InternalError(format!("halt signature unrecoverable: {e:?}"))
            })?;
            if recovered != claimed {
                return Err(ChainError::InternalError(format!(
                    "halt signature from producer {} does not verify",
                    entry.producer
                )));
            }
            valid += 1;
        }
        if valid == 0 {
            return Err(ChainError::InternalError(
                "halt commitment carries no valid producer signature".into(),
            ));
        }
        Ok(())
    }

    /// Verify a version 2 commitment against a weighted producer roster:
    /// same two-thirds rule as [`Self::verify_weighted_quorum`], over the
    /// checkpoint-bound v2 digest.
    pub fn verify_weighted_quorum_v2(
        &self,
        expected_height: u32,
        expected_block_id: &[u8; 32],
        expected_checkpoint: &[u8; 32],
        roster: &[HaltRosterEntry],
    ) -> Result<(), ChainError> {
        let (committed_id, committed_checkpoint) =
            self.check_terminal_v2(expected_height, expected_block_id, expected_checkpoint)?;
        let total: u128 = roster.iter().map(|entry| entry.weight.0).sum();
        if roster.is_empty() || total == 0 {
            return Err(ChainError::InternalError(
                "halt commitment roster carries no weight".into(),
            ));
        }
        let digest = Self::digest_v2(self.halt_height, &committed_id, &committed_checkpoint);
        let mut signed: std::collections::HashSet<K1PublicKey> = std::collections::HashSet::new();
        for entry in &self.signatures {
            let claimed = K1PublicKey::from_string(&entry.key).map_err(|e| {
                ChainError::InternalError(format!("halt signature key invalid: {e:?}"))
            })?;
            if !roster.iter().any(|rostered| rostered.key == claimed) {
                return Err(ChainError::InternalError(format!(
                    "halt signature from producer {} is not in the committed schedule",
                    entry.producer
                )));
            }
            let signature = K1Signature::from_string(&entry.signature).map_err(|e| {
                ChainError::InternalError(format!("halt signature malformed: {e:?}"))
            })?;
            let recovered = signature.recover(&digest).map_err(|e| {
                ChainError::InternalError(format!("halt signature unrecoverable: {e:?}"))
            })?;
            if recovered != claimed {
                return Err(ChainError::InternalError(format!(
                    "halt signature from producer {} does not verify",
                    entry.producer
                )));
            }
            signed.insert(claimed);
        }
        let signed_weight: u128 = roster
            .iter()
            .filter(|entry| signed.contains(&entry.key))
            .map(|entry| entry.weight.0)
            .sum();
        if signed_weight * 3 < total * 2 {
            return Err(ChainError::InternalError(format!(
                "halt commitment weight {signed_weight} below two-thirds quorum of {total}"
            )));
        }
        Ok(())
    }
}

/// Integer vote weights: XPR `total_votes` is a float64 whose mainnet
/// magnitudes (1e20+) saturate `u64`, silently turning a stake quorum into a
/// member count. Weights are `u128` converted once from the source float by
/// truncation (`as u128`, finite non-negative inputs only, checked where the
/// roster is built); both the contract and the verifier must use this exact
/// conversion so their tallies agree bit-for-bit. JSON encodes the weight as
/// a decimal string: `serde_json` without `arbitrary_precision` cannot
/// round-trip `u128` magnitudes as numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HaltWeight(pub u128);

impl HaltWeight {
    /// Truncate a source float to an integer weight, failing closed on
    /// non-finite or negative inputs (NaN and infinities must never become
    /// silent zeros or saturating maxima in quorum math).
    pub fn from_votes(votes: f64) -> Result<Self, ChainError> {
        if !votes.is_finite() || votes < 0.0 {
            return Err(ChainError::InternalError(format!(
                "halt weight source is not a finite non-negative float: {votes}"
            )));
        }
        Ok(HaltWeight(votes as u128))
    }
}

impl Serialize for HaltWeight {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for HaltWeight {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StringOrNumber;
        impl<'de> serde::de::Visitor<'de> for StringOrNumber {
            type Value = HaltWeight;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a decimal weight string or a JSON number")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<HaltWeight, E> {
                value
                    .parse::<u128>()
                    .map(HaltWeight)
                    .map_err(|_| E::custom(format!("invalid halt weight: {value}")))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<HaltWeight, E> {
                Ok(HaltWeight(u128::from(value)))
            }
        }
        deserializer.deserialize_any(StringOrNumber)
    }
}

/// One roster entry for weighted quorum verification: a scheduled
/// producer's signing key and its vote weight (e.g. `total_votes` as
/// [`HaltWeight`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HaltRosterEntry {
    pub producer: String,
    pub key: K1PublicKey,
    pub weight: HaltWeight,
}

/// Domain separator for a step-one halt declaration: the old schedule's
/// signed statement, made while block H is still in the future, that H is
/// the last block its validator set will author on this source chain id.
pub const HALT_DECLARATION_DOMAIN: &[u8] = b"PULSEVM-XPR-HALT-DECLARATION-v1";
/// Domain separator for a step-two halt confirmation: the quorum's signed
/// statement, made once block H exists, binding the declaration to the
/// terminal block id, the migration checkpoint, and the successor chain id.
pub const HALT_CONFIRMATION_DOMAIN: &[u8] = b"PULSEVM-XPR-HALT-CONFIRMATION-v1";

/// One validator-set member as carried inside a halt declaration. The shape
/// mirrors the transport roster entry; parsing it yields a
/// [`HaltRosterEntry`] the same quorum check consumes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaltDeclarationMember {
    /// Producer name, as registered on the source chain.
    pub producer: String,
    /// Signing key in `PUB_K1_` or legacy `EOS` form.
    pub key: String,
    /// Vote weight (e.g. `total_votes` as [`HaltWeight`]).
    pub weight: HaltWeight,
}

/// Step one of the cutover: the old schedule declares, K blocks before the
/// cutover, that `last_height` (H) is the last block its validator set will
/// author on `source_chain_id`. The declaration names the set explicitly so
/// the statement is self-contained: verifiers never consult a schedule from
/// any other source. The successor chain id is deliberately absent — it
/// cannot be bound before the successor genesis exists, so it is bound by
/// the step-two confirmation instead, chained here via its digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaltDeclaration {
    pub version: u16,
    /// 64-hex source chain id: "this chain id" in the last-block statement.
    pub source_chain_id: String,
    /// H: the last height the declaring set will author.
    pub last_height: u32,
    /// V: the declaring validator set, sorted by producer name.
    pub validator_set: Vec<HaltDeclarationMember>,
    pub signatures: Vec<HaltSignature>,
}

/// Step two of the cutover: once block H exists, the same quorum confirms
/// the handoff — declaration digest, terminal block id, migration
/// checkpoint, and successor chain id — in one digest. Either step alone is
/// insufficient: the declaration commits to the future before the state
/// exists, the confirmation commits to the state once it does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaltConfirmation {
    pub version: u16,
    /// 64-hex digest of the step-one declaration this confirms.
    pub declaration_digest: String,
    /// H: must equal the declaration's `last_height`.
    pub halt_height: u32,
    /// 64-hex id of the terminal block H.
    pub halt_block_id: String,
    /// 64-hex SHA-256 of the migration checkpoint exported at H.
    pub checkpoint_sha256: String,
    /// 64-hex successor (A-Chain) id the state continues on.
    pub new_chain_id: String,
    pub signatures: Vec<HaltSignature>,
}

impl HaltDeclaration {
    pub const VERSION: u16 = 1;

    /// Sort members into canonical order (producer, then key) before
    /// signing. The digest covers stored order, so signers and verifiers
    /// must agree on it; sorting at construction is the convention.
    pub fn sort_members(members: &mut [HaltDeclarationMember]) {
        members.sort_by(|left, right| {
            left.producer
                .cmp(&right.producer)
                .then_with(|| left.key.cmp(&right.key))
        });
    }

    /// Parse the declared set into quorum-checkable roster entries.
    pub fn roster(&self) -> Result<Vec<HaltRosterEntry>, ChainError> {
        self.validator_set
            .iter()
            .map(|member| {
                let key = K1PublicKey::from_string(&member.key).map_err(|e| {
                    ChainError::InternalError(format!(
                        "halt declaration member {} key invalid: {e:?}",
                        member.producer
                    ))
                })?;
                Ok(HaltRosterEntry {
                    producer: member.producer.clone(),
                    key,
                    weight: member.weight,
                })
            })
            .collect::<Result<_, _>>()
    }

    /// Canonical declaration message: domain || source-chain-id ||
    /// last-height-be32 || member-count-be32 || per member
    /// (producer-len-be32 || producer-utf8 || key-compressed || weight-be128).
    pub fn message_bytes(
        source_chain_id: &[u8; 32],
        last_height: u32,
        members: &[HaltDeclarationMember],
    ) -> Result<Vec<u8>, ChainError> {
        let mut message =
            Vec::with_capacity(HALT_DECLARATION_DOMAIN.len() + 32 + 4 + 4 + members.len() * 64);
        message.extend_from_slice(HALT_DECLARATION_DOMAIN);
        message.extend_from_slice(source_chain_id);
        message.extend_from_slice(&last_height.to_be_bytes());
        message.extend_from_slice(
            &(u32::try_from(members.len())
                .map_err(|_| ChainError::InternalError("halt declaration set too large".into()))?)
            .to_be_bytes(),
        );
        for member in members {
            let key = K1PublicKey::from_string(&member.key).map_err(|e| {
                ChainError::InternalError(format!(
                    "halt declaration member {} key invalid: {e:?}",
                    member.producer
                ))
            })?;
            message.extend_from_slice(
                &(u32::try_from(member.producer.len()).map_err(|_| {
                    ChainError::InternalError("halt declaration producer name too long".into())
                })?)
                .to_be_bytes(),
            );
            message.extend_from_slice(member.producer.as_bytes());
            message.extend_from_slice(&key.compressed());
            message.extend_from_slice(&member.weight.0.to_be_bytes());
        }
        Ok(message)
    }

    /// Signing digest for this declaration.
    pub fn digest(&self) -> Result<[u8; 32], ChainError> {
        let source_chain_id = decode_hex_32(&self.source_chain_id).map_err(|e| {
            ChainError::InternalError(format!("halt declaration source chain id invalid: {e}"))
        })?;
        Ok(*Digest::hash(Self::message_bytes(
            &source_chain_id,
            self.last_height,
            &self.validator_set,
        )?)
        .as_bytes())
    }

    /// Build the declaration an on-chain cutover ceremony froze: the
    /// canonical member order over the frozen roster, one signature per
    /// vote over the declaration digest. A vote naming a producer outside
    /// the frozen set fails closed (the contract rejects it on-chain, so
    /// the exporter must never produce one). Key string forms may differ
    /// between the vote and the roster (`PUB_K1_` vs legacy `EOS`); the
    /// comparison runs on the decoded point, which is form-independent.
    pub fn from_contract_votes(
        source_chain_id: &str,
        last_height: u32,
        members: Vec<HaltDeclarationMember>,
        votes: &[HaltContractVote],
    ) -> Result<Self, ChainError> {
        let mut validator_set = members;
        Self::sort_members(&mut validator_set);
        let source_bytes = decode_hex_32(source_chain_id).map_err(|e| {
            ChainError::InternalError(format!("halt declaration source chain id invalid: {e}"))
        })?;
        let digest = *Digest::hash(Self::message_bytes(
            &source_bytes,
            last_height,
            &validator_set,
        )?)
        .as_bytes();
        let mut signatures = Vec::with_capacity(votes.len());
        for vote in votes {
            let claimed = K1PublicKey::from_string(&vote.key).map_err(|e| {
                ChainError::InternalError(format!("cutover contract vote key invalid: {e:?}"))
            })?;
            let rostered = validator_set.iter().find(|member| {
                member.producer == vote.producer
                    && K1PublicKey::from_string(&member.key).is_ok_and(|key| key == claimed)
            });
            if rostered.is_none() {
                return Err(ChainError::InternalError(format!(
                    "cutover contract vote from producer {} is not signed by its rostered key",
                    vote.producer
                )));
            }
            // The signature must run over this exact frozen digest: a vote
            // for a different height or set cannot ride along.
            let signature = K1Signature::from_string(&vote.signature).map_err(|e| {
                ChainError::InternalError(format!(
                    "cutover contract vote signature malformed: {e:?}"
                ))
            })?;
            let recovered = signature.recover(&digest).map_err(|e| {
                ChainError::InternalError(format!(
                    "cutover contract vote signature unrecoverable: {e:?}"
                ))
            })?;
            if recovered != claimed {
                return Err(ChainError::InternalError(format!(
                    "cutover contract vote from producer {} does not verify",
                    vote.producer
                )));
            }
            signatures.push(HaltSignature {
                producer: vote.producer.clone(),
                key: vote.key.clone(),
                signature: vote.signature.clone(),
            });
        }
        Ok(Self {
            version: Self::VERSION,
            source_chain_id: source_chain_id.to_string(),
            last_height,
            validator_set,
            signatures,
        })
    }

    /// Verify the declaration against the expected cutover height: version
    /// and height must match, the set must carry weight, and the signers'
    /// combined weight must reach two thirds of the declared set over the
    /// declaration digest. Returns the digest so the caller can chain the
    /// step-two confirmation to exactly this declaration.
    pub fn verify(&self, expected_height: u32) -> Result<[u8; 32], ChainError> {
        if self.version != Self::VERSION {
            return Err(ChainError::InternalError(format!(
                "unsupported halt declaration version {}",
                self.version
            )));
        }
        if self.last_height != expected_height {
            return Err(ChainError::InternalError(format!(
                "halt declaration height {} does not match cutover height {}",
                self.last_height, expected_height
            )));
        }
        let roster = self.roster()?;
        let digest = self.digest()?;
        let signed =
            recover_rostered_signatures(&self.signatures, &roster, &digest, "declaration")?;
        check_two_thirds_quorum(&roster, &signed, "declaration")?;
        Ok(digest)
    }
}

impl HaltConfirmation {
    pub const VERSION: u16 = 1;

    /// Canonical confirmation message: domain || declaration-digest ||
    /// height-be32 || block-id || checkpoint || new-chain-id.
    pub fn message_bytes(
        declaration_digest: &[u8; 32],
        halt_height: u32,
        halt_block_id: &[u8; 32],
        checkpoint_sha256: &[u8; 32],
        new_chain_id: &[u8; 32],
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(HALT_CONFIRMATION_DOMAIN.len() + 32 * 4 + 4);
        message.extend_from_slice(HALT_CONFIRMATION_DOMAIN);
        message.extend_from_slice(declaration_digest);
        message.extend_from_slice(&halt_height.to_be_bytes());
        message.extend_from_slice(halt_block_id);
        message.extend_from_slice(checkpoint_sha256);
        message.extend_from_slice(new_chain_id);
        message
    }

    /// Signing digest for this confirmation.
    pub fn digest(&self) -> Result<[u8; 32], ChainError> {
        let declaration_digest = decode_hex_32(&self.declaration_digest).map_err(|e| {
            ChainError::InternalError(format!("halt confirmation declaration link invalid: {e}"))
        })?;
        let halt_block_id = decode_hex_32(&self.halt_block_id).map_err(|e| {
            ChainError::InternalError(format!("halt confirmation block id invalid: {e}"))
        })?;
        let checkpoint_sha256 = decode_hex_32(&self.checkpoint_sha256).map_err(|e| {
            ChainError::InternalError(format!("halt confirmation checkpoint binding invalid: {e}"))
        })?;
        let new_chain_id = decode_hex_32(&self.new_chain_id).map_err(|e| {
            ChainError::InternalError(format!("halt confirmation new chain id invalid: {e}"))
        })?;
        Ok(*Digest::hash(Self::message_bytes(
            &declaration_digest,
            self.halt_height,
            &halt_block_id,
            &checkpoint_sha256,
            &new_chain_id,
        ))
        .as_bytes())
    }

    /// Verify the confirmation: version, declaration link, height, terminal
    /// block id, checkpoint, and successor chain id must all match the
    /// expected cutover values, and the same declared set's quorum must have
    /// signed the confirmation digest.
    pub fn verify(
        &self,
        declaration_digest: &[u8; 32],
        roster: &[HaltRosterEntry],
        expected_height: u32,
        expected_block_id: &[u8; 32],
        expected_checkpoint: &[u8; 32],
        expected_new_chain_id: &[u8; 32],
    ) -> Result<(), ChainError> {
        if self.version != Self::VERSION {
            return Err(ChainError::InternalError(format!(
                "unsupported halt confirmation version {}",
                self.version
            )));
        }
        let linked = decode_hex_32(&self.declaration_digest).map_err(|e| {
            ChainError::InternalError(format!("halt confirmation declaration link invalid: {e}"))
        })?;
        if linked != *declaration_digest {
            return Err(ChainError::InternalError(
                "halt confirmation does not chain the verified declaration".into(),
            ));
        }
        if self.halt_height != expected_height {
            return Err(ChainError::InternalError(format!(
                "halt confirmation height {} does not match cutover height {}",
                self.halt_height, expected_height
            )));
        }
        let committed_id = decode_hex_32(&self.halt_block_id).map_err(|e| {
            ChainError::InternalError(format!("halt confirmation block id invalid: {e}"))
        })?;
        if committed_id != *expected_block_id {
            return Err(ChainError::InternalError(
                "halt confirmation block id does not match the terminal block".into(),
            ));
        }
        let committed_checkpoint = decode_hex_32(&self.checkpoint_sha256).map_err(|e| {
            ChainError::InternalError(format!("halt confirmation checkpoint binding invalid: {e}"))
        })?;
        if committed_checkpoint != *expected_checkpoint {
            return Err(ChainError::InternalError(
                "halt confirmation checkpoint binding does not match the migration checkpoint"
                    .into(),
            ));
        }
        let committed_chain = decode_hex_32(&self.new_chain_id).map_err(|e| {
            ChainError::InternalError(format!("halt confirmation new chain id invalid: {e}"))
        })?;
        if committed_chain != *expected_new_chain_id {
            return Err(ChainError::InternalError(
                "halt confirmation successor chain id does not match this chain".into(),
            ));
        }
        let digest = self.digest()?;
        let signed =
            recover_rostered_signatures(&self.signatures, roster, &digest, "confirmation")?;
        check_two_thirds_quorum(roster, &signed, "confirmation")?;
        Ok(())
    }
}

/// One on-chain cutover vote: a `cutover::vote` action the exporter lifted
/// from a source block. The vote signature runs over the step-one
/// declaration digest, so each entry converts one-to-one into a
/// [`HaltDeclaration`] signature; the block number is the on-chain
/// timestamp the off-chain ceremony cannot prove.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaltContractVote {
    /// Producer named in the vote action. Informational for tallying (the
    /// key decides), but it must name the roster entry holding that key.
    pub producer: String,
    /// Source-chain block carrying the vote action. Must predate H: votes
    /// are the pre-commitment, and anything at or past H is not one.
    pub block: u32,
    /// Frozen roster key the vote claims, `PUB_K1_` or legacy `EOS` form.
    pub key: String,
    /// `SIG_K1_` signature over the declaration digest.
    pub signature: String,
}

/// The cutover contract's frozen ceremony as captured from the source
/// chain: the `ceremony` singleton plus every `vote` action the exporter
/// scanned. This is transport evidence for the step-one declaration: the
/// digest must equal [`HaltDeclaration::digest`], the captured weights must
/// match a recomputation from the declared set and the recovered signers,
/// and every vote must sit inside the declaration window. It replaces the
/// inclusion block with per-vote inclusion proofs. The step-two
/// confirmation still chains the declaration to the terminal block, the
/// checkpoint, and the new chain id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaltContractCeremony {
    /// Account hosting the cutover contract on the source chain.
    pub contract: String,
    /// 64-hex frozen declaration digest; must equal the declaration digest.
    pub declaration_digest: String,
    /// Roster weight captured from the singleton; must equal the declared
    /// set's total (the contract froze the live schedule, so this pins the
    /// freeze to the declaration).
    pub total_weight: HaltWeight,
    /// Tally captured from the singleton; must equal the recomputed tally
    /// of the recovered vote signers (the contract enforces this on-chain;
    /// the verifier replays it off-chain).
    pub voted_weight: HaltWeight,
    /// The singleton must report a completed tally: an open tally proves
    /// nothing about the quorum, however many votes the exporter found.
    pub finalized: bool,
    /// Block where finalization was captured. Must predate H: the quorum
    /// completes before the cutover, never after it.
    pub finalized_block: u32,
    /// Every vote action the exporter found, in scan order.
    pub votes: Vec<HaltContractVote>,
}

impl HaltContractCeremony {
    /// Verify the on-chain ceremony against the declared set and the
    /// verified declaration digest: the singleton must be finalized on the
    /// same digest, every vote must be a rostered schedule key inside the
    /// declaration window, the captured tally must match the recomputed
    /// one, and the recomputed tally must clear the strict quorum.
    pub fn verify(
        &self,
        expected_height: u32,
        max_declaration_lag: Option<u32>,
        roster: &[HaltRosterEntry],
        declaration_digest: &[u8; 32],
    ) -> Result<(), ChainError> {
        if !self.finalized {
            return Err(ChainError::InternalError(
                "cutover contract ceremony is not finalized".into(),
            ));
        }
        let frozen = decode_hex_32(&self.declaration_digest).map_err(|e| {
            ChainError::InternalError(format!("cutover contract declaration link invalid: {e}"))
        })?;
        if frozen != *declaration_digest {
            return Err(ChainError::InternalError(
                "cutover contract digest does not match the verified declaration".into(),
            ));
        }
        if self.finalized_block >= expected_height {
            return Err(ChainError::InternalError(format!(
                "cutover contract finalized at block {} which does not predate cutover height {}",
                self.finalized_block, expected_height
            )));
        }
        if let Some(max_lag) = max_declaration_lag
            && self.finalized_block.saturating_add(max_lag) < expected_height
        {
            return Err(ChainError::InternalError(format!(
                "cutover contract finalized at block {} is older than the ceremony window (H={expected_height}, max lag {max_lag})",
                self.finalized_block
            )));
        }
        let roster_total: u128 = roster.iter().map(|entry| entry.weight.0).sum();
        if self.total_weight.0 != roster_total {
            return Err(ChainError::InternalError(format!(
                "cutover contract total weight {} does not match the declared set {}",
                self.total_weight.0, roster_total
            )));
        }
        let mut seen = std::collections::HashSet::new();
        let mut signatures = Vec::with_capacity(self.votes.len());
        for vote in &self.votes {
            if vote.block >= expected_height {
                return Err(ChainError::InternalError(format!(
                    "cutover contract vote from producer {} at block {} does not predate cutover height {expected_height}",
                    vote.producer, vote.block
                )));
            }
            if let Some(max_lag) = max_declaration_lag
                && vote.block.saturating_add(max_lag) < expected_height
            {
                return Err(ChainError::InternalError(format!(
                    "cutover contract vote from producer {} at block {} is older than the ceremony window (H={expected_height}, max lag {max_lag})",
                    vote.producer, vote.block
                )));
            }
            let claimed = K1PublicKey::from_string(&vote.key).map_err(|e| {
                ChainError::InternalError(format!("cutover contract vote key invalid: {e:?}"))
            })?;
            match roster.iter().find(|entry| entry.producer == vote.producer) {
                Some(entry) if entry.key == claimed => {}
                _ => {
                    return Err(ChainError::InternalError(format!(
                        "cutover contract vote from producer {} is not signed by its rostered key",
                        vote.producer
                    )));
                }
            }
            if !seen.insert(claimed) {
                return Err(ChainError::InternalError(format!(
                    "cutover contract vote from producer {} is duplicated",
                    vote.producer
                )));
            }
            signatures.push(HaltSignature {
                producer: vote.producer.clone(),
                key: vote.key.clone(),
                signature: vote.signature.clone(),
            });
        }
        let signed = recover_rostered_signatures(
            &signatures,
            roster,
            declaration_digest,
            "contract ceremony",
        )?;
        let signed_weight: u128 = roster
            .iter()
            .filter(|entry| signed.contains(&entry.key))
            .map(|entry| entry.weight.0)
            .sum();
        if self.voted_weight.0 != signed_weight {
            return Err(ChainError::InternalError(format!(
                "cutover contract tally {} does not match the recomputed vote weight {signed_weight}",
                self.voted_weight.0
            )));
        }
        check_two_thirds_quorum(roster, &signed, "contract ceremony")?;
        Ok(())
    }
}

/// Recover every signature over `digest`, requiring each claimed key to be
/// rostered. Returns the rostered keys that signed, each counted once.
/// `context` names the ceremony step for error messages.
fn recover_rostered_signatures(
    signatures: &[HaltSignature],
    roster: &[HaltRosterEntry],
    digest: &[u8; 32],
    context: &str,
) -> Result<std::collections::HashSet<K1PublicKey>, ChainError> {
    let mut signed = std::collections::HashSet::new();
    for entry in signatures {
        let claimed = K1PublicKey::from_string(&entry.key).map_err(|e| {
            ChainError::InternalError(format!("halt {context} signature key invalid: {e:?}"))
        })?;
        if !roster.iter().any(|rostered| rostered.key == claimed) {
            return Err(ChainError::InternalError(format!(
                "halt {context} signature from producer {} is not in the declared set",
                entry.producer
            )));
        }
        let signature = K1Signature::from_string(&entry.signature).map_err(|e| {
            ChainError::InternalError(format!("halt {context} signature malformed: {e:?}"))
        })?;
        let recovered = signature.recover(digest).map_err(|e| {
            ChainError::InternalError(format!("halt {context} signature unrecoverable: {e:?}"))
        })?;
        if recovered != claimed {
            return Err(ChainError::InternalError(format!(
                "halt {context} signature from producer {} does not verify",
                entry.producer
            )));
        }
        signed.insert(claimed);
    }
    Ok(signed)
}

/// Strict two-thirds quorum over roster weight: `signed * 3 > total * 2` in
/// u128, so no float rounding and exactly-two-thirds fails closed — the +1
/// in 2/3+1. An empty or all-zero roster fails closed. `context` names the
/// ceremony step for error messages.
fn check_two_thirds_quorum(
    roster: &[HaltRosterEntry],
    signed: &std::collections::HashSet<K1PublicKey>,
    context: &str,
) -> Result<(), ChainError> {
    let total: u128 = roster.iter().map(|entry| entry.weight.0).sum();
    if roster.is_empty() || total == 0 {
        return Err(ChainError::InternalError(format!(
            "halt {context} set carries no weight"
        )));
    }
    let signed_weight: u128 = roster
        .iter()
        .filter(|entry| signed.contains(&entry.key))
        .map(|entry| entry.weight.0)
        .sum();
    if signed_weight * 3 <= total * 2 {
        return Err(ChainError::InternalError(format!(
            "halt {context} weight {signed_weight} below two-thirds quorum of {total}"
        )));
    }
    Ok(())
}
fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("must be 64 hexadecimal characters".into());
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        bytes[index] = (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulsevm_crypto::k1::K1PrivateKey;

    const HEIGHT: u32 = 310;
    const WEIGHTS: [HaltWeight; 3] = [HaltWeight(50), HaltWeight(30), HaltWeight(20)];

    fn block_id() -> [u8; 32] {
        [0xab; 32]
    }

    fn block_id_hex() -> String {
        "ab".repeat(32)
    }

    fn key(seed: &str) -> K1PrivateKey {
        K1PrivateKey::from_seed_string(seed).expect("deterministic test key")
    }

    fn roster() -> (Vec<K1PrivateKey>, Vec<HaltRosterEntry>) {
        let keys = vec![key("halt-test-1"), key("halt-test-2"), key("halt-test-3")];
        let entries = keys
            .iter()
            .zip(["prod.a", "prod.b", "prod.c"])
            .zip(WEIGHTS)
            .map(|((signing, producer), weight)| HaltRosterEntry {
                producer: producer.to_string(),
                key: signing.public_key(),
                weight,
            })
            .collect();
        (keys, entries)
    }

    fn sign(signing: &K1PrivateKey, producer: &str, height: u32, id: &[u8; 32]) -> HaltSignature {
        let digest = HaltCommitment::digest(height, id);
        HaltSignature {
            producer: producer.to_string(),
            key: signing.public_key().to_string(),
            signature: signing.sign(&digest).to_string(),
        }
    }

    fn commitment(signatures: Vec<HaltSignature>) -> HaltCommitment {
        HaltCommitment {
            version: HaltCommitment::VERSION,
            halt_height: HEIGHT,
            halt_block_id: block_id_hex(),
            checkpoint_sha256: None,
            producer_keys: Vec::new(),
            signatures,
        }
    }

    #[test]
    fn quorum_accepts_two_thirds_weight() {
        let (keys, roster) = roster();
        let id = block_id();
        for pair in [&[0, 1][..], &[0, 2][..], &[0, 1, 2][..]] {
            let signatures = pair
                .iter()
                .map(|&i| sign(&keys[i], &roster[i].producer, HEIGHT, &id))
                .collect();
            commitment(signatures)
                .verify_weighted_quorum(HEIGHT, &id, &roster)
                .expect("quorum weight must verify");
        }
    }

    #[test]
    fn quorum_accepts_exact_two_thirds() {
        let a = key("halt-test-1");
        let b = key("halt-test-2");
        let roster = vec![
            HaltRosterEntry {
                producer: "prod.a".to_string(),
                key: a.public_key(),
                weight: HaltWeight(2),
            },
            HaltRosterEntry {
                producer: "prod.b".to_string(),
                key: b.public_key(),
                weight: HaltWeight(1),
            },
        ];
        let id = block_id();
        commitment(vec![sign(&a, "prod.a", HEIGHT, &id)])
            .verify_weighted_quorum(HEIGHT, &id, &roster)
            .expect("exact two-thirds must verify");
    }

    #[test]
    fn quorum_rejects_shortfall_on_both_sides_of_the_line() {
        let (keys, roster) = roster();
        let id = block_id();
        // 30 + 20 = 50 < 67: below quorum.
        let below = vec![
            sign(&keys[1], &roster[1].producer, HEIGHT, &id),
            sign(&keys[2], &roster[2].producer, HEIGHT, &id),
        ];
        assert!(
            commitment(below)
                .verify_weighted_quorum(HEIGHT, &id, &roster)
                .is_err()
        );
        // 50 alone is below quorum even though it is the largest single weight.
        let single = vec![sign(&keys[0], &roster[0].producer, HEIGHT, &id)];
        assert!(
            commitment(single)
                .verify_weighted_quorum(HEIGHT, &id, &roster)
                .is_err()
        );
    }

    #[test]
    fn quorum_counts_each_producer_once() {
        let (keys, roster) = roster();
        let id = block_id();
        // prod.a signs twice: still only 50 of weight, below quorum.
        let double = vec![
            sign(&keys[0], &roster[0].producer, HEIGHT, &id),
            sign(&keys[0], &roster[0].producer, HEIGHT, &id),
        ];
        assert!(
            commitment(double)
                .verify_weighted_quorum(HEIGHT, &id, &roster)
                .is_err()
        );
    }

    #[test]
    fn quorum_rejects_non_roster_signer() {
        let (keys, roster) = roster();
        let id = block_id();
        let outsider = key("halt-test-outsider");
        let signatures = vec![
            sign(&keys[0], &roster[0].producer, HEIGHT, &id),
            sign(&keys[1], &roster[1].producer, HEIGHT, &id),
            sign(&outsider, "prod.zz", HEIGHT, &id),
        ];
        assert!(
            commitment(signatures)
                .verify_weighted_quorum(HEIGHT, &id, &roster)
                .is_err()
        );
    }

    #[test]
    fn quorum_rejects_signature_over_other_height() {
        let (keys, roster) = roster();
        let id = block_id();
        let signatures = vec![
            sign(&keys[0], &roster[0].producer, HEIGHT, &id),
            sign(&keys[1], &roster[1].producer, HEIGHT + 1, &id),
        ];
        assert!(
            commitment(signatures)
                .verify_weighted_quorum(HEIGHT, &id, &roster)
                .is_err()
        );
    }

    #[test]
    fn quorum_rejects_wrong_terminal_and_empty_roster() {
        let (keys, roster) = roster();
        let id = block_id();
        let signatures = vec![
            sign(&keys[0], &roster[0].producer, HEIGHT, &id),
            sign(&keys[1], &roster[1].producer, HEIGHT, &id),
        ];
        let committed = commitment(signatures);
        assert!(
            committed
                .verify_weighted_quorum(HEIGHT + 1, &id, &roster)
                .is_err()
        );
        assert!(
            committed
                .verify_weighted_quorum(HEIGHT, &[0xcd; 32], &roster)
                .is_err()
        );
        assert!(committed.verify_weighted_quorum(HEIGHT, &id, &[]).is_err());
        let zeroed: Vec<HaltRosterEntry> = roster
            .iter()
            .map(|entry| HaltRosterEntry {
                weight: HaltWeight(0),
                ..entry.clone()
            })
            .collect();
        assert!(
            committed
                .verify_weighted_quorum(HEIGHT, &id, &zeroed)
                .is_err()
        );
    }

    #[test]
    fn v1_single_signature_path_still_valid() {
        let (keys, roster) = roster();
        let id = block_id();
        let committed = HaltCommitment {
            producer_keys: roster.iter().map(|entry| entry.key.to_string()).collect(),
            ..commitment(vec![sign(&keys[0], &roster[0].producer, HEIGHT, &id)])
        };
        committed
            .verify(HEIGHT, &id)
            .expect("v1 path must keep working");
    }

    fn checkpoint() -> [u8; 32] {
        [0x77; 32]
    }

    fn hex_encode(bytes: &[u8; 32]) -> String {
        const NIBBLE: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for byte in bytes {
            out.push(NIBBLE[(byte >> 4) as usize] as char);
            out.push(NIBBLE[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn sign_v2(
        signing: &K1PrivateKey,
        producer: &str,
        height: u32,
        id: &[u8; 32],
    ) -> HaltSignature {
        let digest = HaltCommitment::digest_v2(height, id, &checkpoint());
        HaltSignature {
            producer: producer.to_string(),
            key: signing.public_key().to_string(),
            signature: signing.sign(&digest).to_string(),
        }
    }

    fn commitment_v2(signatures: Vec<HaltSignature>) -> HaltCommitment {
        HaltCommitment {
            version: HaltCommitment::VERSION_V2,
            halt_height: HEIGHT,
            halt_block_id: block_id_hex(),
            checkpoint_sha256: Some(hex_encode(&checkpoint())),
            producer_keys: Vec::new(),
            signatures,
        }
    }

    #[test]
    fn v2_digest_differs_from_v1_and_binds_checkpoint() {
        let id = block_id();
        let v1 = HaltCommitment::digest(HEIGHT, &id);
        let v2 = HaltCommitment::digest_v2(HEIGHT, &id, &checkpoint());
        assert_ne!(v1, v2, "v2 digest must be domain-separated from v1");
        let other = HaltCommitment::digest_v2(HEIGHT, &id, &[0x78; 32]);
        assert_ne!(v2, other, "v2 digest must bind the checkpoint hash");
    }

    #[test]
    fn v2_verify_accepts_bound_checkpoint() {
        let (keys, roster) = roster();
        let id = block_id();
        let committed = HaltCommitment {
            producer_keys: roster.iter().map(|entry| entry.key.to_string()).collect(),
            ..commitment_v2(vec![sign_v2(&keys[0], &roster[0].producer, HEIGHT, &id)])
        };
        committed
            .verify_v2(HEIGHT, &id, &checkpoint())
            .expect("v2 commitment must verify against its bound checkpoint");
    }

    #[test]
    fn v2_verify_rejects_wrong_checkpoint() {
        let (keys, roster) = roster();
        let id = block_id();
        let committed = HaltCommitment {
            producer_keys: roster.iter().map(|entry| entry.key.to_string()).collect(),
            ..commitment_v2(vec![sign_v2(&keys[0], &roster[0].producer, HEIGHT, &id)])
        };
        assert!(committed.verify_v2(HEIGHT, &id, &[0x78; 32]).is_err());
        assert!(committed.verify(HEIGHT, &id).is_err());
    }

    #[test]
    fn v2_weighted_quorum_accepts_and_rejects_shortfall() {
        let (keys, roster) = roster();
        let id = block_id();
        let quorum: Vec<HaltSignature> = [0, 1]
            .iter()
            .map(|&i| sign_v2(&keys[i], &roster[i].producer, HEIGHT, &id))
            .collect();
        commitment_v2(quorum)
            .verify_weighted_quorum_v2(HEIGHT, &id, &checkpoint(), &roster)
            .expect("v2 quorum weight must verify");
        let shortfall = vec![sign_v2(&keys[2], &roster[2].producer, HEIGHT, &id)];
        assert!(
            commitment_v2(shortfall)
                .verify_weighted_quorum_v2(HEIGHT, &id, &checkpoint(), &roster)
                .is_err()
        );
    }

    const NEW_CHAIN: [u8; 32] = [0x22; 32];

    fn hex32(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn source_chain_hex() -> String {
        "11".repeat(32)
    }

    fn new_chain_hex() -> String {
        "22".repeat(32)
    }

    fn declaration_members(keys: &[K1PrivateKey]) -> Vec<HaltDeclarationMember> {
        let names = ["prod.a", "prod.b", "prod.c"];
        keys.iter()
            .zip(names)
            .zip(WEIGHTS)
            .map(|((signing, producer), weight)| HaltDeclarationMember {
                producer: producer.to_string(),
                key: signing.public_key().to_string(),
                weight,
            })
            .collect()
    }

    fn sign_declaration(
        signing: &K1PrivateKey,
        producer: &str,
        digest: &[u8; 32],
    ) -> HaltSignature {
        HaltSignature {
            producer: producer.to_string(),
            key: signing.public_key().to_string(),
            signature: signing.sign(digest).to_string(),
        }
    }

    fn declared(signatures: Vec<HaltSignature>) -> HaltDeclaration {
        let keys = vec![key("halt-test-1"), key("halt-test-2"), key("halt-test-3")];
        let mut members = declaration_members(&keys);
        HaltDeclaration::sort_members(&mut members);
        HaltDeclaration {
            version: HaltDeclaration::VERSION,
            source_chain_id: source_chain_hex(),
            last_height: HEIGHT,
            validator_set: members,
            signatures,
        }
    }

    fn declared_digest(declaration: &HaltDeclaration) -> [u8; 32] {
        declaration.digest().expect("declaration digest must parse")
    }

    fn confirmed(
        signatures: Vec<HaltSignature>,
        declaration_digest: &[u8; 32],
    ) -> HaltConfirmation {
        HaltConfirmation {
            version: HaltConfirmation::VERSION,
            declaration_digest: hex32(declaration_digest),
            halt_height: HEIGHT,
            halt_block_id: block_id_hex(),
            checkpoint_sha256: hex32(&checkpoint()),
            new_chain_id: new_chain_hex(),
            signatures,
        }
    }

    fn sign_confirmation(
        signing: &K1PrivateKey,
        producer: &str,
        confirmation: &HaltConfirmation,
    ) -> HaltSignature {
        let digest = confirmation
            .digest()
            .expect("confirmation digest must parse");
        HaltSignature {
            producer: producer.to_string(),
            key: signing.public_key().to_string(),
            signature: signing.sign(&digest).to_string(),
        }
    }

    #[test]
    fn declaration_quorum_accepts_and_rejects_shortfall() {
        let (keys, _) = roster();
        let unsigned = declared(Vec::new());
        let digest = declared_digest(&unsigned);
        let quorum = [0, 1]
            .iter()
            .map(|&i| {
                let names = ["prod.a", "prod.b", "prod.c"];
                sign_declaration(&keys[i], names[i], &digest)
            })
            .collect();
        let digest = declared(quorum)
            .verify(HEIGHT)
            .expect("declaration quorum weight must verify");
        let shortfall = vec![sign_declaration(&keys[2], "prod.c", &digest)];
        assert!(declared(shortfall).verify(HEIGHT).is_err());
    }

    #[test]
    fn declaration_digest_is_canonical_over_member_order() {
        let keys = vec![key("halt-test-1"), key("halt-test-2"), key("halt-test-3")];
        let mut members = declaration_members(&keys);
        members.reverse();
        HaltDeclaration::sort_members(&mut members);
        let sorted = declared(Vec::new());
        assert_eq!(members, sorted.validator_set);
        // Stored order is what the digest covers: shuffling changes it.
        let mut shuffled = sorted.clone();
        shuffled.validator_set.reverse();
        assert_ne!(sorted.digest().unwrap(), shuffled.digest().unwrap());
    }

    #[test]
    fn declaration_rejects_wrong_height_and_chain() {
        let (keys, _) = roster();
        let unsigned = declared(Vec::new());
        let digest = declared_digest(&unsigned);
        let quorum = [0, 1]
            .iter()
            .map(|&i| {
                let names = ["prod.a", "prod.b", "prod.c"];
                sign_declaration(&keys[i], names[i], &digest)
            })
            .collect::<Vec<_>>();
        let declaration = declared(quorum.clone());
        assert!(declaration.verify(HEIGHT + 1).is_err());
        let mut wrong_version = declaration.clone();
        wrong_version.version = 99;
        assert!(wrong_version.verify(HEIGHT).is_err());
        // A declaration for another source chain is another digest: the
        // quorum's signatures do not carry over.
        let mut wrong_chain = declaration.clone();
        wrong_chain.source_chain_id = "33".repeat(32);
        assert!(wrong_chain.verify(HEIGHT).is_err());
        // An empty or weightless set fails closed even with no signatures.
        let mut empty = declaration.clone();
        empty.validator_set.clear();
        assert!(empty.verify(HEIGHT).is_err());
        let mut weightless = declaration.clone();
        for member in &mut weightless.validator_set {
            member.weight = HaltWeight(0);
        }
        assert!(weightless.verify(HEIGHT).is_err());
    }

    #[test]
    fn weight_keeps_mainnet_magnitudes_and_string_encoding() {
        // Live XPR `total_votes` reach 1e20+: `as u64` would saturate every
        // large producer at u64::MAX, turning a stake quorum into a member
        // count. u128 truncation preserves the magnitudes.
        let votes = 5.251494364735212e21_f64;
        let weight = HaltWeight::from_votes(votes).expect("finite votes convert");
        assert_eq!(weight.0, votes as u128);
        assert!(weight.0 > u64::MAX as u128);
        // JSON encodes as a decimal string (no arbitrary_precision); plain
        // numbers still parse for back-compat with small fixture weights.
        let encoded = serde_json::to_string(&weight).expect("weight serializes");
        assert_eq!(encoded, format!("\"{}\"", weight.0));
        let decoded: HaltWeight = serde_json::from_str(&encoded).expect("string parses");
        assert_eq!(decoded, weight);
        let legacy: HaltWeight = serde_json::from_str("20").expect("number parses");
        assert_eq!(legacy, HaltWeight(20));
        // Non-finite and negative sources fail closed, never silent 0/MAX.
        assert!(HaltWeight::from_votes(f64::NAN).is_err());
        assert!(HaltWeight::from_votes(f64::INFINITY).is_err());
        assert!(HaltWeight::from_votes(-1.0).is_err());
        // A declaration member round-trips through JSON with string weights.
        let member = HaltDeclarationMember {
            producer: "prod.a".to_string(),
            key: key("halt-test-1").public_key().to_string(),
            weight,
        };
        let json = serde_json::to_string(&member).expect("member serializes");
        assert!(json.contains(&format!("\"weight\":\"{}\"", weight.0)));
        let back: HaltDeclarationMember = serde_json::from_str(&json).expect("member parses");
        assert_eq!(back, member);
    }

    #[test]
    fn declaration_rejects_signature_outside_the_set() {
        let (keys, _) = roster();
        let unsigned = declared(Vec::new());
        let digest = declared_digest(&unsigned);
        let outsider = key("halt-outsider");
        let forged = vec![sign_declaration(&outsider, "prod.zzz", &digest)];
        assert!(declared(forged).verify(HEIGHT).is_err());
        // A signature over another digest does not verify either.
        let wrong_digest =
            HaltDeclaration::message_bytes(&[0x99; 32], HEIGHT, &unsigned.validator_set)
                .map(|message| *pulsevm_crypto::Digest::hash(&message).as_bytes())
                .expect("message must build");
        let mismatched = vec![sign_declaration(&keys[0], "prod.a", &wrong_digest)];
        assert!(declared(mismatched).verify(HEIGHT).is_err());
    }

    #[test]
    fn confirmation_chains_declaration_and_state() {
        let (keys, roster) = roster();
        let names = ["prod.a", "prod.b", "prod.c"];
        let unsigned = declared(Vec::new());
        let decl_digest = declared_digest(&unsigned);
        let decl_sigs = [0, 1]
            .iter()
            .map(|&i| sign_declaration(&keys[i], names[i], &decl_digest))
            .collect();
        let declaration = declared(decl_sigs);
        let verified = declaration.verify(HEIGHT).expect("declaration must verify");
        let parsed = declaration.roster().expect("declaration set must parse");
        assert_eq!(parsed, roster);

        let template = confirmed(Vec::new(), &verified);
        let conf_sigs = [0, 1]
            .iter()
            .map(|&i| sign_confirmation(&keys[i], names[i], &template))
            .collect();
        let confirmation = confirmed(conf_sigs, &verified);
        confirmation
            .verify(
                &verified,
                &roster,
                HEIGHT,
                &block_id(),
                &checkpoint(),
                &NEW_CHAIN,
            )
            .expect("confirmation must chain the declaration and the state");
    }

    #[test]
    fn confirmation_rejects_any_broken_link() {
        let (keys, roster) = roster();
        let names = ["prod.a", "prod.b", "prod.c"];
        let unsigned = declared(Vec::new());
        let decl_digest = declared_digest(&unsigned);
        let template = confirmed(Vec::new(), &decl_digest);
        let quorum = [0, 1]
            .iter()
            .map(|&i| sign_confirmation(&keys[i], names[i], &template))
            .collect::<Vec<_>>();
        let good = confirmed(quorum, &decl_digest);
        let id = block_id();
        let checkpoint_bytes = checkpoint();
        let expect_ok = |confirmation: &HaltConfirmation| {
            confirmation.verify(
                &decl_digest,
                &roster,
                HEIGHT,
                &id,
                &checkpoint_bytes,
                &NEW_CHAIN,
            )
        };
        expect_ok(&good).expect("baseline confirmation must verify");

        let mut wrong_link = good.clone();
        wrong_link.declaration_digest = "44".repeat(32);
        assert!(expect_ok(&wrong_link).is_err());

        let mut wrong_height = good.clone();
        wrong_height.halt_height = HEIGHT + 1;
        assert!(
            wrong_height
                .verify(
                    &decl_digest,
                    &roster,
                    HEIGHT,
                    &id,
                    &checkpoint_bytes,
                    &NEW_CHAIN
                )
                .is_err()
        );

        let mut wrong_block = good.clone();
        wrong_block.halt_block_id = "55".repeat(32);
        assert!(expect_ok(&wrong_block).is_err());

        let mut wrong_checkpoint = good.clone();
        wrong_checkpoint.checkpoint_sha256 = "66".repeat(32);
        assert!(expect_ok(&wrong_checkpoint).is_err());

        let mut wrong_chain = good.clone();
        wrong_chain.new_chain_id = "77".repeat(32);
        assert!(expect_ok(&wrong_chain).is_err());

        // Quorum shortfall on the confirmation digest fails even though the
        // declaration itself still verifies.
        let shortfall_template = confirmed(Vec::new(), &decl_digest);
        let shortfall = confirmed(
            vec![sign_confirmation(&keys[2], names[2], &shortfall_template)],
            &decl_digest,
        );
        assert!(expect_ok(&shortfall).is_err());

        let mut wrong_version = good.clone();
        wrong_version.version = 99;
        assert!(expect_ok(&wrong_version).is_err());
    }

    fn ceremony_votes(
        keys: &[K1PrivateKey],
        digest: &[u8; 32],
        blocks: &[u32],
    ) -> Vec<HaltContractVote> {
        let names = ["prod.a", "prod.b", "prod.c"];
        keys.iter()
            .zip(names)
            .zip(blocks)
            .map(|((signing, producer), block)| HaltContractVote {
                producer: producer.to_string(),
                block: *block,
                key: signing.public_key().to_string(),
                signature: signing.sign(digest).to_string(),
            })
            .collect()
    }

    fn ceremony_template(digest: &[u8; 32], votes: Vec<HaltContractVote>) -> HaltContractCeremony {
        HaltContractCeremony {
            contract: "cutover".to_string(),
            declaration_digest: hex32(digest),
            total_weight: HaltWeight(WEIGHTS.iter().map(|weight| weight.0).sum()),
            voted_weight: HaltWeight(WEIGHTS[0].0 + WEIGHTS[1].0),
            finalized: true,
            finalized_block: HEIGHT - 1,
            votes,
        }
    }

    fn ceremony_inputs() -> (Vec<K1PrivateKey>, Vec<HaltRosterEntry>, [u8; 32]) {
        let (keys, roster) = roster();
        let unsigned = declared(Vec::new());
        let digest = declared_digest(&unsigned);
        (keys, roster, digest)
    }

    fn declaration_from_votes(
        keys: &[K1PrivateKey],
        digest: &[u8; 32],
        blocks: &[u32],
    ) -> HaltDeclaration {
        let names = ["prod.a", "prod.b", "prod.c"];
        let members: Vec<HaltDeclarationMember> = keys
            .iter()
            .zip(names)
            .zip(WEIGHTS)
            .map(|((signing, producer), weight)| HaltDeclarationMember {
                producer: producer.to_string(),
                key: signing.public_key().to_string(),
                weight,
            })
            .collect();
        let votes = ceremony_votes(keys, digest, blocks);
        HaltDeclaration::from_contract_votes(&source_chain_hex(), HEIGHT, members, &votes)
            .expect("contract votes must build a declaration")
    }

    #[test]
    fn from_contract_votes_builds_verifiable_declaration() {
        let (keys, _, _) = ceremony_inputs();
        // The digest must run over the same two members the declaration is
        // built from (prod.a/prod.b with WEIGHTS[0]/WEIGHTS[1]).
        let names = ["prod.a", "prod.b"];
        let members: Vec<HaltDeclarationMember> = keys[..2]
            .iter()
            .zip(names)
            .zip([WEIGHTS[0], WEIGHTS[1]])
            .map(|((signing, producer), weight)| HaltDeclarationMember {
                producer: producer.to_string(),
                key: signing.public_key().to_string(),
                weight,
            })
            .collect();
        let mut unsigned = HaltDeclaration {
            version: HaltDeclaration::VERSION,
            source_chain_id: source_chain_hex(),
            last_height: HEIGHT,
            validator_set: members,
            signatures: Vec::new(),
        };
        HaltDeclaration::sort_members(&mut unsigned.validator_set);
        let digest = unsigned.digest().expect("unsigned digest parses");
        let built = declaration_from_votes(&keys[..2], &digest, &[HEIGHT - 3, HEIGHT - 2]);
        assert_eq!(built.digest().expect("built digest parses"), digest);
        assert_eq!(built.validator_set, unsigned.validator_set);
        built.verify(HEIGHT).expect("built declaration must verify");
    }

    #[test]
    fn from_contract_votes_accepts_legacy_key_form() {
        // The disposable fixture dev pair (also hardcoded in the rehearsal
        // scripts): legacy EOS form and modern PUB_K1_ form, same point.
        let dev = K1PrivateKey::from_string("5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3")
            .expect("fixture dev key parses");
        let modern = dev.public_key().to_string();
        assert!(modern.starts_with("PUB_K1_"));
        let legacy = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV";
        assert_eq!(
            K1PublicKey::from_string(legacy).expect("legacy form parses"),
            dev.public_key()
        );
        let members = vec![HaltDeclarationMember {
            producer: "prod.a".to_string(),
            key: modern,
            weight: HaltWeight(1),
        }];
        let mut unsigned = HaltDeclaration {
            version: HaltDeclaration::VERSION,
            source_chain_id: source_chain_hex(),
            last_height: HEIGHT,
            validator_set: members.clone(),
            signatures: Vec::new(),
        };
        HaltDeclaration::sort_members(&mut unsigned.validator_set);
        let digest = unsigned.digest().expect("unsigned digest parses");
        let votes = vec![HaltContractVote {
            producer: "prod.a".to_string(),
            block: HEIGHT - 2,
            key: legacy.to_string(),
            signature: dev.sign(&digest).to_string(),
        }];
        let built =
            HaltDeclaration::from_contract_votes(&source_chain_hex(), HEIGHT, members, &votes)
                .expect("legacy-form vote must build");
        built
            .verify(HEIGHT)
            .expect("legacy-form declaration must verify");
    }

    #[test]
    fn from_contract_votes_rejects_outsider_and_wrong_digest() {
        let (keys, _, _) = ceremony_inputs();
        let unsigned = declared(Vec::new());
        let digest = declared_digest(&unsigned);
        // Outsider vote: well-formed signature, but not a roster member.
        let outsider = key("halt-test-outsider");
        let members: Vec<HaltDeclarationMember> = keys[..1]
            .iter()
            .zip(["prod.a"])
            .zip([WEIGHTS[0]])
            .map(|((signing, producer), weight)| HaltDeclarationMember {
                producer: producer.to_string(),
                key: signing.public_key().to_string(),
                weight,
            })
            .collect();
        let bad_votes = vec![HaltContractVote {
            producer: "mallory".to_string(),
            block: HEIGHT - 2,
            key: outsider.public_key().to_string(),
            signature: outsider.sign(&digest).to_string(),
        }];
        assert!(
            HaltDeclaration::from_contract_votes(
                &source_chain_hex(),
                HEIGHT,
                members.clone(),
                &bad_votes
            )
            .is_err()
        );
        // Vote for a different height: the signature runs over another
        // digest, so it cannot ride along on this declaration.
        let mut other = unsigned.clone();
        other.last_height = HEIGHT + 1;
        let other_digest = other.digest().expect("other digest parses");
        let wrong_votes = vec![HaltContractVote {
            producer: "prod.a".to_string(),
            block: HEIGHT - 2,
            key: keys[0].public_key().to_string(),
            signature: keys[0].sign(&other_digest).to_string(),
        }];
        assert!(
            HaltDeclaration::from_contract_votes(
                &source_chain_hex(),
                HEIGHT,
                members,
                &wrong_votes
            )
            .is_err()
        );
    }

    #[test]
    fn contract_ceremony_accepts_quorum_votes_in_window() {
        let (keys, roster, digest) = ceremony_inputs();
        let votes = ceremony_votes(&keys[..2], &digest, &[HEIGHT - 30, HEIGHT - 2]);
        ceremony_template(&digest, votes)
            .verify(HEIGHT, Some(30), &roster, &digest)
            .expect("quorum votes in window must verify");
    }

    #[test]
    fn contract_ceremony_rejects_open_tally_and_digest_link() {
        let (keys, roster, digest) = ceremony_inputs();
        let votes = ceremony_votes(&keys[..2], &digest, &[HEIGHT - 3, HEIGHT - 2]);
        let mut open = ceremony_template(&digest, votes.clone());
        open.finalized = false;
        assert!(
            open.verify(HEIGHT, None, &roster, &digest).is_err(),
            "an open tally proves no quorum"
        );
        let mut wrong_link = ceremony_template(&digest, votes);
        wrong_link.declaration_digest = "44".repeat(32);
        assert!(
            wrong_link.verify(HEIGHT, None, &roster, &digest).is_err(),
            "a digest link to another declaration must fail"
        );
    }

    #[test]
    fn contract_ceremony_rejects_outsider_wrong_key_and_double_vote() {
        let (keys, roster, digest) = ceremony_inputs();
        let mut votes = ceremony_votes(&keys[..2], &digest, &[HEIGHT - 3, HEIGHT - 2]);
        // A vote naming a rostered producer but signed by another key: the
        // name/key binding must hold, not just roster membership.
        votes[1].key = keys[2].public_key().to_string();
        assert!(
            ceremony_template(&digest, votes)
                .verify(HEIGHT, None, &roster, &digest)
                .is_err(),
            "a vote under another member's key must fail"
        );
        // An outsider key is not in the declared set at all.
        let outsider = key("halt-test-outsider");
        let mut votes = ceremony_votes(&keys[..1], &digest, &[HEIGHT - 3]);
        votes.push(HaltContractVote {
            producer: "mallory".to_string(),
            block: HEIGHT - 2,
            key: outsider.public_key().to_string(),
            signature: outsider.sign(&digest).to_string(),
        });
        assert!(
            ceremony_template(&digest, votes)
                .verify(HEIGHT, None, &roster, &digest)
                .is_err(),
            "an outsider vote must fail"
        );
        // The same key twice under the same name must fail even though the
        // tally would pass: the evidence itself is malformed.
        let vote = &ceremony_votes(&keys[..1], &digest, &[HEIGHT - 3])[0];
        let mut doubled_vote = vote.clone();
        doubled_vote.block = HEIGHT - 2;
        let mut doubled = ceremony_template(&digest, vec![vote.clone(), doubled_vote]);
        doubled.voted_weight = HaltWeight(WEIGHTS[0].0 * 2);
        assert!(
            doubled.verify(HEIGHT, None, &roster, &digest).is_err(),
            "a duplicated vote must fail"
        );
    }

    #[test]
    fn contract_ceremony_rejects_shortfall_and_tally_mismatch() {
        let (keys, roster, digest) = ceremony_inputs();
        // prod.c alone (20 of 100) cannot finalize: exact-boundary shortfall.
        let votes = ceremony_votes(&keys[2..3], &digest, &[HEIGHT - 2]);
        let mut short = ceremony_template(&digest, votes);
        short.voted_weight = HaltWeight(WEIGHTS[2].0);
        assert!(
            short.verify(HEIGHT, None, &roster, &digest).is_err(),
            "a shortfall tally must fail"
        );
        // Captured tally disagreeing with the recomputed signer weight fails
        // even though the signatures themselves clear the quorum.
        let votes = ceremony_votes(&keys[..2], &digest, &[HEIGHT - 3, HEIGHT - 2]);
        let mut inflated = ceremony_template(&digest, votes);
        inflated.voted_weight = HaltWeight(WEIGHTS[0].0 + WEIGHTS[1].0 + 1);
        assert!(
            inflated.verify(HEIGHT, None, &roster, &digest).is_err(),
            "an inflated contract tally must fail"
        );
        let votes = ceremony_votes(&keys[..2], &digest, &[HEIGHT - 3, HEIGHT - 2]);
        let mut wrong_total = ceremony_template(&digest, votes);
        wrong_total.total_weight =
            HaltWeight(WEIGHTS.iter().map(|weight| weight.0).sum::<u128>() + 1);
        assert!(
            wrong_total.verify(HEIGHT, None, &roster, &digest).is_err(),
            "a total weight divorced from the declared set must fail"
        );
    }

    #[test]
    fn contract_ceremony_enforces_vote_and_finality_windows() {
        let (keys, roster, digest) = ceremony_inputs();
        // A vote at or past H is not a pre-commitment.
        let votes = ceremony_votes(&keys[..2], &digest, &[HEIGHT - 3, HEIGHT]);
        assert!(
            ceremony_template(&digest, votes)
                .verify(HEIGHT, None, &roster, &digest)
                .is_err(),
            "a vote at H must fail"
        );
        // Finalization at or past H likewise misses the pre-commitment.
        let votes = ceremony_votes(&keys[..2], &digest, &[HEIGHT - 3, HEIGHT - 2]);
        let mut late = ceremony_template(&digest, votes);
        late.finalized_block = HEIGHT;
        assert!(
            late.verify(HEIGHT, None, &roster, &digest).is_err(),
            "finalization at H must fail"
        );
        // With a claimed freshness bound, stale votes and stale finality
        // fail even though both predate H.
        let votes = ceremony_votes(&keys[..2], &digest, &[HEIGHT - 31, HEIGHT - 2]);
        assert!(
            ceremony_template(&digest, votes)
                .verify(HEIGHT, Some(30), &roster, &digest)
                .is_err(),
            "a vote older than the ceremony window must fail"
        );
        let votes = ceremony_votes(&keys[..2], &digest, &[HEIGHT - 3, HEIGHT - 2]);
        let mut stale = ceremony_template(&digest, votes);
        stale.finalized_block = HEIGHT - 31;
        assert!(
            stale.verify(HEIGHT, Some(30), &roster, &digest).is_err(),
            "stale finalization must fail"
        );
    }
}
