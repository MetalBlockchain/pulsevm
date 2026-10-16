//! XPR halt commitment: the old network's signed promise to stop at H.
//!
//! Customer continuity rests on the swap, not on either chain alone: the XPR
//! producers commit to never authoring past H, the new network verifies that
//! commitment against the old schedule's keys before authoring H+1, and the
//! replay terminates. This module defines the commitment wire format and its
//! verification. The quorum policy lives with the ceremony: version 1
//! requires at least one valid producer signature over the halt; a mainnet
//! ceremony upgrades the threshold to 2/3 of schedule weight without
//! changing the format.

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
    /// Old-schedule producer keys a commitment signature may come from.
    pub producer_keys: Vec<String>,
    pub signatures: Vec<HaltSignature>,
}

impl HaltCommitment {
    pub const VERSION: u16 = 1;

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
        *Digest::hash(&Self::message_bytes(halt_height, halt_block_id)).as_bytes()
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
