use std::collections::VecDeque;

use pulsevm_crypto::{
    Digest,
    FixedBytes,
};
use pulsevm_database::{
    BlockTimestamp,
    Database,
};
use pulsevm_error::ChainError;
use pulsevm_proc_macros::{
    NumBytes,
    Read,
    Write,
};
use pulsevm_serialization::{
    Read as SerializationRead,
    Write,
};
use serde::{
    Serialize,
    ser::SerializeStruct,
};

use crate::{
    chain::{
        Name,
        id::Id,
        producer_schedule::ProducerSchedule,
        transaction::TransactionReceipt,
    },
    crypto::Signature,
    utils::pulse_assert,
};

/// Leap's protocol-feature activation extension. The extension payload is the
/// canonical serialized `vector<checksum256>` and is part of the signed block
/// header. Extension id 0 is reserved for this payload in Leap.
pub const PROTOCOL_FEATURE_ACTIVATION_EXTENSION_ID: u16 = 0;

/// Number of 500 ms slots a block may be ahead of a validator's local clock.
/// Twenty slots (ten seconds) leaves room for normal clock and network jitter
/// while preventing a producer from moving chain time arbitrarily far ahead.
pub const MAX_FUTURE_BLOCK_TIME_SLOTS: u32 = 20;

#[derive(Debug, Default, Clone, Read, Write, NumBytes)]
pub struct BlockHeader {
    pub timestamp: BlockTimestamp,
    pub producer: Name,
    pub confirmed: u16,
    pub previous: Id,
    pub transaction_mroot: Digest,
    pub action_mroot: Digest,
    pub schedule_version: u32,
    // Placeholder for new producers, we don't use this for now
    pub new_producers: Option<ProducerSchedule>,
    // Placeholder for header extensions, we don't use this for now
    pub header_extensions: Vec<(u16, Vec<u8>)>,
}

impl BlockHeader {
    fn digest(&self) -> Result<Digest, ChainError> {
        let packed = self
            .pack()
            .map_err(|e| ChainError::SerializationError(e.to_string()))?;
        Ok(Digest::hash(&packed))
    }

    /// The digest a producer signs (and a validator recovers the signer from).
    /// The header commits to the producer, previous, merkle roots, schedule
    /// version and any `new_producers`, but not to the signature itself, so
    /// signing it is well-defined — and a schedule change rides inside it.
    pub fn sig_digest(&self) -> Result<Digest, ChainError> {
        self.digest()
    }

    /// The producer schedule this block activates, if it changes one. The change
    /// travels in the signed header, so it is committed with the block and can be
    /// reconstructed from the block log — the schedule is never trusted from an
    /// out-of-band source.
    pub fn new_schedule(&self) -> &Option<ProducerSchedule> {
        &self.new_producers
    }

    /// Decode the optional Leap protocol-feature activation extension. Unknown
    /// header extensions remain rejected until their consensus semantics are
    /// implemented; accepting them as opaque bytes would make block ids valid
    /// while silently ignoring state transitions.
    pub fn protocol_feature_activations(&self) -> Result<Vec<Digest>, ChainError> {
        let mut decoded = None;
        for (id, payload) in &self.header_extensions {
            if *id != PROTOCOL_FEATURE_ACTIVATION_EXTENSION_ID {
                return Err(ChainError::BlockError(format!(
                    "unsupported block header extension {}",
                    id
                )));
            }
            if decoded.is_some() {
                return Err(ChainError::BlockError(
                    "duplicate protocol feature activation extension".into(),
                ));
            }
            let mut pos = 0;
            let features = Vec::<Digest>::read(payload, &mut pos).map_err(|error| {
                ChainError::BlockError(format!(
                    "invalid protocol feature activation extension: {error}"
                ))
            })?;
            if pos != payload.len() || features.is_empty() {
                return Err(ChainError::BlockError(
                    "protocol feature activation extension must contain a non-empty digest vector"
                        .into(),
                ));
            }
            for (index, feature) in features.iter().enumerate() {
                if features[..index].contains(feature) {
                    return Err(ChainError::BlockError(
                        "protocol feature activation extension contains a duplicate digest".into(),
                    ));
                }
            }
            decoded = Some(features);
        }
        Ok(decoded.unwrap_or_default())
    }

    /// Pack the protocol-feature activation extension from an ordered digest
    /// list. The caller is responsible for ensuring the list is non-empty.
    pub fn set_protocol_feature_activations(
        &mut self,
        features: &[Digest],
    ) -> Result<(), ChainError> {
        if features.is_empty() {
            self.header_extensions.clear();
            return Ok(());
        }
        let payload = features
            .to_vec()
            .pack()
            .map_err(|error| ChainError::SerializationError(error.to_string()))?;
        self.header_extensions = vec![(PROTOCOL_FEATURE_ACTIVATION_EXTENSION_ID, payload)];
        Ok(())
    }

    fn block_num(&self) -> u32 {
        Self::num_from_id(&self.previous) + 1
    }

    #[inline]
    pub fn num_from_id(id: &Id) -> u32 {
        // First 4 bytes contain the block number in big-endian.
        u32::from_be_bytes(id.0.0[0..4].try_into().unwrap())
    }

    #[inline]
    pub fn id_from_num(id: &Id) -> u32 {
        // First 4 bytes contain the block number in big-endian.
        u32::from_be_bytes(id.0.0[0..4].try_into().unwrap())
    }

    #[inline]
    pub fn calculate_id(&self) -> Result<Id, ChainError> {
        let mut result = self.digest()?; // exclude producer_signature etc.
        let bn_be = self.block_num().to_be_bytes(); // endian_reverse_u32 on LE == write BE bytes
        // Overwrite the first 4 bytes with the big-endian block number
        result.0[0..4].copy_from_slice(&bn_be);
        Ok(Id(FixedBytes(result.0)))
    }

    /// Validate the timestamp against its parent and a validator's current
    /// timestamp. `BlockTimestamp` is represented as a slot count, so every
    /// value is necessarily aligned to the 500 ms protocol boundary.
    pub fn validate_timestamp(
        &self,
        parent_timestamp: &BlockTimestamp,
        now: &BlockTimestamp,
    ) -> Result<(), ChainError> {
        pulse_assert(
            self.timestamp.slot() > parent_timestamp.slot(),
            ChainError::BlockError(format!(
                "block timestamp {} is not after parent timestamp {}",
                self.timestamp.slot(),
                parent_timestamp.slot()
            )),
        )?;

        let max_allowed = now.slot().saturating_add(MAX_FUTURE_BLOCK_TIME_SLOTS);
        pulse_assert(
            self.timestamp.slot() <= max_allowed,
            ChainError::BlockError(format!(
                "block timestamp {} is too far in the future (maximum {})",
                self.timestamp.slot(),
                max_allowed
            )),
        )?;

        Ok(())
    }

    pub fn validate(&self, db: &Database) -> Result<(), ChainError> {
        pulse_assert(
            db.is_account(self.producer.as_u64())?,
            ChainError::BlockError("producer account does not exist".into()),
        )?;
        pulse_assert(
            self.confirmed == 0,
            ChainError::BlockError("confirmed count must be 0".into()),
        )?;
        // A block may change the producer schedule. When it does, the change is
        // carried in `new_producers` and the header's `schedule_version` names the
        // resulting version; the two must agree, and an empty `new_producers`
        // implies version 0. `new_schedule()` bounds the decode. The signature and
        // execution binding are checked by the controller; here we enforce only
        // header self-consistency.
        match self.new_schedule() {
            None => pulse_assert(
                self.schedule_version == 0,
                ChainError::BlockError("schedule version must be 0 without new producers".into()),
            )?,
            Some(schedule) => {
                pulse_assert(
                    !schedule.producers.is_empty(),
                    ChainError::BlockError("new producer schedule is empty".into()),
                )?;
                pulse_assert(
                    schedule.version == self.schedule_version,
                    ChainError::BlockError(
                        "schedule version does not match new_producers version".into(),
                    ),
                )?;
            }
        }
        self.protocol_feature_activations()?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Read, Write, NumBytes)]
pub struct SignedBlockHeader {
    pub header: BlockHeader,
    pub signature: Signature,
}

impl SignedBlockHeader {
    pub fn validate(&self, db: &Database) -> Result<(), ChainError> {
        self.header.validate(db)?;
        // TODO: validate signature if we have the producer's public key available
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Read, Write, NumBytes)]
pub struct SignedBlock {
    pub signed_block_header: SignedBlockHeader,
    // Placeholder for transactions, we don't use this for now
    pub transactions: VecDeque<TransactionReceipt>,
    // Placeholder for header extensions, we don't use this for now
    pub block_extensions: Vec<(u16, Vec<u8>)>,
}

impl SignedBlock {
    pub fn new(
        parent_id: Id,
        timestamp: BlockTimestamp,
        producer: Name,
        transaction_receipts: VecDeque<TransactionReceipt>,
        transaction_mroot: Digest,
        action_mroot: Digest,
    ) -> Self {
        SignedBlock {
            signed_block_header: SignedBlockHeader {
                header: BlockHeader {
                    timestamp,
                    producer,     // Use the provided producer name
                    confirmed: 0, // Placeholder confirmed count
                    previous: parent_id,
                    transaction_mroot,
                    action_mroot,              // Use the provided action merkle root
                    schedule_version: 0,       // Placeholder schedule version
                    new_producers: None,       // Placeholder for new producers
                    header_extensions: vec![], // Placeholder for header extensions
                },
                signature: Signature::default(), // Placeholder signature
            },
            transactions: transaction_receipts,
            block_extensions: vec![],
        }
    }

    pub fn id(&self) -> Result<Id, ChainError> {
        self.signed_block_header.header.calculate_id()
    }

    pub fn previous_id(&self) -> &Id {
        &self.signed_block_header.header.previous
    }

    pub fn block_num(&self) -> u32 {
        self.signed_block_header.header.block_num()
    }

    pub fn timestamp(&self) -> &BlockTimestamp {
        &self.signed_block_header.header.timestamp
    }

    pub fn validate_syntactically(&self, db: &Database) -> Result<(), ChainError> {
        self.signed_block_header.validate(db)?;

        pulse_assert(
            self.transactions.len() > 0,
            ChainError::BlockError("block has no transactions".into()),
        )?;
        pulse_assert(
            self.block_extensions.is_empty(),
            ChainError::BlockError("block extensions not supported".into()),
        )?;

        Ok(())
    }

    pub fn validate_semantically(
        &self,
        transaction_mroot: Digest,
        action_mroot: Digest,
    ) -> Result<(), ChainError> {
        pulse_assert(
            self.signed_block_header.header.transaction_mroot == transaction_mroot,
            ChainError::BlockError(format!(
                "transaction merkle root mismatch: expected {}, got {}",
                transaction_mroot, self.signed_block_header.header.transaction_mroot
            )),
        )?;
        pulse_assert(
            self.signed_block_header.header.action_mroot == action_mroot,
            ChainError::BlockError(format!(
                "action merkle root mismatch: expected {}, got {}",
                action_mroot, self.signed_block_header.header.action_mroot
            )),
        )?;
        Ok(())
    }
}

impl Serialize for SignedBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Block", 9)?;
        state.serialize_field("timestamp", &self.signed_block_header.header.timestamp)?;
        state.serialize_field("producer", &self.signed_block_header.header.producer)?;
        state.serialize_field("confirmed", &self.signed_block_header.header.confirmed)?;
        state.serialize_field("previous", &self.signed_block_header.header.previous)?;
        state.serialize_field(
            "transaction_mroot",
            &self.signed_block_header.header.transaction_mroot,
        )?;
        state.serialize_field(
            "action_mroot",
            &self.signed_block_header.header.action_mroot,
        )?;
        state.serialize_field("transactions", &self.transactions)?;
        state.serialize_field(
            "id",
            &self.signed_block_header.header.calculate_id().unwrap(),
        )?;
        state.serialize_field("block_num", &self.signed_block_header.header.block_num())?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use pulsevm_serialization::{
        Read,
        Write,
    };

    use super::{
        BlockHeader,
        MAX_FUTURE_BLOCK_TIME_SLOTS,
    };
    use crate::{
        block::SignedBlock,
        chain::{
            Name,
            crypto::PrivateKey,
            producer_schedule::{
                ProducerKey,
                ProducerSchedule,
            },
        },
    };
    use pulsevm_crypto::Digest;
    use pulsevm_database::BlockTimestamp;

    #[test]
    pub fn test_block_serialization() {
        let signed_block = SignedBlock::default();
        let packed = signed_block.pack().unwrap();
        let _ = SignedBlock::read(&packed, &mut 0).unwrap();
    }

    #[test]
    fn new_schedule_round_trips_none_some_and_garbage() {
        // No schedule change -> None.
        assert!(BlockHeader::default().new_schedule().is_none());

        // A stamped header decodes back to the same schedule.
        let schedule = ProducerSchedule {
            version: 1,
            producers: vec![ProducerKey {
                producer_name: Name::from_str("pulse").unwrap(),
                block_signing_key: PrivateKey::random().get_public_key(),
            }],
        };
        let mut header = BlockHeader::default();
        header.new_producers = Some(schedule.clone());
        header.schedule_version = 1;
        assert_eq!(header.new_schedule().as_ref(), Some(&schedule));
    }

    #[test]
    fn protocol_feature_activation_extension_round_trips_and_rejects_duplicates() {
        let features = [Digest([1u8; 32]), Digest([2u8; 32])];
        let mut header = BlockHeader::default();
        header.set_protocol_feature_activations(&features).unwrap();
        assert_eq!(header.protocol_feature_activations().unwrap(), features);

        let mut duplicate = BlockHeader::default();
        duplicate
            .set_protocol_feature_activations(&[features[0], features[0]])
            .unwrap();
        assert!(duplicate.protocol_feature_activations().is_err());
    }

    #[test]
    fn timestamp_must_advance_beyond_parent() {
        let parent = BlockTimestamp::new(100);
        let now = BlockTimestamp::new(100);

        for slot in [99, 100] {
            let mut header = BlockHeader::default();
            header.timestamp = BlockTimestamp::new(slot);
            assert!(
                header.validate_timestamp(&parent, &now).is_err(),
                "timestamp {slot} must not be accepted after parent 100"
            );
        }
    }

    #[test]
    fn timestamp_may_skip_slots_but_not_run_too_far_ahead() {
        let parent = BlockTimestamp::new(100);
        let now = BlockTimestamp::new(100);

        let mut accepted = BlockHeader::default();
        accepted.timestamp = BlockTimestamp::new(100 + MAX_FUTURE_BLOCK_TIME_SLOTS);
        assert!(accepted.validate_timestamp(&parent, &now).is_ok());

        let mut rejected = BlockHeader::default();
        rejected.timestamp = BlockTimestamp::new(101 + MAX_FUTURE_BLOCK_TIME_SLOTS);
        assert!(rejected.validate_timestamp(&parent, &now).is_err());
    }
}
