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
use pulsevm_serialization::Write;
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
    pub new_producers: Option<Vec<u8>>,
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
    pub fn new_schedule(&self) -> Result<Option<ProducerSchedule>, ChainError> {
        match &self.new_producers {
            None => Ok(None),
            Some(bytes) => {
                let schedule = ProducerSchedule::read_bounded(bytes)
                    .map_err(|e| ChainError::BlockError(format!("invalid new_producers: {}", e)))?;
                Ok(Some(schedule))
            }
        }
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
        match self.new_schedule()? {
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
        pulse_assert(
            self.header_extensions.is_empty(),
            ChainError::BlockError("header extensions not supported".into()),
        )?;
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

    use super::BlockHeader;
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

    #[test]
    pub fn test_block_serialization() {
        let signed_block = SignedBlock::default();
        let packed = signed_block.pack().unwrap();
        let _ = SignedBlock::read(&packed, &mut 0).unwrap();
    }

    #[test]
    fn new_schedule_round_trips_none_some_and_garbage() {
        // No schedule change -> None.
        assert!(BlockHeader::default().new_schedule().unwrap().is_none());

        // A stamped header decodes back to the same schedule.
        let schedule = ProducerSchedule {
            version: 1,
            producers: vec![ProducerKey {
                producer_name: Name::from_str("pulse").unwrap(),
                block_signing_key: PrivateKey::random().get_public_key(),
            }],
        };
        let mut header = BlockHeader::default();
        header.new_producers = Some(schedule.pack().unwrap());
        header.schedule_version = 1;
        assert_eq!(header.new_schedule().unwrap().unwrap(), schedule);

        // Undecodable new_producers is an error, never a panic.
        let mut header = BlockHeader::default();
        header.new_producers = Some(vec![0xff, 0xff, 0xff, 0xff, 0xff]);
        assert!(header.new_schedule().is_err());
    }
}
