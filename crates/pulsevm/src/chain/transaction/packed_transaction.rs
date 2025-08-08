use std::collections::HashSet;

use pulsevm_crypto::Bytes;
use pulsevm_serialization::{NumBytes, Read, ReadError, Write, WriteError};
use serde::Serialize;

use crate::chain::{
    Id, Signature, SignedTransaction, Transaction, TransactionCompression, error::ChainError,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackedTransaction {
    signatures: HashSet<Signature>,      // Signatures of the transaction
    compression: TransactionCompression, // Compression type used for the transaction
    packed_trx: Bytes,                   // Packed transaction, not signed, data

    // Following fields are not serialized
    unpacked_trx: SignedTransaction,
    trx_id: Id,
}

impl PackedTransaction {
    pub fn new(
        signatures: HashSet<Signature>,
        compression: TransactionCompression,
        packed_trx: Bytes,
    ) -> Result<Self, ChainError> {
        let unpacked_trx = Transaction::read(packed_trx.as_slice(), &mut 0).map_err(|e| {
            ChainError::SerializationError(format!("failed to unpack transaction: {}", e))
        })?;
        let trx_id: Id = unpacked_trx.id()?;

        Ok(Self {
            signatures: signatures.clone(),
            compression,
            packed_trx,

            unpacked_trx: SignedTransaction::new(unpacked_trx, signatures),
            trx_id: trx_id,
        })
    }

    pub fn get_transaction(&self) -> &Transaction {
        &self.unpacked_trx.transaction()
    }

    pub fn get_signed_transaction(&self) -> &SignedTransaction {
        &self.unpacked_trx
    }

    pub fn id(&self) -> &Id {
        &self.trx_id
    }

    #[allow(dead_code)]
    pub fn from_signed_transaction(trx: SignedTransaction) -> Result<Self, ChainError> {
        let trx_id = trx.transaction().id().map_err(|e| {
            ChainError::SerializationError(format!("failed to get transaction ID: {}", e))
        })?;

        Ok(Self {
            signatures: trx.signatures().clone(),
            compression: TransactionCompression::None, // Default to no compression for now
            packed_trx: trx
                .transaction()
                .pack()
                .map_err(|e| {
                    ChainError::SerializationError(format!("failed to pack transaction: {}", e))
                })?
                .into(),

            unpacked_trx: trx,
            trx_id,
        })
    }
}

impl NumBytes for PackedTransaction {
    fn num_bytes(&self) -> usize {
        self.signatures.num_bytes() + self.compression.num_bytes() + self.packed_trx.num_bytes()
    }
}

impl Write for PackedTransaction {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.signatures.write(bytes, pos)?;
        self.compression.write(bytes, pos)?;
        self.packed_trx.write(bytes, pos)?;
        Ok(())
    }
}

impl Read for PackedTransaction {
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let signatures = HashSet::<Signature>::read(data, pos)?;
        let compression = TransactionCompression::read(data, pos)?;
        let packed_trx = Bytes::read(data, pos)?;
        PackedTransaction::new(signatures, compression, packed_trx)
            .map_err(|_| ReadError::ParseError)
    }
}
