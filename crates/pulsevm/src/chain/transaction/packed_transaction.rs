use std::{collections::HashSet, io::Read as IoRead};

use flate2::read::ZlibDecoder;
use pulsevm_crypto::Bytes;
use pulsevm_serialization::{NumBytes, Read, ReadError, Write, WriteError};
use serde::{Serialize, ser::SerializeStruct};

use crate::chain::{
    Id, Signature, SignedTransaction, Transaction, TransactionCompression, error::ChainError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedTransaction {
    signatures: HashSet<Signature>,      // Signatures of the transaction
    compression: TransactionCompression, // Compression type used for the transaction
    packed_context_free_data: Bytes,     // Packed context-free data, if any
    packed_trx: Bytes,                   // Packed transaction, not signed, data

    // Following fields are not serialized
    unpacked_trx: SignedTransaction,
    trx_id: Id,
}

impl PackedTransaction {
    pub fn new(
        signatures: HashSet<Signature>,
        compression: TransactionCompression,
        packed_context_free_data: Bytes,
        packed_trx: Bytes,
    ) -> Result<Self, ChainError> {
        let trx_bytes = maybe_decompress(compression, packed_trx.as_ref())?;
        let cfd_bytes = maybe_decompress(compression, packed_context_free_data.as_ref())?;
        let unpacked_trx = Transaction::read(trx_bytes.as_slice(), &mut 0).map_err(|e| {
            ChainError::SerializationError(format!("failed to unpack transaction: {}", e))
        })?;
        let unpacked_context_free_data =
            Vec::<Bytes>::read(cfd_bytes.as_slice(), &mut 0).map_err(|e| {
                ChainError::SerializationError(format!("failed to unpack context free data: {}", e))
            })?;
        let trx_id: Id = unpacked_trx.id()?;

        Ok(Self {
            signatures: signatures.clone(),
            compression,
            packed_context_free_data,
            packed_trx,

            unpacked_trx: SignedTransaction::new(
                unpacked_trx,
                signatures,
                unpacked_context_free_data,
            ),
            trx_id: trx_id,
        })
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
            packed_context_free_data: Bytes::default(), // No context-free data for now
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
        self.signatures.num_bytes()
            + self.compression.num_bytes()
            + self.packed_context_free_data.num_bytes()
            + self.packed_trx.num_bytes()
    }
}

impl Write for PackedTransaction {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.signatures.write(bytes, pos)?;
        self.compression.write(bytes, pos)?;
        self.packed_context_free_data.write(bytes, pos)?;
        self.packed_trx.write(bytes, pos)?;
        Ok(())
    }
}

impl Read for PackedTransaction {
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let signatures = HashSet::<Signature>::read(data, pos)?;
        let compression = TransactionCompression::read(data, pos)?;
        let packed_context_free_data = Bytes::read(data, pos)?;
        let packed_trx = Bytes::read(data, pos)?;
        PackedTransaction::new(
            signatures,
            compression,
            packed_context_free_data,
            packed_trx,
        )
        .map_err(|_| ReadError::ParseError)
    }
}

impl Serialize for PackedTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PackedTransaction", 5)?;
        state.serialize_field("id", &self.trx_id)?;
        state.serialize_field("signatures", &self.signatures)?;
        state.serialize_field("compression", &self.compression)?;
        state.serialize_field("packed_trx", &self.packed_trx)?;
        state.serialize_field("transaction", &self.unpacked_trx.transaction())?;
        state.end()
    }
}

fn maybe_decompress(
    compression: TransactionCompression,
    data: &[u8],
) -> Result<Vec<u8>, ChainError> {
    match compression {
        TransactionCompression::None => Ok(data.to_vec()),
        TransactionCompression::Zlib => {
            if data.is_empty() {
                return Ok(Vec::new());
            }
            let mut decoder = ZlibDecoder::new(data);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(|e| {
                ChainError::SerializationError(format!("zlib decompress failed: {e}"))
            })?;
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use pulsevm_crypto::Bytes;
    use pulsevm_serialization::Read;

    use crate::chain::PackedTransaction;

    #[test]
    fn it_works() {
        let packed_trx = hex::decode("789cab38bb219991415d8bfb21031030820886d6c5eb181ce6cd524ad9310b2100042bde1a19a5c1050a166d6702d28c606d4cf5befb5857f4fa58969c3b71c15e5267daca46bb25d738048f3cebd2759de1e459c308359d48a50c0055322f6f").unwrap();
        let mut pos = 0;
        let unpacked_trx = PackedTransaction::new(
            HashSet::new(),
            crate::chain::TransactionCompression::Zlib,
            Bytes::default(),
            packed_trx.into(),
        )
        .unwrap();
    }
}
