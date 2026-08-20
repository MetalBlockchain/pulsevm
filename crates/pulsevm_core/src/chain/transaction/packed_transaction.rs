use std::{
    collections::BTreeSet,
    io::Read as IoRead,
};

use flate2::read::ZlibDecoder;
use pulsevm_constants::{
    FIXED_NET_OVERHEAD_OF_PACKED_TRX,
    MAX_UNCOMPRESSED_PACKED_TRX_SIZE,
};
use pulsevm_crypto::Bytes;
use pulsevm_error::ChainError;
use pulsevm_serialization::{
    NumBytes,
    Read,
    ReadError,
    Write,
    WriteError,
};
use serde::{
    Serialize,
    ser::SerializeStruct,
};

use crate::{
    chain::{
        id::Id,
        transaction::{
            SignedTransaction,
            Transaction,
            TransactionCompression,
        },
        utils::pulse_assert,
    },
    crypto::Signature,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedTransaction {
    signatures: BTreeSet<Signature>,     // Signatures of the transaction
    compression: TransactionCompression, // Compression type used for the transaction
    packed_context_free_data: Bytes,     // Packed context-free data, if any
    packed_trx: Bytes,                   // Packed transaction, not signed, data

    // Following fields are not serialized
    unpacked_trx: SignedTransaction,
    trx_id: Id,
}

impl PackedTransaction {
    /// Materialize the raw `transaction` bytes XPR stores in a
    /// `generated_transaction_object`. Deferred transactions have already
    /// passed authorization when scheduled, so their source representation has
    /// neither signatures nor context-free data. The caller must use the
    /// controller's deferred execution path; normal mempool admission still
    /// rejects the empty signature set.
    pub fn from_deferred_transaction_bytes(packed_trx: Bytes) -> Result<Self, ChainError> {
        Self::new(
            BTreeSet::new(),
            TransactionCompression::None,
            Bytes::default(),
            packed_trx,
        )
    }

    #[inline]
    pub fn new(
        signatures: BTreeSet<Signature>,
        compression: TransactionCompression,
        packed_context_free_data: Bytes,
        packed_trx: Bytes,
    ) -> Result<Self, ChainError> {
        let trx_bytes = maybe_decompress(compression, packed_trx.as_ref())?;
        let cfd_bytes = maybe_decompress(compression, packed_context_free_data.as_ref())?;
        let unpacked_trx = Transaction::read(trx_bytes.as_slice(), &mut 0).map_err(|e| {
            ChainError::SerializationError(format!("failed to unpack transaction: {}", e))
        })?;
        let unpacked_context_free_data = if cfd_bytes.len() > 0 {
            Vec::<Bytes>::read(cfd_bytes.as_slice(), &mut 0).map_err(|e| {
                ChainError::SerializationError(format!("failed to unpack context free data: {}", e))
            })?
        } else {
            vec![]
        };
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

    #[inline]
    pub fn get_signed_transaction(&self) -> &SignedTransaction {
        &self.unpacked_trx
    }

    #[inline]
    pub fn get_transaction(&self) -> &Transaction {
        self.unpacked_trx.transaction()
    }

    #[inline]
    pub fn get_unprunable_size(&self) -> Result<u64, ChainError> {
        let mut size = FIXED_NET_OVERHEAD_OF_PACKED_TRX as u64;
        size += self.packed_trx.len() as u64;
        pulse_assert(
            size <= u32::MAX as u64,
            ChainError::TransactionError("packed_transaction is too big".into()),
        )?;
        Ok(size)
    }

    #[inline]
    pub fn get_prunable_size(&self) -> Result<u64, ChainError> {
        let mut size = self.signatures.num_bytes() as u64;
        size += self.packed_context_free_data.len() as u64;
        pulse_assert(
            size <= u32::MAX as u64,
            ChainError::TransactionError("packed_transaction is too big".into()),
        )?;
        Ok(size)
    }

    #[inline]
    pub fn id(&self) -> &Id {
        &self.trx_id
    }

    #[inline]
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
    #[inline]
    fn num_bytes(&self) -> usize {
        self.signatures.num_bytes()
            + self.compression.num_bytes()
            + self.packed_context_free_data.num_bytes()
            + self.packed_trx.num_bytes()
    }
}

impl Write for PackedTransaction {
    #[inline]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.signatures.write(bytes, pos)?;
        self.compression.write(bytes, pos)?;
        self.packed_context_free_data.write(bytes, pos)?;
        self.packed_trx.write(bytes, pos)?;
        Ok(())
    }
}

impl Read for PackedTransaction {
    #[inline]
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let signatures = BTreeSet::<Signature>::read(data, pos)?;
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
        state.serialize_field("packed_context_free_data", &self.packed_context_free_data)?;
        state.serialize_field("transaction", &self.unpacked_trx.transaction())?;
        state.end()
    }
}

#[inline]
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
            // Cap the decompressed output: a small compressed payload can otherwise expand by a
            // factor of ~1000, and this runs on unauthenticated ingress before any net usage
            // accounting. Read one byte past the limit so an oversized stream is detectable.
            let mut decoder =
                ZlibDecoder::new(data).take(MAX_UNCOMPRESSED_PACKED_TRX_SIZE as u64 + 1);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(|e| {
                ChainError::SerializationError(format!("zlib decompress failed: {e}"))
            })?;
            pulse_assert(
                out.len() <= MAX_UNCOMPRESSED_PACKED_TRX_SIZE,
                ChainError::SerializationError(
                    "zlib decompress failed: uncompressed data is too big".into(),
                ),
            )?;
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{
        Compression,
        write::ZlibEncoder,
    };
    use std::io::Write as IoWrite;

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn decompression_bomb_is_rejected() {
        // A highly compressible payload one byte past the cap. This is a few KB compressed.
        let bomb = zlib_compress(&vec![0u8; MAX_UNCOMPRESSED_PACKED_TRX_SIZE + 1]);
        assert!(bomb.len() < 64 * 1024, "test payload should be tiny");

        let err = maybe_decompress(TransactionCompression::Zlib, &bomb)
            .expect_err("oversized payload must be rejected");
        assert!(
            format!("{err}").contains("uncompressed data is too big"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn decompression_at_the_limit_succeeds() {
        let payload = vec![0u8; MAX_UNCOMPRESSED_PACKED_TRX_SIZE];
        let out = maybe_decompress(TransactionCompression::Zlib, &zlib_compress(&payload)).unwrap();
        assert_eq!(out.len(), MAX_UNCOMPRESSED_PACKED_TRX_SIZE);
    }

    #[test]
    fn ordinary_payload_round_trips() {
        let payload = b"a normally sized transaction payload".to_vec();
        let out = maybe_decompress(TransactionCompression::Zlib, &zlib_compress(&payload)).unwrap();
        assert_eq!(out, payload);
    }
}
