//! Avalanche Interchain Messaging (ICM / warp) for PulseVM.
//!
//! This module implements cross-chain messaging the Avalanche-native way: a
//! source chain emits an [`UnsignedMessage`], the local validator's BLS key signs
//! its id, a relayer aggregates signatures from enough of the source subnet's
//! stake, and the destination chain verifies the aggregate against the source
//! validator set before delivering the payload to a contract.
//!
//! Layers:
//! * [`codec`] — the AvalancheGo big-endian wire codec primitives;
//! * [`payload`] — `AddressedCall` / `Hash` message bodies;
//! * [`message`] — `UnsignedMessage` / `Message` / `BitSetSignature` envelopes;
//! * [`validator`] — the canonical validator set and signer bitset;
//! * [`verify`] — weighted-quorum aggregate BLS verification;
//! * [`signer`] — the boundary to MetalGo's warp signer (local BLS or gRPC).
//!
//! The cryptography lives in `pulsevm_crypto::bls`. The wire format mirrors
//! AvalancheGo so PulseVM interoperates with MetalGo validators and ICM relayers.

pub mod codec;
pub mod manager;
pub mod message;
pub mod payload;
pub mod signer;
pub mod validator;
pub mod validator_source;
pub mod verify;

pub use manager::{
    VerifiedMessage,
    WarpManager,
};
pub use message::{
    BitSetSignature,
    Message,
    UnsignedMessage,
};
pub use payload::{
    AddressedCall,
    Hash,
};
pub use signer::{
    LocalBlsSigner,
    WarpSigner,
    WarpSignerError,
};
pub use validator::{
    CanonicalValidatorSet,
    SignerBitset,
    Validator,
};
pub use validator_source::{
    StaticValidatorSource,
    ValidatorSetSource,
};
pub use verify::{
    VerifyError,
    verify_message,
    verify_message_with_quorum,
};
