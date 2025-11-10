use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::secp256k1::PublicKey;

#[derive(Debug, Default, Clone, Read, Write, NumBytes)]
pub struct BlockSigningAuthority {
    variant: u8,
    threshold: u32,
    keys: Vec<PublicKey>,
}
