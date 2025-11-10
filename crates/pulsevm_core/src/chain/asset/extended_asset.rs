use std::fmt;

use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{asset::Asset, name::Name};

#[derive(Clone, Debug, Eq, PartialEq, Hash, Read, Write, NumBytes)]
pub struct ExtendedAsset {
    /// The asset
    pub quantity: Asset,
    /// The owner of the asset
    pub contract: Name,
}

impl fmt::Display for ExtendedAsset {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}@{}", self.quantity, self.contract)
    }
}
