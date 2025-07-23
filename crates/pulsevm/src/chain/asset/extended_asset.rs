use std::fmt;

use crate::chain::{Asset, Name};

#[derive(Clone, Debug, Eq, PartialEq)]
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