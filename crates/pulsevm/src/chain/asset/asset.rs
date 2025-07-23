use std::fmt;

use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::Symbol;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Asset {
    /// The amount of the asset
    pub amount: i64,
    /// The symbol name of the asset
    pub symbol: Symbol,
}

impl fmt::Display for Asset {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let precision = self.symbol.precision();
        let symbol_code = self.symbol.code();
        
        if precision == 0 {
            write!(f, "{} {}", self.amount, symbol_code)
        } else {
            let precision = usize::from(precision);
            let formatted = format!(
                "{:0precision$}",
                self.amount,
                precision = precision + if self.amount < 0 { 2 } else { 1 }
            );
            let index = formatted.len() - precision;
            let whole = formatted.get(..index).unwrap_or_else(|| "");
            let fraction = formatted.get(index..).unwrap_or_else(|| "");
            write!(f, "{}.{} {}", whole, fraction, symbol_code)
        }
    }
}

impl Serialize for Asset {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.amount.serialize(bytes);
        self.symbol.serialize(bytes);
    }
}

impl Deserialize for Asset {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let amount = i64::deserialize(data, pos)?;
        let symbol = Symbol::deserialize(data, pos)?;
        Ok(Asset { amount, symbol })
    }
}