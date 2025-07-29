use std::fmt;

use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::Symbol;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct Asset {
    /// The amount of the asset
    pub amount: i64,
    /// The symbol name of the asset
    pub symbol: Symbol,
}

impl Asset {
    /// Creates a new asset with the given amount and symbol.
    pub fn new(amount: i64, symbol: Symbol) -> Self {
        Asset { amount, symbol }
    }

    /// Returns the amount of the asset.
    pub fn amount(&self) -> i64 {
        self.amount
    }

    /// Returns the symbol of the asset.
    pub fn symbol(&self) -> &Symbol {
        &self.symbol
    }
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
