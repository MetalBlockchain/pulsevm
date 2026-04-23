use std::{fmt, str::FromStr};

use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::{Deserialize, Serialize, de};

use crate::chain::asset::{Symbol, SymbolCode};

#[derive(Debug)]
pub struct ParseAssetError(String);

impl fmt::Display for ParseAssetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseAssetError {}

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

impl Default for Asset {
    fn default() -> Self {
        Asset {
            amount: 0,
            symbol: Symbol::new_with_code(4, SymbolCode::from_str("SYS").unwrap()),
        }
    }
}

impl Serialize for Asset {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = self.to_string();
        serializer.serialize_str(&value)
    }
}

impl<'de> Deserialize<'de> for Asset {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<Asset>().map_err(de::Error::custom)
    }
}

impl FromStr for Asset {
    type Err = ParseAssetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (amount_str, symbol_str) = s
            .split_once(' ')
            .ok_or_else(|| ParseAssetError("expected format: \"1.0000 XPR\"".into()))?;

        let symbol_code = SymbolCode::from_str(symbol_str)
            .map_err(|e| ParseAssetError(format!("invalid symbol code: {}", e)))?;

        let (amount, precision) = if let Some((whole, fraction)) = amount_str.split_once('.') {
            let precision = fraction.len() as u8;
            let combined = format!("{}{}", whole, fraction);
            let amount = combined
                .parse::<i64>()
                .map_err(|e| ParseAssetError(format!("invalid amount: {}", e)))?;
            (amount, precision)
        } else {
            let amount = amount_str
                .parse::<i64>()
                .map_err(|e| ParseAssetError(format!("invalid amount: {}", e)))?;
            (amount, 0u8)
        };

        let symbol = Symbol::new_with_code(precision, symbol_code);
        Ok(Asset { amount, symbol })
    }
}

#[cfg(test)]
mod tests {
    use pulsevm_serialization::Write;

    use super::*;

    #[test]
    fn test_asset_display() {
        let symbol = Symbol::new_with_code(4, SymbolCode::from_str("SYS").unwrap());
        let asset = Asset::new(123456, symbol.clone());
        assert_eq!(asset.to_string(), "12.3456 SYS");

        let asset = Asset::new(-123456, symbol.clone());
        assert_eq!(asset.to_string(), "-12.3456 SYS");

        let asset = Asset::new(1000000, symbol.clone());
        assert_eq!(asset.to_string(), "100.0000 SYS");

        let asset = Asset::new(
            1000000,
            Symbol::new_with_code(0, SymbolCode::from_str("USD").unwrap()),
        );
        assert_eq!(asset.to_string(), "1000000 USD");

        let asset = Asset::new(0, symbol);
        assert_eq!(asset.to_string(), "0.0000 SYS");
    }

    #[test]
    fn test_asset_pack() {
        let symbol = Symbol::new_with_code(4, SymbolCode::from_str("SYS").unwrap());
        let asset = Asset::new(123456, symbol);
        let packed = asset.pack().unwrap();
        let packed = hex::encode(packed);
        let expected_hex = "40e20100000000000453595300000000"; // amount: 123456 (0xe201), precision: 4, symbol: "SYS"
        assert_eq!(packed, expected_hex);
    }
}
