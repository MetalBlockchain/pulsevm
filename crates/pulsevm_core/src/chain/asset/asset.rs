use std::{fmt, str::FromStr};

use pulsevm_proc_macros::{NumBytes, Write};
use pulsevm_serialization::{Read, ReadError};
use serde::{Deserialize, Serialize, de};

use crate::chain::asset::{MAX_PRECISION, Symbol, SymbolCode};

/// Matches nodeos `asset::max_amount`. Amounts are bounded well inside i64 so
/// that addition of two valid assets cannot overflow.
pub const MAX_AMOUNT: i64 = (1i64 << 62) - 1;

#[derive(Debug)]
pub struct ParseAssetError(String);

impl fmt::Display for ParseAssetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseAssetError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Write, NumBytes)]
pub struct Asset {
    /// The amount of the asset
    pub amount: i64,
    /// The symbol name of the asset
    pub symbol: Symbol,
}

impl Asset {
    /// Unchecked constructor. Prefer [`Asset::try_new`] for anything derived
    /// from guest input.
    pub const fn new(amount: i64, symbol: Symbol) -> Self {
        Asset { amount, symbol }
    }

    /// Checked constructor: rejects out-of-range amounts and invalid symbols.
    pub fn try_new(amount: i64, symbol: Symbol) -> Result<Self, ParseAssetError> {
        let asset = Asset { amount, symbol };
        if !asset.is_amount_within_range() {
            return Err(ParseAssetError("magnitude of asset amount must be less than 2^62".into()));
        }
        if !asset.symbol.is_valid() {
            return Err(ParseAssetError("invalid symbol".into()));
        }
        Ok(asset)
    }

    pub const fn amount(&self) -> i64 {
        self.amount
    }

    pub const fn symbol(&self) -> &Symbol {
        &self.symbol
    }

    #[must_use]
    pub const fn is_amount_within_range(&self) -> bool {
        -MAX_AMOUNT <= self.amount && self.amount <= MAX_AMOUNT
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.is_amount_within_range() && self.symbol.is_valid()
    }
}

impl fmt::Display for Asset {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let precision = usize::from(self.symbol.precision());
        let code = self.symbol.code();

        if precision == 0 {
            return write!(f, "{} {}", self.amount, code);
        }

        // Work on the magnitude and emit the sign separately, so the digit
        // arithmetic never has to account for a leading '-'.
        let negative = self.amount < 0;
        let magnitude = self.amount.unsigned_abs();
        let digits = format!("{:0width$}", magnitude, width = precision + 1);
        let split = digits.len() - precision;

        write!(
            f,
            "{}{}.{} {}",
            if negative { "-" } else { "" },
            &digits[..split],
            &digits[split..],
            code
        )
    }
}

impl Default for Asset {
    fn default() -> Self {
        // "SYS" packed little-endian: S=0x53, Y=0x59, S=0x53.
        const SYS: u64 = 0x53_59_53;
        Asset {
            amount: 0,
            symbol: Symbol::new_with_code(4, SymbolCode::new(SYS)),
        }
    }
}

impl Read for Asset {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let amount = i64::read(bytes, pos)?;
        // Symbol::read already validates precision and code.
        let symbol = Symbol::read(bytes, pos)?;
        let asset = Asset { amount, symbol };
        if !asset.is_amount_within_range() {
            return Err(ReadError::ParseError);
        }
        Ok(asset)
    }
}

impl Serialize for Asset {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
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
        let s = s.trim();
        let (amount_str, symbol_str) = s
            .split_once(' ')
            .ok_or_else(|| ParseAssetError("expected format: \"1.0000 XPR\"".into()))?;
        let amount_str = amount_str.trim();
        let symbol_str = symbol_str.trim();

        let symbol_code = SymbolCode::from_str(symbol_str)
            .map_err(|e| ParseAssetError(format!("invalid symbol code: {}", e)))?;

        // Parse the sign explicitly so the fractional digits are always a
        // plain unsigned run — "-0.5000" must not depend on "-0" parsing.
        let (negative, digits_str) = match amount_str.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, amount_str.strip_prefix('+').unwrap_or(amount_str)),
        };

        let (whole, fraction) = match digits_str.split_once('.') {
            Some((w, f)) => (w, f),
            None => (digits_str, ""),
        };

        if whole.is_empty() && fraction.is_empty() {
            return Err(ParseAssetError("missing amount".into()));
        }
        if !whole.bytes().all(|b| b.is_ascii_digit())
            || !fraction.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(ParseAssetError(format!("invalid amount: {}", amount_str)));
        }

        let precision = fraction.len();
        if precision > usize::from(MAX_PRECISION) {
            return Err(ParseAssetError(format!(
                "precision {} exceeds maximum of {}",
                precision, MAX_PRECISION
            )));
        }

        let combined = format!("{}{}", whole, fraction);
        let magnitude = combined
            .parse::<u64>()
            .map_err(|e| ParseAssetError(format!("invalid amount: {}", e)))?;

        if magnitude > MAX_AMOUNT as u64 {
            return Err(ParseAssetError(
                "magnitude of asset amount must be less than 2^62".into(),
            ));
        }

        let amount = if negative {
            -(magnitude as i64)
        } else {
            magnitude as i64
        };

        let symbol = Symbol::try_new_with_code(precision as u8, symbol_code)
            .map_err(|e| ParseAssetError(format!("invalid symbol: {}", e)))?;

        Ok(Asset { amount, symbol })
    }
}

#[cfg(test)]
mod tests {
    use pulsevm_serialization::Write;

    use super::*;

    fn sys(precision: u8) -> Symbol {
        Symbol::new_with_code(precision, SymbolCode::from_str("SYS").unwrap())
    }

    #[test]
    fn test_asset_display() {
        assert_eq!(Asset::new(123456, sys(4)).to_string(), "12.3456 SYS");
        assert_eq!(Asset::new(-123456, sys(4)).to_string(), "-12.3456 SYS");
        assert_eq!(Asset::new(1000000, sys(4)).to_string(), "100.0000 SYS");
        assert_eq!(Asset::new(0, sys(4)).to_string(), "0.0000 SYS");
        assert_eq!(Asset::new(1, sys(4)).to_string(), "0.0001 SYS");
        assert_eq!(Asset::new(-1, sys(4)).to_string(), "-0.0001 SYS");
        assert_eq!(
            Asset::new(
                1000000,
                Symbol::new_with_code(0, SymbolCode::from_str("USD").unwrap())
            )
            .to_string(),
            "1000000 USD"
        );
    }

    #[test]
    fn display_round_trips_through_from_str() {
        for s in [
            "12.3456 SYS",
            "-12.3456 SYS",
            "0.0000 SYS",
            "-0.0001 SYS",
            "1000000 USD",
            "0.1 CUR",
        ] {
            assert_eq!(s.parse::<Asset>().unwrap().to_string(), s, "round trip: {s}");
        }
    }

    #[test]
    fn rejects_excessive_precision() {
        // 19 fractional digits — above MAX_PRECISION of 18.
        assert!("0.1000000000000000000 CUR".parse::<Asset>().is_err());
        // 18 is the boundary and must be accepted.
        assert!("0.100000000000000000 CUR".parse::<Asset>().is_ok());
    }

    #[test]
    fn rejects_out_of_range_amount() {
        let over = Asset::new(MAX_AMOUNT + 1, sys(4));
        assert!(!over.is_amount_within_range());
        assert!(Asset::read(&over.pack().unwrap(), &mut 0).is_err());

        let under = Asset::new(-MAX_AMOUNT - 1, sys(4));
        assert!(!under.is_amount_within_range());
        assert!(Asset::read(&under.pack().unwrap(), &mut 0).is_err());
    }

    #[test]
    fn rejects_malformed_amounts() {
        assert!("1.0.0 SYS".parse::<Asset>().is_err());
        assert!("abc SYS".parse::<Asset>().is_err());
        assert!(". SYS".parse::<Asset>().is_err());
        assert!("1.0000 sys".parse::<Asset>().is_err());
        assert!("1.0000".parse::<Asset>().is_err());
    }

    #[test]
    fn test_asset_pack() {
        let asset = Asset::new(123456, sys(4));
        let packed = hex::encode(asset.pack().unwrap());
        // amount: 123456 LE, then precision 4 + "SYS" packed into the symbol u64
        assert_eq!(packed, "40e20100000000000453595300000000");
    }
}