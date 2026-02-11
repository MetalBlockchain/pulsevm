use std::ops::Mul;

use pulsevm_error::ChainError;

use crate::bridge::ffi::{ElasticLimitParameters, Ratio};

impl ElasticLimitParameters {
    pub fn new(
        target: u64,
        max: u64,
        periods: u32,
        max_multiplier: u32,
        contract_rate: Ratio,
        expand_rate: Ratio,
    ) -> Self {
        ElasticLimitParameters {
            target,
            max,
            periods,
            max_multiplier,
            contract_rate,
            expand_rate,
        }
    }

    pub fn validate(&self) -> Result<(), ChainError> {
        if self.periods == 0 {
            return Err(ChainError::InvalidArgument(
                "elastic limit parameter 'periods' cannot be zero".to_owned(),
            ));
        }
        if self.contract_rate.denominator == 0 {
            return Err(ChainError::InvalidArgument(
                "elastic limit parameter 'contract_rate' is not a well-defined ratio".to_owned(),
            ));
        }
        if self.expand_rate.denominator == 0 {
            return Err(ChainError::InvalidArgument(
                "elastic limit parameter 'expand_rate' is not a well-defined ratio".to_owned(),
            ));
        }

        Ok(())
    }
}

impl Mul<Ratio> for u64 {
    type Output = Result<u64, ChainError>;

    fn mul(self, r: Ratio) -> Self::Output {
        if !(r.numerator == 0 || u64::MAX / r.numerator >= self) {
            return Err(ChainError::InvalidArgument(
                "usage exceeds maximum value representable after extending for precision"
                    .to_string(),
            ));
        }

        Ok((self * r.numerator) / r.denominator)
    }
}
