use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{error::ChainError, utils::{pulse_assert, Ratio}};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct ElasticLimitParameters {
    pub target: u64,
    pub max: u64,
    pub periods: u32,
    pub max_multiplier: u32,
    pub contract_rate: Ratio<u64>,
    pub expand_rate: Ratio<u64>,
}

impl ElasticLimitParameters {
    pub fn new(
        target: u64,
        max: u64,
        periods: u32,
        max_multiplier: u32,
        contract_rate: Ratio<u64>,
        expand_rate: Ratio<u64>,
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
        pulse_assert(
            self.periods > 0,
            ChainError::InvalidArgument(
                "elastic limit parameter 'periods' cannot be zero".to_owned(),
            ),
        )?;
        pulse_assert(
            self.contract_rate.denominator > 0,
            ChainError::InvalidArgument(
                "elastic limit parameter 'contract_rate' is not a well-defined ratio".to_owned(),
            ),
        )?;
        pulse_assert(
            self.expand_rate.denominator > 0,
            ChainError::InvalidArgument(
                "elastic limit parameter 'expand_rate' is not a well-defined ratio".to_owned(),
            ),
        )?;
        Ok(())
    }
}
