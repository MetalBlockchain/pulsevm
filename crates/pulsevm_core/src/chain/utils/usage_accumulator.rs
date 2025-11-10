use std::{
    ops::{Add, Div, Mul, Rem},
    u64,
};

use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{config::RATE_LIMITING_PRECISION, error::ChainError, utils::pulse_assert};

#[derive(Debug, Clone, Copy, PartialEq, Read, Write, NumBytes, Default, Eq, Hash)]
pub struct Ratio<T> {
    pub numerator: T,
    pub denominator: T,
}

pub fn make_ratio<T>(n: T, d: T) -> Ratio<T> {
    Ratio {
        numerator: n,
        denominator: d,
    }
}

impl Mul<Ratio<u64>> for u64 {
    type Output = Result<u64, ChainError>;

    fn mul(self, r: Ratio<u64>) -> Self::Output {
        pulse_assert(
            r.numerator == 0 || u64::MAX / r.numerator >= self,
            ChainError::InvalidArgument(
                "usage exceeds maximum value representable after extending for precision"
                    .to_string(),
            ),
        )?;
        Ok((self * r.numerator) / r.denominator)
    }
}

#[derive(Debug, Clone, Copy, NumBytes, Read, Write, Default, PartialEq, Eq, Hash)]
pub struct UsageAccumulator {
    pub last_ordinal: u32, //< The ordinal of the last period which has contributed to the average
    pub value_ex: u64,     //< The current average pre-multiplied by Precision
    pub consumed: u64,     //< The last periods average + the current periods contribution so far
}

impl UsageAccumulator {
    pub fn average(&self) -> u64 {
        integer_divide_ceil(self.value_ex, RATE_LIMITING_PRECISION)
    }

    pub fn max_raw_value(&self) -> u64 {
        u64::MAX / RATE_LIMITING_PRECISION
    }

    pub fn add(&mut self, units: u64, ordinal: u32, window_size: u64) -> Result<(), ChainError> {
        // check for some numerical limits before doing any state mutations
        pulse_assert(
            units <= self.max_raw_value(),
            ChainError::InvalidArgument(
                "usage exceeds maximum value representable after extending for precision"
                    .to_string(),
            ),
        )?;
        pulse_assert(
            u64::MAX - self.consumed >= units,
            ChainError::InvalidArgument("overflow in tracked usage when adding usage".to_string()),
        )?;

        let value_ex_contrib = integer_divide_ceil(units * RATE_LIMITING_PRECISION, window_size);
        pulse_assert(
            u64::MAX - self.value_ex >= value_ex_contrib,
            ChainError::InvalidArgument(
                "overflow in accumulated value when adding usage".to_string(),
            ),
        )?;

        if self.last_ordinal != ordinal {
            pulse_assert(
                ordinal > self.last_ordinal,
                ChainError::InvalidArgument(
                    "new ordinal cannot be less than the previous ordinal".to_string(),
                ),
            )?;

            if self.last_ordinal as u64 + window_size > ordinal as u64 {
                let delta = ordinal - self.last_ordinal;
                let decay = make_ratio(window_size - delta as u64, window_size as u64);

                self.value_ex = (self.value_ex * decay)?;
            } else {
                self.value_ex = 0;
            }

            self.last_ordinal = ordinal;
            self.consumed = self.average();
        }

        self.consumed += units;
        self.value_ex += value_ex_contrib;

        Ok(())
    }
}

pub fn integer_divide_ceil<T>(num: T, den: T) -> T
where
    T: Copy + PartialOrd + Div<Output = T> + Rem<Output = T> + Add<Output = T> + From<u8>,
{
    let div = num / den;
    let rem = num % den;
    if rem > T::from(0) {
        div + T::from(1)
    } else {
        div
    }
}
