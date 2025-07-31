use std::ops::{Add, Div, Rem};

pub struct ExponentialMovingAverageAccumulator {
    last_ordinal: u32, //< The ordinal of the last period which has contributed to the average
    value_ex: u64, //< The current average pre-multiplied by Precision
    consumed: u64, //< The last periods average + the current periods contribution so far

    precision: u64, //< The precision of the average
}

impl ExponentialMovingAverageAccumulator {
    pub fn average(&self) -> u64 {
        integer_divide_ceil(self.value_ex, self.precision)
    }
}

fn integer_divide_ceil<T>(num: T, den: T) -> T
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