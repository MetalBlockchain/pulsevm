use std::{
    ops::{Add, Div, Rem},
    u64,
};

use pulsevm_ffi::Ratio;

pub fn make_ratio(n: u64, d: u64) -> Ratio {
    Ratio {
        numerator: n,
        denominator: d,
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
