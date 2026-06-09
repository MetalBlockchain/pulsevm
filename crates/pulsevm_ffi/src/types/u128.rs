use crate::bridge::ffi::U128;

impl From<u128> for U128 {
    fn from(v: u128) -> Self {
        U128 { lo: v as u64, hi: (v >> 64) as u64 }
    }
}

impl From<U128> for u128 {
    fn from(v: U128) -> Self {
        ((v.hi as u128) << 64) | (v.lo as u128)
    }
}