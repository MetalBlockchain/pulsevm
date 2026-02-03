use core::ops::{Add, AddAssign, Sub, SubAssign};

use pulsevm_proc_macros::{NumBytes, Read, Write};

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Read, Write, NumBytes,
)]
pub struct Microseconds(pub i64);

impl Microseconds {
    #[inline]
    pub const fn new(count: i64) -> Self {
        Self(count)
    }

    #[inline]
    pub const fn maximum() -> Self {
        Self(0x7fff_ffff_ffff_ffff)
    }

    #[inline]
    pub const fn count(self) -> i64 {
        self.0
    }

    #[inline]
    pub const fn to_seconds(self) -> i64 {
        self.0 / 1_000_000
    }
}

/* arithmetic */
impl Add for Microseconds {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}
impl Sub for Microseconds {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}
impl AddAssign for Microseconds {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}
impl SubAssign for Microseconds {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

/* helper constructors (match the C++ free functions) */
#[inline]
pub const fn seconds(s: i64) -> Microseconds {
    Microseconds(s * 1_000_000)
}
#[inline]
pub const fn milliseconds(ms: i64) -> Microseconds {
    Microseconds(ms * 1_000)
}
#[inline]
pub const fn minutes(m: i64) -> Microseconds {
    seconds(60 * m)
}
#[inline]
pub const fn hours(h: i64) -> Microseconds {
    minutes(60 * h)
}
#[inline]
pub const fn days(d: i64) -> Microseconds {
    hours(24 * d)
}
