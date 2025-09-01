use std::ops::{Add, AddAssign, Sub, SubAssign};

use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::Microseconds;

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Read, Write, NumBytes,
)]
pub struct TimePoint {
    pub elapsed: Microseconds, // microseconds since UNIX epoch
}

impl TimePoint {
    #[inline]
    pub const fn new(elapsed: Microseconds) -> Self {
        Self { elapsed }
    }

    #[inline]
    pub const fn time_since_epoch(&self) -> Microseconds {
        self.elapsed
    }

    #[inline]
    pub const fn sec_since_epoch(&self) -> u32 {
        (self.elapsed.count() / 1_000_000) as u32
    }

    #[inline]
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let dur = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d,
            // If the clock is before 1970-01-01 (rare), clamp to 0.
            Err(_) => std::time::Duration::from_secs(0),
        };

        let micros = (dur.as_secs() as i64)
            .saturating_mul(1_000_000)
            .saturating_add((dur.subsec_nanos() / 1_000) as i64);

        // If your Microseconds type has `new(i64) -> Microseconds`
        TimePoint::new(Microseconds::new(micros))

        // If instead you use helpers, this is equivalent:
        // use crate::microseconds::{seconds, microseconds};
        // TimePoint::new(seconds(dur.as_secs() as i64) + microseconds((dur.subsec_nanos()/1_000) as i64))
    }
}

/* ---- arithmetic/relations (match C++ semantics) ---- */

impl Add<Microseconds> for TimePoint {
    type Output = TimePoint;
    #[inline]
    fn add(self, rhs: Microseconds) -> Self::Output {
        TimePoint::new(self.elapsed + rhs)
    }
}

impl Add for TimePoint {
    type Output = TimePoint;
    #[inline]
    fn add(self, rhs: TimePoint) -> Self::Output {
        TimePoint::new(self.elapsed + rhs.elapsed)
    }
}

impl Sub<Microseconds> for TimePoint {
    type Output = TimePoint;
    #[inline]
    fn sub(self, rhs: Microseconds) -> Self::Output {
        TimePoint::new(self.elapsed - rhs)
    }
}

impl Sub for TimePoint {
    type Output = Microseconds;
    #[inline]
    fn sub(self, rhs: TimePoint) -> Self::Output {
        self.elapsed - rhs.elapsed
    }
}

impl AddAssign<Microseconds> for TimePoint {
    #[inline]
    fn add_assign(&mut self, rhs: Microseconds) {
        self.elapsed += rhs;
    }
}

impl SubAssign<Microseconds> for TimePoint {
    #[inline]
    fn sub_assign(&mut self, rhs: Microseconds) {
        self.elapsed -= rhs;
    }
}
