//! Plain-Rust chain value types shared by `pulsevm_core` and `pulsevm_ffi`.
//!
//! These were originally declared inside the `pulsevm_ffi` cxx bridge, which
//! forced every consumer to depend on the C++ layer just to name a timestamp.
//! They are pure data with pure-Rust behaviour; `pulsevm_ffi` converts them to
//! its bridge structs only where a value actually crosses into C++.

mod block_timestamp;
mod config;
mod elastic_limit_parameters;
mod time;
mod time_point_sec;

pub use block_timestamp::BlockTimestamp;
pub use config::{
    ChainConfigV0,
    MIN_NET_USAGE_DELTA_BETWEEN_BASE_AND_MAX_FOR_TRX,
    PERCENT_1,
    PERCENT_100,
};
pub use elastic_limit_parameters::{
    ElasticLimitParameters,
    Ratio,
};
pub use time::{
    Microseconds,
    TimePoint,
    days,
    hours,
    microseconds,
    milliseconds,
    minutes,
    seconds,
};
pub use time_point_sec::TimePointSec;
