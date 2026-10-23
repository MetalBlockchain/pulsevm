//! Plain-Rust chain value types shared by `pulsevm_core` and `pulsevm_database`.
//!
//! These were originally declared inside the `pulsevm_database` cxx bridge, which
//! forced every consumer to depend on the C++ layer just to name a timestamp.
//! They are pure data with pure-Rust behaviour; `pulsevm_database` converts them to
//! without pulling in a database implementation.

mod authority;
mod block_timestamp;
mod config;
mod elastic_limit_parameters;
mod genesis;
mod migration;
mod time;
mod time_point_sec;

pub use authority::{
    Authority,
    KeyWeight,
    ParsePermissionLevelError,
    PermissionLevel,
    PermissionLevelWeight,
    WaitWeight,
};
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
pub use genesis::GenesisState;
pub use migration::{
    CEREMONY_VOTE_WINDOW_US,
    HALT_CONFIRMATION_DOMAIN,
    HALT_DECLARATION_DOMAIN,
    HALT_DOMAIN,
    HALT_DOMAIN_V2,
    HaltCommitment,
    HaltConfirmation,
    HaltContractCeremony,
    HaltContractVote,
    HaltDeclaration,
    HaltDeclarationMember,
    HaltRosterEntry,
    HaltSignature,
    HaltWeight,
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
