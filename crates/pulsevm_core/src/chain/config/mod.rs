use pulsevm_constants::PERCENT_100;
use pulsevm_name_macro::name;
use crate::name::Name;

pub const PLUGIN_VERSION: u32 = 38;
pub const VERSION: &str = "v0.0.1";

// Names
pub const NEWACCOUNT_NAME: Name = Name::new(name!("newaccount"));
pub const SETCODE_NAME: Name = Name::new(name!("setcode"));
pub const SETABI_NAME: Name = Name::new(name!("setabi"));
pub const UPDATEAUTH_NAME: Name = Name::new(name!("updateauth"));
pub const DELETEAUTH_NAME: Name = Name::new(name!("deleteauth"));
pub const LINKAUTH_NAME: Name = Name::new(name!("linkauth"));
pub const UNLINKAUTH_NAME: Name = Name::new(name!("unlinkauth"));
pub const ONERROR_NAME: Name = Name::new(name!("onerror"));
pub const ONBLOCK_NAME: Name = Name::new(name!("onblock"));

pub const fn eos_percent(value: u64, percentage: u32) -> u64 {
    (value * percentage as u64) / PERCENT_100
}
