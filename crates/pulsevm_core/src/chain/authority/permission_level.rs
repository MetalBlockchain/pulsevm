use core::fmt;

use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::Serialize;

use crate::chain::Name;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Read,
    Write,
    NumBytes,
    Serialize,
)]
pub struct PermissionLevel {
    pub actor: Name,
    pub permission: Name,
}

impl PermissionLevel {
    pub fn new(actor: Name, permission: Name) -> Self {
        PermissionLevel { actor, permission }
    }
}

impl fmt::Display for PermissionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.actor, self.permission)
    }
}

impl From<(Name, Name)> for PermissionLevel {
    fn from(value: (Name, Name)) -> Self {
        PermissionLevel {
            actor: value.0,
            permission: value.1,
        }
    }
}
