use core::fmt;

use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::Name;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct PermissionLevel {
    actor: Name,
    permission: Name,
}

impl PermissionLevel {
    pub fn new(actor: Name, permission: Name) -> Self {
        PermissionLevel { actor, permission }
    }

    pub fn actor(&self) -> Name {
        self.actor
    }

    pub fn permission(&self) -> Name {
        self.permission
    }
}

impl fmt::Display for PermissionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.actor, self.permission)
    }
}