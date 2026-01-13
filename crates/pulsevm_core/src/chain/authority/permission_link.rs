use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{
    config::{self, BillableSize},
    name::Name,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct PermissionLink {
    id: u64,
    /// The account which is defining its permission requirements
    account: Name,
    /// The contract which account requires @ref required_permission to invoke
    code: Name,
    /// The message type which account requires @ref required_permission to invoke
    /// May be empty; if so, it sets a default @ref required_permission for all messages to @ref code
    message_type: Name,
    /// The permission level which @ref account requires for the specified message types
    /// all of the above fields should not be changed within a chainbase modifier lambda
    pub required_permission: Name,
}

impl PermissionLink {
    pub fn new(
        id: u64,
        account: Name,
        code: Name,
        message_type: Name,
        required_permission: Name,
    ) -> Self {
        PermissionLink {
            id,
            account,
            code,
            message_type,
            required_permission,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn account(&self) -> &Name {
        &self.account
    }

    pub fn code(&self) -> &Name {
        &self.code
    }

    pub fn message_type(&self) -> &Name {
        &self.message_type
    }

    pub fn required_permission(&self) -> &Name {
        &self.required_permission
    }
}

impl BillableSize for PermissionLink {
    fn billable_size() -> u64 {
        (config::OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64 * 3) // 3 indexes
            + 8 // id
            + 8 // account
            + 8 // code
            + 8 // message_type
            + 8 // required_permission
    }
}
