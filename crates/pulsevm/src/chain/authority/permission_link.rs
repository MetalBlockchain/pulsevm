use pulsevm_chainbase::{ChainbaseObject, SecondaryIndex, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;

use crate::chain::{Id, Name};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct PermissionLink {
    id: Id,
    /// The account which is defining its permission requirements
    account: Name,
    /// The contract which account requires @ref required_permission to invoke
    code: Name,
    /// The message type which account requires @ref required_permission to invoke
    /// May be empty; if so, it sets a default @ref required_permission for all messages to @ref code
    message_type: Name,
    /// The permission level which @ref account requires for the specified message types
    /// all of the above fields should not be changed within a chainbase modifier lambda
    required_permission: Name,
}

impl PermissionLink {
    pub fn new(
        id: Id,
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

    pub fn id(&self) -> Id {
        self.id
    }

    pub fn account(&self) -> Name {
        self.account
    }

    pub fn code(&self) -> Name {
        self.code
    }

    pub fn message_type(&self) -> Name {
        self.message_type
    }

    pub fn required_permission(&self) -> Name {
        self.required_permission
    }
}

impl ChainbaseObject for PermissionLink {
    type PrimaryKey = Id;

    fn primary_key(&self) -> Vec<u8> {
        PermissionLink::primary_key_to_bytes(self.id)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.0.to_vec()
    }

    fn table_name() -> &'static str {
        "permission_link"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![
            SecondaryKey {
                key: PermissionLinkByActionNameIndex::secondary_key_as_bytes((
                    self.account,
                    self.code,
                    self.message_type,
                )),
                index_name: PermissionLinkByActionNameIndex::index_name(),
            },
            SecondaryKey {
                key: PermissionLinkByPermissionNameIndex::secondary_key_as_bytes((
                    self.account,
                    self.required_permission,
                    self.id,
                )),
                index_name: PermissionLinkByPermissionNameIndex::index_name(),
            },
        ]
    }
}

#[derive(Debug, Default)]
pub struct PermissionLinkByActionNameIndex;

impl SecondaryIndex<PermissionLink> for PermissionLinkByActionNameIndex {
    type Key = (Name, Name, Name);
    type Object = PermissionLink;

    fn secondary_key(object: &PermissionLink) -> Vec<u8> {
        PermissionLinkByActionNameIndex::secondary_key_as_bytes((
            object.account,
            object.code,
            object.message_type,
        ))
    }

    fn secondary_key_as_bytes(key: Self::Key) -> Vec<u8> {
        key.pack().unwrap()
    }

    fn index_name() -> &'static str {
        "permission_link_by_action_name"
    }
}

#[derive(Debug, Default)]
pub struct PermissionLinkByPermissionNameIndex;

impl SecondaryIndex<PermissionLink> for PermissionLinkByPermissionNameIndex {
    type Key = (Name, Name, Id);
    type Object = PermissionLink;

    fn secondary_key(object: &PermissionLink) -> Vec<u8> {
        PermissionLinkByPermissionNameIndex::secondary_key_as_bytes((
            object.account,
            object.required_permission,
            object.id,
        ))
    }

    fn secondary_key_as_bytes(key: Self::Key) -> Vec<u8> {
        key.pack().unwrap()
    }

    fn index_name() -> &'static str {
        "permission_link_by_permission_name"
    }
}
