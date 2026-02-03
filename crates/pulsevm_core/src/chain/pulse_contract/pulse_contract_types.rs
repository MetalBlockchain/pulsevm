use std::sync::Arc;

use pulsevm_crypto::Bytes;
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{authority::Authority, name::Name};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct NewAccount {
    pub creator: Name,
    pub name: Name,
    pub owner: Authority,
    pub active: Authority,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct UpdateAuth {
    pub account: Name,
    pub permission: Name,
    pub parent: Name,
    pub auth: Authority,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct DeleteAuth {
    pub account: Name,
    pub permission: Name,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct LinkAuth {
    pub account: Name,
    pub code: Name,
    pub message_type: Name,
    pub requirement: Name,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct UnlinkAuth {
    pub account: Name,
    pub code: Name,
    pub message_type: Name,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct SetCode {
    pub account: Name,
    pub vm_type: u8,
    pub vm_version: u8,
    pub code: Arc<Bytes>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct SetAbi {
    pub account: Name,
    pub abi: Arc<Bytes>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use pulsevm_ffi::{
        KeyWeight, PermissionLevel, PermissionLevelWeight, WaitWeight, parse_public_key,
    };
    use pulsevm_name_macro::name;
    use pulsevm_serialization::{Read, Write};

    #[test]
    fn test_new_account_serialization() {
        let new_account = NewAccount {
            creator: Name::from_str("alice").unwrap(),
            name: Name::from_str("newaccount").unwrap(),
            owner: Authority::new(
                1,
                vec![KeyWeight {
                    key: parse_public_key(
                        "PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H",
                    )
                    .unwrap(),
                    weight: 1,
                }],
                vec![PermissionLevelWeight {
                    permission: PermissionLevel {
                        actor: name!("bob"),
                        permission: name!("active"),
                    },
                    weight: 1,
                }],
                vec![WaitWeight {
                    wait_sec: 10,
                    weight: 1,
                }],
            ),
            active: Authority::new(1, vec![], vec![], vec![]),
        };

        let packed = new_account.pack().unwrap();
        let unpacked = NewAccount::read(&packed, &mut 0).unwrap();

        assert_eq!(new_account, unpacked);
    }
}
