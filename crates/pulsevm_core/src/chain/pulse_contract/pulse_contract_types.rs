use std::sync::Arc;

use pulsevm_crypto::{
    Bytes,
    Digest,
};
use pulsevm_proc_macros::{
    NumBytes,
    Read,
    Write,
};
use pulsevm_serialization::Write;

use crate::chain::{
    authority::{
        Authority,
        PermissionLevel,
    },
    name::Name,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct NewAccount {
    pub creator: Name,
    pub name: Name,
    pub owner: Authority,
    pub active: Authority,
}

impl TryFrom<NewAccount> for Arc<[u8]> {
    type Error = String;

    fn try_from(value: NewAccount) -> Result<Self, Self::Error> {
        value.pack().map(Arc::from).map_err(|e| e.to_string())
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes)]
pub struct CancelDelay {
    pub canceling_auth: PermissionLevel,
    pub trx_id: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct SetCode {
    pub account: Name,
    pub vm_type: u8,
    pub vm_version: u8,
    pub code: Arc<Bytes>,
}

impl TryFrom<SetCode> for Arc<[u8]> {
    type Error = String;

    fn try_from(value: SetCode) -> Result<Self, Self::Error> {
        value.pack().map(Arc::from).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct SetAbi {
    pub account: Name,
    pub abi: Arc<Bytes>,
}

impl TryFrom<SetAbi> for Arc<[u8]> {
    type Error = String;

    fn try_from(value: SetAbi) -> Result<Self, Self::Error> {
        value.pack().map(Arc::from).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use pulsevm_crypto::k1::K1PublicKey;
    use pulsevm_database::{
        KeyWeight,
        PermissionLevel,
        PermissionLevelWeight,
        WaitWeight,
    };
    use pulsevm_name_macro::name;
    use pulsevm_serialization::{
        Read,
        Write,
    };

    #[test]
    fn test_new_account_serialization() {
        let new_account = NewAccount {
            creator: Name::from_str("alice").unwrap(),
            name: Name::from_str("newaccount").unwrap(),
            owner: Authority::new(
                1,
                vec![KeyWeight::new(
                    K1PublicKey::from_string(
                        "PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H",
                    )
                    .unwrap(),
                    1,
                )],
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

    #[test]
    fn updateauth_accepts_opaque_k1_authority_key() {
        // XPR Mainnet block 315,443,046 stores an all-zero K1 shim. Leap
        // accepts and persists this unsatisfiable authority verbatim.
        let packed = hex::decode(
            "000000f3ea93af4200000000a8ed32320000000080ab26a701000000010000000000000000000000000000000000000000000000000000000000000000000001000000",
        )
        .unwrap();
        let mut pos = 0;
        let update = UpdateAuth::read(&packed, &mut pos).unwrap();

        assert_eq!(pos, packed.len());
        assert_eq!(update.account, name!("certburn"));
        assert_eq!(update.permission, name!("active"));
        assert_eq!(update.parent, name!("owner"));
        assert!(update.auth.validate());
        assert_eq!(update.auth.keys.len(), 1);
        assert_eq!(update.auth.keys[0].key.to_packed(), [0_u8; 34]);
        assert!(update.auth.keys[0].key.as_k1().is_none());
    }
}
