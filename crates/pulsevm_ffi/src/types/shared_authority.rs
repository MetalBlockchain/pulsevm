use pulsevm_crypto::k1::K1PublicKey;

use crate::{
    Authority,
    KeyWeight,
    PermissionLevel,
    PermissionLevelWeight,
    WaitWeight,
    bridge::ffi::{
        CxxSharedAuthority,
        get_authority_from_shared_authority,
        packed_public_key_bytes,
    },
};

impl CxxSharedAuthority {
    pub fn to_authority(&self) -> Authority {
        // Keys read out of chainbase are always well-formed, so the re-parse
        // cannot fail here.
        let auth = get_authority_from_shared_authority(self);
        let keys = auth
            .keys
            .iter()
            .map(|k| {
                let packed = match k.key.as_ref() {
                    Some(pk) => packed_public_key_bytes(pk),
                    None => Vec::new(),
                };
                KeyWeight {
                    key: K1PublicKey::from_packed(&packed)
                        .expect("chainbase authority has valid keys"),
                    weight: k.weight,
                }
            })
            .collect();
        let accounts = auth
            .accounts
            .iter()
            .map(|a| PermissionLevelWeight {
                permission: PermissionLevel {
                    actor: a.permission.actor,
                    permission: a.permission.permission,
                },
                weight: a.weight,
            })
            .collect();
        let waits = auth
            .waits
            .iter()
            .map(|w| WaitWeight {
                wait_sec: w.wait_sec,
                weight: w.weight,
            })
            .collect();
        Authority {
            threshold: auth.threshold,
            keys,
            accounts,
            waits,
        }
    }
}
