use std::collections::{
    BTreeSet,
    HashMap,
};

use pulsevm_crypto::AuthorityPublicKey;
use pulsevm_database::{
    DbRead,
    Microseconds,
};
use pulsevm_error::ChainError;

use super::authority::{
    Authority,
    KeyWeight,
    PermissionLevel,
    PermissionLevelWeight,
};

pub struct AuthorityChecker<'a> {
    recursion_depth_limit: u16,
    provided_keys: &'a BTreeSet<AuthorityPublicKey>,
    provided_delay: Microseconds,
    used_keys: BTreeSet<AuthorityPublicKey>,
    cached_permissions: HashMap<PermissionLevel, PermissionCacheStatus>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use pulsevm_crypto::AuthorityPublicKey;
    use pulsevm_database::Microseconds;

    use super::{
        AuthorityChecker,
        KeyWeight,
    };

    #[test]
    fn matches_r1_and_webauthn_authority_keys_without_curve_aliasing() {
        let point = [
            3, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ];
        let r1 = AuthorityPublicKey::R1(point);
        let webauthn = AuthorityPublicKey::WebAuthn {
            point,
            user_presence: 1,
            rpid: "example.com".into(),
        };
        let provided = BTreeSet::from([r1.clone(), webauthn.clone()]);
        let permissions = BTreeSet::new();
        let mut checker = AuthorityChecker::new(6, &provided, &permissions, Microseconds::new(0));

        assert_eq!(checker.visit_key_weight(&KeyWeight::new(r1, 2)).unwrap(), 2);
        assert_eq!(
            checker
                .visit_key_weight(&KeyWeight::new(webauthn, 3))
                .unwrap(),
            3
        );
        assert!(checker.all_keys_used());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PermissionCacheStatus {
    BeingEvaluated,
    PermissionUnsatisfied,
    PermissionSatisfied,
}

impl<'a> AuthorityChecker<'a> {
    pub fn new(
        recursion_depth_limit: u16,
        provided_keys: &'a BTreeSet<AuthorityPublicKey>,
        provided_permissions: &'a BTreeSet<PermissionLevel>,
        provided_delay: Microseconds,
    ) -> Self {
        let mut cached_permissions = HashMap::new();

        for permission in provided_permissions.iter() {
            cached_permissions.insert(
                permission.clone(),
                PermissionCacheStatus::PermissionSatisfied,
            );
        }

        Self {
            recursion_depth_limit,
            provided_keys,
            provided_delay,
            used_keys: BTreeSet::new(),
            cached_permissions,
        }
    }

    pub fn all_keys_used(&self) -> bool {
        if self.provided_keys.len() != self.used_keys.len() {
            return false;
        }

        return *self.provided_keys == self.used_keys;
    }

    pub fn used_keys(&self) -> &BTreeSet<AuthorityPublicKey> {
        &self.used_keys
    }

    pub fn satisfied(
        &mut self,
        db: &DbRead<'_>,
        authority: &Authority,
        recursion_depth: u16,
    ) -> Result<bool, ChainError> {
        // Restore used_keys unless satisfied: keys from a failed branch must not count as used.
        let used_keys_snapshot = self.used_keys.clone();

        let mut total_weight = 0u32;

        for key in authority.keys() {
            total_weight += self.visit_key_weight(key)? as u32;
        }

        if total_weight >= authority.threshold() {
            return Ok(true);
        }

        for permission in authority.accounts() {
            total_weight +=
                self.visit_permission_level_weight(db, permission, recursion_depth)? as u32;
        }

        if total_weight >= authority.threshold() {
            return Ok(true);
        }

        for wait in authority.waits() {
            if self.provided_delay >= Microseconds::new(wait.wait_sec as i64 * 1_000_000) {
                total_weight += wait.weight as u32;
            }
        }

        if total_weight >= authority.threshold() {
            Ok(true)
        } else {
            self.used_keys = used_keys_snapshot;
            Ok(false)
        }
    }

    pub fn visit_key_weight(&mut self, key: &KeyWeight) -> Result<u16, ChainError> {
        if self.provided_keys.contains(&key.key) {
            self.used_keys.insert(key.key.clone());
            return Ok(key.weight);
        }

        Ok(0)
    }

    pub fn visit_permission_level_weight<'b>(
        &mut self,
        db: &DbRead<'_>,
        permission: &PermissionLevelWeight,
        recursion_depth: u16,
    ) -> Result<u16, ChainError> {
        // Cache before the depth limit, so an already-satisfied permission counts at any depth.
        match self.cached_permissions.get(&permission.permission) {
            Some(PermissionCacheStatus::BeingEvaluated) => {
                // Cycle (A->B->A): the back-edge grants no real authority, so
                // return weight 0 and keep evaluating siblings (e.g. a sibling
                // permission with a signed key) instead of failing the tx.
                return Ok(0);
            }
            Some(PermissionCacheStatus::PermissionSatisfied) => {
                return Ok(permission.weight);
            }
            Some(PermissionCacheStatus::PermissionUnsatisfied) => {
                return Ok(0);
            }
            None => {
                // fall through to evaluation
            }
        }

        if recursion_depth >= self.recursion_depth_limit {
            return Ok(0);
        }

        // not cached yet – fetch authority from DB
        let auth = match db.permission_authority(
            permission.permission.actor,
            permission.permission.permission,
        )? {
            Some(auth) => auth,
            None => return Ok(0),
        };

        // mark as being evaluated to detect cycles
        self.cached_permissions.insert(
            permission.permission.clone(),
            PermissionCacheStatus::BeingEvaluated,
        );

        let satisfied = self.satisfied(db, &auth, recursion_depth + 1)?;

        if satisfied {
            self.cached_permissions.insert(
                permission.permission.clone(),
                PermissionCacheStatus::PermissionSatisfied,
            );
            Ok(permission.weight)
        } else {
            self.cached_permissions.insert(
                permission.permission.clone(),
                PermissionCacheStatus::PermissionUnsatisfied,
            );
            Ok(0)
        }
    }
}
