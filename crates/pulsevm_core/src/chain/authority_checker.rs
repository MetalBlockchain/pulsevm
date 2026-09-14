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
    WaitWeight,
};

pub struct AuthorityChecker<'a> {
    recursion_depth_limit: u16,
    provided_keys: &'a BTreeSet<AuthorityPublicKey>,
    provided_permissions: &'a BTreeSet<PermissionLevel>,
    provided_delay: Microseconds,
    used_keys: BTreeSet<AuthorityPublicKey>,
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

enum AuthorityFactor<'a> {
    Permission(&'a PermissionLevelWeight),
    Key(&'a KeyWeight),
    Wait(&'a WaitWeight),
}

impl<'a> AuthorityChecker<'a> {
    pub fn new(
        recursion_depth_limit: u16,
        provided_keys: &'a BTreeSet<AuthorityPublicKey>,
        provided_permissions: &'a BTreeSet<PermissionLevel>,
        provided_delay: Microseconds,
    ) -> Self {
        Self {
            recursion_depth_limit,
            provided_keys,
            provided_permissions,
            provided_delay,
            used_keys: BTreeSet::new(),
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
        let mut cached_permissions = self
            .provided_permissions
            .iter()
            .cloned()
            .map(|permission| (permission, PermissionCacheStatus::PermissionSatisfied))
            .collect();
        self.satisfied_with_cache(db, authority, recursion_depth, &mut cached_permissions)
    }

    pub fn satisfied_with_delay(
        &mut self,
        db: &DbRead<'_>,
        authority: &Authority,
        recursion_depth: u16,
        provided_delay: Microseconds,
    ) -> Result<bool, ChainError> {
        let original_delay = self.provided_delay;
        self.provided_delay = provided_delay;
        let result = self.satisfied(db, authority, recursion_depth);
        self.provided_delay = original_delay;
        result
    }

    fn satisfied_with_cache(
        &mut self,
        db: &DbRead<'_>,
        authority: &Authority,
        recursion_depth: u16,
        cached_permissions: &mut HashMap<PermissionLevel, PermissionCacheStatus>,
    ) -> Result<bool, ChainError> {
        // Restore used_keys unless satisfied: keys from a failed branch must not count as used.
        let used_keys_snapshot = self.used_keys.clone();
        let mut total_weight = 0u32;

        // Leap evaluates all factors by descending (weight, kind-priority):
        // waits, keys, then permission levels for equal weights. Besides
        // determining which keys count as used, that order is observable when
        // nested authorities share or cycle through cached permissions.
        let mut factors = Vec::with_capacity(
            authority.keys().len() + authority.accounts().len() + authority.waits().len(),
        );
        factors.extend(
            authority
                .accounts()
                .iter()
                .map(|value| (value.weight, 1_u8, AuthorityFactor::Permission(value))),
        );
        factors.extend(
            authority
                .keys()
                .iter()
                .map(|value| (value.weight, 2_u8, AuthorityFactor::Key(value))),
        );
        factors.extend(
            authority
                .waits()
                .iter()
                .map(|value| (value.weight, 3_u8, AuthorityFactor::Wait(value))),
        );
        factors.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));

        for (_, _, factor) in factors {
            total_weight += match factor {
                AuthorityFactor::Permission(permission) => self.visit_permission_level_weight(
                    db,
                    permission,
                    recursion_depth,
                    cached_permissions,
                )? as u32,
                AuthorityFactor::Key(key) => self.visit_key_weight(key)? as u32,
                AuthorityFactor::Wait(wait) => {
                    if self.provided_delay >= Microseconds::new(wait.wait_sec as i64 * 1_000_000) {
                        wait.weight as u32
                    } else {
                        0
                    }
                }
            };
            if total_weight >= authority.threshold() {
                return Ok(true);
            }
        }

        self.used_keys = used_keys_snapshot;
        Ok(false)
    }

    pub fn visit_key_weight(&mut self, key: &KeyWeight) -> Result<u16, ChainError> {
        if self.provided_keys.contains(&key.key) {
            self.used_keys.insert(key.key.clone());
            return Ok(key.weight);
        }

        Ok(0)
    }

    fn visit_permission_level_weight(
        &mut self,
        db: &DbRead<'_>,
        permission: &PermissionLevelWeight,
        recursion_depth: u16,
        cached_permissions: &mut HashMap<PermissionLevel, PermissionCacheStatus>,
    ) -> Result<u16, ChainError> {
        // Cache before the depth limit, so an already-satisfied permission counts at any depth.
        let status = cached_permissions.get(&permission.permission).or_else(|| {
            cached_permissions.get(&PermissionLevel::new(permission.permission.actor, 0))
        });
        match status {
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
        cached_permissions.insert(
            permission.permission.clone(),
            PermissionCacheStatus::BeingEvaluated,
        );

        let satisfied =
            self.satisfied_with_cache(db, &auth, recursion_depth + 1, cached_permissions)?;

        if satisfied {
            cached_permissions.insert(
                permission.permission.clone(),
                PermissionCacheStatus::PermissionSatisfied,
            );
            Ok(permission.weight)
        } else {
            cached_permissions.insert(
                permission.permission.clone(),
                PermissionCacheStatus::PermissionUnsatisfied,
            );
            Ok(0)
        }
    }
}
