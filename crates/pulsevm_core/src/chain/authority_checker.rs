use std::collections::{HashMap, HashSet};

use cxx::SharedPtr;
use pulsevm_error::ChainError;
use pulsevm_ffi::{CxxPublicKey, Database};

use crate::crypto::PublicKey;

use super::authority::{Authority, KeyWeight, PermissionLevel, PermissionLevelWeight};

pub struct AuthorityChecker<'a> {
    recursion_depth_limit: u16,
    provided_keys: &'a HashSet<PublicKey>,
    used_keys: HashSet<PublicKey>,
    cached_permissions: HashMap<PermissionLevel, PermissionCacheStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PermissionCacheStatus {
    BeingEvaluated,
    PermissionUnsatisfied,
    PermissionSatisfied,
}

impl<'a> AuthorityChecker<'a> {
    pub fn new(recursion_depth_limit: u16, provided_keys: &'a HashSet<PublicKey>) -> Self {
        Self {
            recursion_depth_limit,
            provided_keys,
            used_keys: HashSet::new(),
            cached_permissions: HashMap::new(),
        }
    }

    pub fn all_keys_used(&self) -> bool {
        if self.provided_keys.len() != self.used_keys.len() {
            return false;
        }

        return *self.provided_keys == self.used_keys;
    }

    pub fn satisfied(&mut self, db: &Database, authority: &Authority, recursion_depth: u16) -> Result<bool, ChainError> {
        let mut total_weight = 0u32;

        for key in authority.keys() {
            total_weight += self.visit_key_weight(key)? as u32;
        }

        if total_weight >= authority.threshold() {
            return Ok(true);
        }

        for permission in authority.accounts() {
            total_weight += self.visit_permission_level_weight(db, permission, recursion_depth)? as u32;
        }

        Ok(total_weight >= authority.threshold())
    }

    pub fn visit_key_weight(&mut self, key: &KeyWeight) -> Result<u16, ChainError> {
        let pub_key = PublicKey::new(key.key.clone());

        if self.provided_keys.contains(&pub_key) {
            self.used_keys.insert(pub_key);
            return Ok(key.weight);
        }

        Ok(0)
    }

    pub fn visit_permission_level_weight<'b>(
        &mut self,
        db: &Database,
        permission: &PermissionLevelWeight,
        recursion_depth: u16,
    ) -> Result<u16, ChainError> {
        if recursion_depth > self.recursion_depth_limit {
            return Err(ChainError::AuthorizationError("recursion depth exceeded".to_string()));
        }

        // cache lookup
        match self.cached_permissions.get(&permission.permission) {
            Some(PermissionCacheStatus::BeingEvaluated) => {
                // cycle
                return Err(ChainError::AuthorizationError("permission cycle detected".to_string()));
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

        // not cached yet – fetch authority from DB
        let auth = db.find_permission_by_actor_and_permission(permission.permission.actor, permission.permission.permission)?;

        if auth.is_null() {
            return Ok(0);
        }

        let auth = unsafe { &*auth };

        // mark as being evaluated to detect cycles
        self.cached_permissions
            .insert(permission.permission.clone(), PermissionCacheStatus::BeingEvaluated);

        let satisfied = self.satisfied(db, &auth.get_authority().to_authority(), recursion_depth + 1)?;

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
