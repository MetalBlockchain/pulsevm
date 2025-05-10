use std::collections::{HashMap, HashSet};

use pulsevm_chainbase::UndoSession;

use super::{
    authority::{
        Authority, KeyWeight, Permission, PermissionByOwnerIndex, PermissionLevel,
        PermissionLevelWeight,
    }, error::ChainError, PublicKey
};

pub struct AuthorityChecker {
    recursion_depth_limit: u16,
    provided_keys: HashSet<PublicKey>,
    used_keys: HashSet<PublicKey>,
    cached_permissions: HashMap<PermissionLevel, PermissionCacheStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PermissionCacheStatus {
    BeingEvaluated,
    PermissionUnsatisfied,
    PermissionSatisfied,
}

impl AuthorityChecker {
    pub fn new() -> Self {
        Self {
            recursion_depth_limit: 0,
            provided_keys: HashSet::new(),
            used_keys: HashSet::new(),
            cached_permissions: HashMap::new(),
        }
    }

    pub fn all_keys_used(&self) -> bool {
        if self.provided_keys.len() != self.used_keys.len() {
            return false;
        }

        return self.provided_keys == self.used_keys;
    }

    pub fn satisfied(
        &mut self,
        session: &UndoSession,
        authority: &Authority,
        recursion_depth: u16,
    ) -> Result<bool, ChainError> {
        let mut total_weight = 0u32;

        for key in authority.keys() {
            total_weight += self.visit_key_weight(key)? as u32;
        }

        if total_weight >= authority.threshold() {
            return Ok(true);
        }

        for permission in authority.accounts() {
            total_weight +=
                self.visit_permission_level_weight(session, permission, recursion_depth)? as u32;
        }

        Ok(total_weight >= authority.threshold())
    }

    pub fn visit_key_weight(&mut self, key: &KeyWeight) -> Result<u16, ChainError> {
        if self.provided_keys.contains(key.key()) {
            self.used_keys.insert(key.key().clone());
            return Ok(key.weight());
        }
        Ok(0)
    }

    pub fn visit_permission_level_weight(
        &mut self,
        session: &UndoSession,
        permission: &PermissionLevelWeight,
        recursion_depth: u16,
    ) -> Result<u16, ChainError> {
        if recursion_depth > self.recursion_depth_limit {
            return Err(ChainError::AuthorizationError(
                "recursion depth exceeded".to_string(),
            ));
        }
        if !self
            .cached_permissions
            .contains_key(permission.permission())
        {
            let auth = session
                .find_by_secondary::<Permission, PermissionByOwnerIndex>((
                    permission.permission().actor(),
                    permission.permission().permission(),
                ))
                .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;

            if auth.is_none() {
                return Ok(0);
            }
            let auth = auth.unwrap();
            self.cached_permissions.insert(
                permission.permission().clone(),
                PermissionCacheStatus::BeingEvaluated,
            );
            let satisfied = self.satisfied(session, &auth.authority, recursion_depth + 1)?;

            if satisfied {
                self.cached_permissions.insert(
                    permission.permission().clone(),
                    PermissionCacheStatus::PermissionSatisfied,
                );
                return Ok(permission.weight());
            } else {
                self.cached_permissions.insert(
                    permission.permission().clone(),
                    PermissionCacheStatus::PermissionUnsatisfied,
                );
            }
        } else if self
            .cached_permissions
            .get(permission.permission())
            .unwrap()
            == &PermissionCacheStatus::PermissionSatisfied
        {
            return Ok(permission.weight());
        }

        Ok(0)
    }
}
