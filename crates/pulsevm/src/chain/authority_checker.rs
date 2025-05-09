use std::collections::{HashMap, HashSet};

use pulsevm_chainbase::UndoSession;

use super::{
    PublicKey,
    authority::{
        Authority, KeyWeight, Permission, PermissionByOwnerIndex, PermissionLevel,
        PermissionLevelWeight,
    },
    authorization_manager::AuthorityError,
};

pub struct AuthorityChecker {
    pub recursion_depth_limit: u16,
    pub provided_keys: HashSet<PublicKey>,
    pub used_keys: HashSet<PublicKey>,
    pub provided_permissions: HashSet<PermissionLevel>,
    pub cached_permissions: HashMap<PermissionLevel, PermissionCacheStatus>,
    pub total_weight: u32,
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
            provided_permissions: HashSet::new(),
            total_weight: 0,
            cached_permissions: HashMap::new(),
        }
    }

    pub fn satisfied(
        &mut self,
        session: &UndoSession,
        authority: &Authority,
    ) -> Result<bool, AuthorityError> {
        for key in authority.keys() {
            self.visit_key_weight(key)?;
        }

        if self.total_weight >= authority.threshold() {
            return Ok(true);
        }

        for permission in authority.accounts() {
            self.visit_permission_level_weight(session, permission, 0)?;
        }

        Ok(self.total_weight >= authority.threshold())
    }

    pub fn visit_key_weight(&mut self, key: &KeyWeight) -> Result<(), AuthorityError> {
        if self.provided_keys.contains(key.key()) {
            self.used_keys.insert(key.key().clone());
            self.total_weight += key.weight() as u32;
        }
        Ok(())
    }

    pub fn visit_permission_level_weight(
        &mut self,
        session: &UndoSession,
        permission: &PermissionLevelWeight,
        recursion_depth: u16,
    ) -> Result<(), AuthorityError> {
        if recursion_depth > self.recursion_depth_limit {
            return Err(AuthorityError::RecursionDepthExceeded);
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
                .map_err(|e| AuthorityError::InternalError)?;

            if auth.is_none() {
                return Ok(());
            }
            let auth = auth.unwrap();
            self.cached_permissions.insert(
                permission.permission().clone(),
                PermissionCacheStatus::BeingEvaluated,
            );
            let satisfied = self.satisfied(session, &auth.authority)?;

            if satisfied {
                self.total_weight += permission.weight() as u32;
                self.cached_permissions.insert(
                    permission.permission().clone(),
                    PermissionCacheStatus::PermissionSatisfied,
                );
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
            self.total_weight += permission.weight() as u32;
        }

        Ok(())
    }
}
