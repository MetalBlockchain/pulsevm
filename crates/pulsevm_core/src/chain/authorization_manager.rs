use std::collections::HashSet;

use crate::{
    chain::{
        authority::PermissionByParentIndex,
        genesis::ChainConfig,
        name::Name,
        pulse_contract::{DeleteAuth, LinkAuth, UnlinkAuth, UpdateAuth},
        secp256k1::PublicKey,
        transaction::Action,
    },
    utils::pulse_assert,
};

use super::{
    ACTIVE_NAME, ANY_NAME,
    authority::{
        Authority, Permission, PermissionByOwnerIndex, PermissionLevel, PermissionLink,
        PermissionLinkByActionNameIndex,
    },
    authority_checker::AuthorityChecker,
    error::ChainError,
};
use pulsevm_chainbase::UndoSession;
use pulsevm_proc_macros::name;

pub struct AuthorizationManager;

impl AuthorizationManager {
    pub fn check_authorization(
        chain_config: &ChainConfig,
        session: &mut UndoSession,
        actions: &Vec<Action>,
        provided_keys: &HashSet<PublicKey>,
        provided_permissions: &HashSet<PermissionLevel>,
        satisfied_authorizations: &HashSet<PermissionLevel>,
    ) -> Result<(), ChainError> {
        let mut permissions_to_satisfy = HashSet::<PermissionLevel>::new();

        for act in actions.iter() {
            let mut special_case = false;

            if act.account().as_u64() == name!("pulse") {
                special_case = true;

                match act.name().as_u64() {
                    name!("updateauth") => {
                        Self::check_updateauth_authorization(session, act, act.authorization())?
                    }
                    name!("deleteauth") => Self::check_deleteauth_authorization(session, act)?,
                    name!("linkauth") => Self::check_linkauth_authorization(session, act)?,
                    name!("unlinkauth") => Self::check_unlinkauth_authorization(session, act)?,
                    _ => special_case = false,
                }
            }

            for declared_auth in act.authorization() {
                if !special_case {
                    let min_permission_name = Self::lookup_minimum_permission(
                        session,
                        declared_auth.actor,
                        act.account(),
                        act.name(),
                    )?;
                    if min_permission_name.is_some() {
                        // since special cases were already handled, it should only be false if the permission is pulse.any
                        let min_permission_name = min_permission_name.unwrap();
                        let min_permission = Self::get_permission(
                            session,
                            &PermissionLevel::new(declared_auth.actor, min_permission_name),
                        )?;
                        Self::get_permission(session, &declared_auth)?
                            .satisfies(&min_permission, session)
                            .map_err(|_| {
                                ChainError::AuthorizationError(format!(
                                    "action declares irrelevant authority '{}'; minimum authority is {}",
                                    declared_auth,
                                    PermissionLevel::new(min_permission.owner, min_permission.name)
                                ))
                            })?;
                    }
                }

                if !satisfied_authorizations.contains(declared_auth) {
                    permissions_to_satisfy.insert(declared_auth.clone());
                }
            }

            let mut authority_checker =
                AuthorityChecker::new(chain_config.max_authority_depth, provided_keys);

            // Now verify that all the declared authorizations are satisfied
            for p in permissions_to_satisfy.iter() {
                let permission = Self::get_permission(session, p)
                    .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
                let satisfied = authority_checker.satisfied(session, &permission.authority, 0)?;

                if !satisfied {
                    return Err(ChainError::AuthorizationError(format!(
                        "transaction declares authority '{}' but does not have signatures for it",
                        p
                    )));
                }
            }

            // Now verify that all the provided keys are used, otherwise we are wasting resources
            if !authority_checker.all_keys_used() {
                return Err(ChainError::AuthorizationError(
                    "transaction bears irrelevant signatures".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn check_updateauth_authorization(
        session: &mut UndoSession,
        action: &Action,
        auths: &[PermissionLevel],
    ) -> Result<(), ChainError> {
        let update = action
            .data_as::<UpdateAuth>()
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        pulse_assert(
            auths.len() == 1,
            ChainError::IrrelevantAuth(
                "updateauth action should only have one declared authorization".into(),
            ),
        )?;
        let auth = &auths[0];
        pulse_assert(auth.actor == update.account, ChainError::IrrelevantAuth("the owner of the affected permission needs to be the actor of the declared authorization".into()))?;

        // Determine the minimum required permission:
        // - If the permission already exists, use it.
        // - Otherwise, we're creating a new permission, so use the parent.
        let requested_perm = PermissionLevel::new(update.account, update.permission);
        let min_permission =
            if let Some(existing) = Self::find_permission(session, &requested_perm)? {
                existing
            } else {
                Self::get_permission(
                    session,
                    &PermissionLevel::new(update.account, update.parent),
                )?
            };

        Self::get_permission(session, &auth)?
            .satisfies(&min_permission, session)
            .map_err(|_| {
                ChainError::AuthorizationError(format!(
                    "updateauth action declares irrelevant authority '{}'; minimum authority is {}",
                    auth,
                    PermissionLevel::new(update.account, min_permission.name)
                ))
            })?;

        Ok(())
    }

    fn check_deleteauth_authorization(
        session: &mut UndoSession,
        action: &Action,
    ) -> Result<(), ChainError> {
        let del = action
            .data_as::<DeleteAuth>()
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;

        if action.authorization().len() != 1 {
            return Err(ChainError::AuthorizationError(
                "deleteauth action should only have one declared authorization".to_string(),
            ));
        }
        let auth = action.authorization()[0];
        if auth.actor.as_u64() != del.account.as_u64() {
            return Err(ChainError::AuthorizationError(
                "the owner of the permission to delete needs to be the actor of the declared authorization".to_string(),
            ));
        }
        let min_permission =
            Self::get_permission(session, &PermissionLevel::new(del.account, del.permission))?;
        Self::get_permission(session, &auth)?
            .satisfies(&min_permission, session)
            .map_err(|_| {
                ChainError::AuthorizationError(format!(
                    "deleteauth action declares irrelevant authority '{}'; minimum authority is {}",
                    auth,
                    PermissionLevel::new(min_permission.owner, min_permission.name)
                ))
            })?;
        Ok(())
    }

    fn check_linkauth_authorization(
        session: &mut UndoSession,
        action: &Action,
    ) -> Result<(), ChainError> {
        let link = action
            .data_as::<LinkAuth>()
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        if action.authorization().len() != 1 {
            return Err(ChainError::AuthorizationError(
                "link action should only have one declared authorization".to_string(),
            ));
        }
        let auth = action.authorization()[0];
        if auth.actor != link.account {
            return Err(ChainError::AuthorizationError(
                "the owner of the linked permission needs to be the actor of the declared authorization".to_string(),
            ));
        }
        if link.code.as_u64() == name!("pulse") {
            match link.message_type.as_u64() {
                name!("updateauth") => {
                    return Err(ChainError::AuthorizationError(
                        "cannot link pulse::updateauth to a minimum permission".to_string(),
                    ));
                }
                name!("deleteauth") => {
                    return Err(ChainError::AuthorizationError(
                        "cannot link pulse::deleteauth to a minimum permission".to_string(),
                    ));
                }
                name!("linkauth") => {
                    return Err(ChainError::AuthorizationError(
                        "cannot link pulse::linkauth to a minimum permission".to_string(),
                    ));
                }
                name!("unlinkauth") => {
                    return Err(ChainError::AuthorizationError(
                        "cannot link pulse::unlinkauth to a minimum permission".to_string(),
                    ));
                }
                _ => {}
            }
        }
        let linked_permission_name =
            Self::lookup_minimum_permission(session, link.account, link.code, link.message_type)?;
        if linked_permission_name.is_none() {
            return Ok(()); // if action is linked to pulse.any permission
        }
        let linked_permission_name = linked_permission_name.unwrap();
        let min_permission = Self::get_permission(
            session,
            &PermissionLevel::new(link.account, linked_permission_name),
        )?;
        Self::get_permission(session, &auth)?
            .satisfies(&min_permission, session)
            .map_err(|_| {
                ChainError::AuthorizationError(format!(
                    "link action declares irrelevant authority '{}'; minimum authority is {}",
                    auth,
                    PermissionLevel::new(link.account, linked_permission_name)
                ))
            })?;
        Ok(())
    }

    fn check_unlinkauth_authorization(
        session: &mut UndoSession,
        action: &Action,
    ) -> Result<(), ChainError> {
        let unlink = action
            .data_as::<UnlinkAuth>()
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        if action.authorization().len() != 1 {
            return Err(ChainError::AuthorizationError(
                "unlink action should only have one declared authorization".to_string(),
            ));
        }
        let auth = action.authorization()[0];
        if auth.actor != unlink.account {
            return Err(ChainError::AuthorizationError(
                "the owner of the linked permission needs to be the actor of the declared authorization".to_string(),
            ));
        }
        let unlinked_permission_name = Self::lookup_minimum_permission(
            session,
            unlink.account,
            unlink.code,
            unlink.message_type,
        )?;
        if unlinked_permission_name.is_none() {
            return Err(ChainError::AuthorizationError(format!(
                "cannot unlink non-existent permission link of account '{}' for actions matching '{}::{}'",
                unlink.account, unlink.code, unlink.message_type
            )));
        }
        let unlinked_permission_name = unlinked_permission_name.unwrap();
        if unlinked_permission_name == ANY_NAME {
            return Ok(());
        }
        let min_permission = Self::get_permission(
            session,
            &PermissionLevel::new(unlink.account, unlinked_permission_name),
        )?;
        Self::get_permission(session, &auth)?
            .satisfies(&min_permission, session)
            .map_err(|_| {
                ChainError::AuthorizationError(format!(
                    "unlink action declares irrelevant authority '{}'; minimum authority is {}",
                    auth,
                    PermissionLevel::new(unlink.account, unlinked_permission_name)
                ))
            })?;
        Ok(())
    }

    pub fn find_permission(
        session: &mut UndoSession,
        level: &PermissionLevel,
    ) -> Result<Option<Permission>, ChainError> {
        if level.actor.empty() || level.permission.empty() {
            return Err(ChainError::AuthorizationError(
                "invalid permission".to_string(),
            ));
        }
        let result = session
            .find_by_secondary::<Permission, PermissionByOwnerIndex>((
                level.actor,
                level.permission,
            ))
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        if result.is_none() {
            return Ok(None);
        }
        Ok(Some(result.unwrap()))
    }

    pub fn get_permission(
        session: &mut UndoSession,
        level: &PermissionLevel,
    ) -> Result<Permission, ChainError> {
        if level.actor.empty() || level.permission.empty() {
            return Err(ChainError::AuthorizationError(
                "invalid permission".to_string(),
            ));
        }
        let result = session
            .find_by_secondary::<Permission, PermissionByOwnerIndex>((
                level.actor,
                level.permission,
            ))
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        if result.is_none() {
            return Err(ChainError::PermissionNotFound(
                level.actor,
                level.permission.clone(),
            ));
        }
        Ok(result.unwrap())
    }

    fn lookup_minimum_permission(
        session: &mut UndoSession,
        authorizer_account: Name,
        scope: Name,
        act_name: Name,
    ) -> Result<Option<Name>, ChainError> {
        if scope == name!("pulse") {
            if act_name == name!("updateauth")
                || act_name == name!("deleteauth")
                || act_name == name!("linkauth")
                || act_name == name!("unlinkauth")
            {
                return Err(ChainError::AuthorizationError(
                    "cannot call lookup_minimum_permission on native actions that are not allowed to be linked to minimum permissions".to_string(),
                ));
            }
        }

        let linked_permission =
            Self::lookup_linked_permission(session, authorizer_account, scope, act_name)?;

        if linked_permission.is_none() {
            return Ok(Some(ACTIVE_NAME));
        }

        let linked_permission = linked_permission.unwrap();
        if linked_permission == ANY_NAME {
            return Ok(None);
        }

        Ok(Some(linked_permission))
    }

    fn lookup_linked_permission(
        session: &mut UndoSession,
        authorizer_account: Name,
        scope: Name,
        act_name: Name,
    ) -> Result<Option<Name>, ChainError> {
        // First look up a specific link for this message act_name
        let mut key = (authorizer_account, scope, act_name);
        let mut link = session
            .find_by_secondary::<PermissionLink, PermissionLinkByActionNameIndex>(key)
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        // If no specific link found, check for a contract-wide default
        if link.is_none() {
            key = (authorizer_account, scope, Name::default());
            link = session
                .find_by_secondary::<PermissionLink, PermissionLinkByActionNameIndex>(key)
                .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        }

        if link.is_some() {
            return Ok(Some(link.unwrap().required_permission()));
        }

        Ok(None)
    }

    pub fn create_permission(
        session: &mut UndoSession,
        account: Name,
        name: Name,
        parent: u64,
        auth: Authority,
    ) -> Result<Permission, ChainError> {
        let id = session.generate_id::<Permission>().map_err(|e| {
            ChainError::AuthorizationError(format!("Failed to generate permission ID: {}", e))
        })?;
        let permission = Permission::new(id, parent, account, name, auth);
        session.insert(&permission).map_err(|e| {
            ChainError::AuthorizationError(format!("Failed to create permission: {}", e))
        })?;
        Ok(permission)
    }

    pub fn modify_permission(
        session: &mut UndoSession,
        permission: &mut Permission,
        auth: &Authority,
    ) -> Result<(), ChainError> {
        session
            .modify(permission, |po| {
                po.authority = auth.clone();
                Ok(())
            })
            .map_err(|e| {
                ChainError::AuthorizationError(format!("Failed to create permission: {}", e))
            })?;
        Ok(())
    }

    pub fn remove_permission(
        session: &mut UndoSession,
        permission: &Permission,
    ) -> Result<(), ChainError> {
        let mut index = session.get_index::<Permission, PermissionByParentIndex>();
        let mut range = index.lower_bound(permission.id())?;
        let next = range.next()?;

        if let Some(_) = next {
            return Err(ChainError::ActionValidationError(format!(
                "cannot delete permission '{}' because it has child permissions",
                permission
            )));
        }

        session.remove(permission.clone())?;

        Ok(())
    }
}
