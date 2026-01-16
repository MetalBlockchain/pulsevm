use std::collections::HashSet;

use pulsevm_ffi::{Database, PermissionObject};

use crate::{
    PULSE_NAME,
    chain::{
        genesis::ChainConfig,
        name::Name,
        pulse_contract::{DeleteAuth, LinkAuth, UnlinkAuth, UpdateAuth},
        secp256k1::PublicKey,
        transaction::Action,
    },
    config::{DELETEAUTH_NAME, LINKAUTH_NAME, UNLINKAUTH_NAME, UPDATEAUTH_NAME},
    utils::pulse_assert,
};

use super::{
    ACTIVE_NAME, ANY_NAME,
    authority::{Authority, Permission, PermissionLevel, PermissionLink},
    authority_checker::AuthorityChecker,
    error::ChainError,
};

pub struct AuthorizationManager;

impl AuthorizationManager {
    pub fn check_authorization(
        chain_config: &ChainConfig,
        db: &mut Database,
        actions: &Vec<Action>,
        provided_keys: &HashSet<PublicKey>,
        provided_permissions: &HashSet<PermissionLevel>,
        satisfied_authorizations: &HashSet<PermissionLevel>,
    ) -> Result<(), ChainError> {
        let mut permissions_to_satisfy = HashSet::<PermissionLevel>::new();

        for act in actions.iter() {
            let mut special_case = false;

            if act.account() == PULSE_NAME {
                special_case = true;

                match act.name() {
                    UPDATEAUTH_NAME => {
                        Self::check_updateauth_authorization(db, act, act.authorization())?
                    }
                    DELETEAUTH_NAME => Self::check_deleteauth_authorization(db, act)?,
                    LINKAUTH_NAME => Self::check_linkauth_authorization(db, act)?,
                    UNLINKAUTH_NAME => Self::check_unlinkauth_authorization(db, act)?,
                    _ => special_case = false,
                }
            }

            for declared_auth in act.authorization() {
                if !special_case {
                    let min_permission_name = Self::lookup_minimum_permission(
                        db,
                        declared_auth.actor,
                        act.account(),
                        act.name(),
                    )?;

                    if let Some(min_permission_name) = min_permission_name {
                        // since special cases were already handled, it should only be false if the permission is pulse.any
                        let min_permission = Self::get_permission(
                            db,
                            &PermissionLevel::new(declared_auth.actor, min_permission_name),
                        )?;
                        pulse_assert(
                            Self::get_permission(db, &declared_auth)?
                                .satisfies(&min_permission, db)?,
                            ChainError::IrrelevantAuth(format!(
                                "action declares irrelevant authority '{}'; minimum authority is {}",
                                declared_auth,
                                PermissionLevel::new(min_permission.owner, min_permission.name)
                            )),
                        )?;
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
                pulse_assert(
                    authority_checker.satisfied(
                        db,
                        &Authority::new_from_permission_level(p.clone()),
                        0,
                    )?,
                    ChainError::AuthorizationError(format!(
                        "transaction declares authority '{}' but does not have signatures for it",
                        p
                    )),
                )?;
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
        db: &mut Database,
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
        let min_permission = if let Some(existing) = Self::find_permission(db, &requested_perm)? {
            existing
        } else {
            Self::get_permission(db, &PermissionLevel::new(update.account, update.parent))?
        };

        pulse_assert(
            Self::get_permission(db, &auth)?.satisfies(&min_permission, db)?,
            ChainError::IrrelevantAuth(format!(
                "updateauth action declares irrelevant authority '{}'; minimum authority is {}",
                auth,
                PermissionLevel::new(update.account, min_permission.name)
            )),
        )?;

        Ok(())
    }

    fn check_deleteauth_authorization(
        db: &mut Database,
        action: &Action,
    ) -> Result<(), ChainError> {
        let del = action
            .data_as::<DeleteAuth>()
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        pulse_assert(
            action.authorization().len() == 1,
            ChainError::AuthorizationError(
                "deleteauth action should only have one declared authorization".to_string(),
            ),
        )?;
        let auth = action.authorization()[0];
        pulse_assert(auth.actor == del.account, ChainError::AuthorizationError(
            "the owner of the permission to delete needs to be the actor of the declared authorization".to_string(),
        ))?;
        let min_permission =
            Self::get_permission(db, &PermissionLevel::new(del.account, del.permission))?;
        pulse_assert(
            Self::get_permission(db, &auth)?.satisfies(&min_permission, db)?,
            ChainError::AuthorizationError(format!(
                "deleteauth action declares irrelevant authority '{}'; minimum authority is {}",
                auth,
                PermissionLevel::new(min_permission.owner, min_permission.name)
            )),
        )?;
        Ok(())
    }

    fn check_linkauth_authorization(db: &mut Database, action: &Action) -> Result<(), ChainError> {
        let link = action
            .data_as::<LinkAuth>()
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        pulse_assert(
            action.authorization().len() == 1,
            ChainError::AuthorizationError(
                "link action should only have one declared authorization".to_string(),
            ),
        )?;
        let auth = action.authorization()[0];
        pulse_assert(auth.actor == link.account, ChainError::AuthorizationError(
            "the owner of the linked permission needs to be the actor of the declared authorization".to_string(),
        ))?;
        if link.code == PULSE_NAME {
            match link.message_type {
                UPDATEAUTH_NAME => {
                    return Err(ChainError::AuthorizationError(
                        "cannot link pulse::updateauth to a minimum permission".to_string(),
                    ));
                }
                DELETEAUTH_NAME => {
                    return Err(ChainError::AuthorizationError(
                        "cannot link pulse::deleteauth to a minimum permission".to_string(),
                    ));
                }
                LINKAUTH_NAME => {
                    return Err(ChainError::AuthorizationError(
                        "cannot link pulse::linkauth to a minimum permission".to_string(),
                    ));
                }
                UNLINKAUTH_NAME => {
                    return Err(ChainError::AuthorizationError(
                        "cannot link pulse::unlinkauth to a minimum permission".to_string(),
                    ));
                }
                _ => {}
            }
        }
        let linked_permission_name =
            Self::lookup_minimum_permission(db, link.account, link.code, link.message_type)?;

        match linked_permission_name {
            None => {
                return Ok(()); // if action is linked to pulse.any permission
            }
            Some(linked_permission_name) => {
                let min_permission = Self::get_permission(
                    db,
                    &PermissionLevel::new(link.account, linked_permission_name),
                )?;
                pulse_assert(
                    Self::get_permission(db, &auth)?.satisfies(&min_permission, db)?,
                    ChainError::AuthorizationError(format!(
                        "link action declares irrelevant authority '{}'; minimum authority is {}",
                        auth,
                        PermissionLevel::new(link.account, linked_permission_name)
                    )),
                )?;
            }
        }

        Ok(())
    }

    fn check_unlinkauth_authorization(
        db: &mut Database,
        action: &Action,
    ) -> Result<(), ChainError> {
        let unlink = action
            .data_as::<UnlinkAuth>()
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        pulse_assert(
            action.authorization().len() == 1,
            ChainError::AuthorizationError(
                "unlink action should only have one declared authorization".to_string(),
            ),
        )?;
        let auth = action.authorization()[0];
        pulse_assert(auth.actor == unlink.account, ChainError::AuthorizationError(
            "the owner of the linked permission needs to be the actor of the declared authorization".to_string(),
        ))?;
        let unlinked_permission_name =
            Self::lookup_minimum_permission(db, unlink.account, unlink.code, unlink.message_type)?;
        match unlinked_permission_name {
            None => {
                return Err(ChainError::AuthorizationError(format!(
                    "cannot unlink non-existent permission link of account '{}' for actions matching '{}::{}'",
                    unlink.account, unlink.code, unlink.message_type
                )));
            }
            Some(name) if name == ANY_NAME => {
                return Ok(());
            }
            Some(unlinked_permission_name) => {
                let min_permission = Self::get_permission(
                    db,
                    &PermissionLevel::new(unlink.account, unlinked_permission_name),
                )?;
                pulse_assert(
                    Self::get_permission(db, &auth)?.satisfies(&min_permission, db)?,
                    ChainError::AuthorizationError(format!(
                        "unlink action declares irrelevant authority '{}'; minimum authority is {}",
                        auth,
                        PermissionLevel::new(unlink.account, unlinked_permission_name)
                    )),
                )?;
            }
        }
        Ok(())
    }

    pub fn find_permission(
        db: &mut Database,
        level: &PermissionLevel,
    ) -> Result<Option<Permission>, ChainError> {
        pulse_assert(
            !level.actor.empty() && !level.permission.empty(),
            ChainError::AuthorizationError("invalid permission".to_string()),
        )?;
        let result = db.find_by_secondary::<Permission, PermissionByOwnerIndex>((
            level.actor,
            level.permission,
        ))?;
        match result {
            Some(permission) => Ok(Some(permission)),
            None => Ok(None),
        }
    }

    pub fn get_permission(
        db: &mut Database,
        actor: &Name,
        permission: &Name,
    ) -> Result<&PermissionObject, ChainError> {
        pulse_assert(
            !actor.empty() && !permission.empty(),
            ChainError::AuthorizationError("invalid permission".to_string()),
        )?;
        let result =
            db.get_permission_by_actor_and_permission(actor.as_ref(), permission.as_ref())?;
        Ok(result)
    }

    fn lookup_minimum_permission(
        db: &mut Database,
        authorizer_account: Name,
        scope: Name,
        act_name: Name,
    ) -> Result<Option<Name>, ChainError> {
        // Special case native actions cannot be linked to a minimum permission, so there is no need to check.
        if scope == PULSE_NAME {
            pulse_assert(act_name != UPDATEAUTH_NAME && act_name != DELETEAUTH_NAME && act_name != LINKAUTH_NAME && act_name != UNLINKAUTH_NAME, ChainError::AuthorizationError(
                "cannot call lookup_minimum_permission on native actions that are not allowed to be linked to minimum permissions".to_string(),
            ))?;
        }

        let linked_permission =
            Self::lookup_linked_permission(db, authorizer_account, scope, act_name)?;

        if let Some(linked_permission) = linked_permission {
            if linked_permission == ANY_NAME {
                return Ok(None);
            }

            return Ok(Some(linked_permission));
        } else {
            return Ok(Some(ACTIVE_NAME));
        }
    }

    fn lookup_linked_permission(
        db: &mut Database,
        authorizer_account: Name,
        scope: Name,
        act_name: Name,
    ) -> Result<Option<Name>, ChainError> {
        // First look up a specific link for this message act_name
        let mut key = (authorizer_account, scope, act_name);
        let mut link =
            db.find_by_secondary::<PermissionLink, PermissionLinkByActionNameIndex>(key)?;

        if let Some(link) = &link {
            return Ok(Some(link.required_permission()));
        } else {
            // If no specific link found, check for a contract-wide default
            key.2 = Name::default();
            link = db.find_by_secondary::<PermissionLink, PermissionLinkByActionNameIndex>(key)?;
        }

        if let Some(link) = &link {
            return Ok(Some(link.required_permission()));
        }

        Ok(None)
    }

    pub fn create_permission(
        db: &mut Database,
        account: Name,
        name: Name,
        parent: u64,
        auth: Authority,
    ) -> Result<Permission, ChainError> {
        let id = db.generate_id::<Permission>()?;
        let permission = Permission::new(id, parent, account, name, auth);
        db.insert(&permission)?;
        Ok(permission)
    }

    pub fn modify_permission(
        db: &mut Database,
        permission: &mut Permission,
        auth: &Authority,
    ) -> Result<(), ChainError> {
        db.modify(permission, |po| {
            po.authority = auth.clone();
            Ok(())
        })?;
        Ok(())
    }

    pub fn remove_permission(db: &mut Database, permission: &Permission) -> Result<(), ChainError> {
        let mut index = db.get_index::<Permission, PermissionByParentIndex>();
        let mut range = index.lower_bound(permission.id())?;
        let next = range.next()?;

        if let Some(_) = next {
            return Err(ChainError::ActionValidationError(format!(
                "cannot delete permission '{}' because it has child permissions",
                permission
            )));
        }

        db.remove(permission.clone())?;

        Ok(())
    }
}
