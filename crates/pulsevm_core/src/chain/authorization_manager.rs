use std::collections::HashSet;

use pulsevm_error::ChainError;
use pulsevm_ffi::{Authority, CxxChainConfig, CxxTimePoint, Database, PermissionObject};

use crate::{
    PULSE_NAME,
    chain::{
        name::Name,
        pulse_contract::{DeleteAuth, LinkAuth, UnlinkAuth, UpdateAuth},
        transaction::Action,
    },
    config::{DELETEAUTH_NAME, LINKAUTH_NAME, UNLINKAUTH_NAME, UPDATEAUTH_NAME},
    crypto::PublicKey,
    utils::pulse_assert,
};

use super::{ACTIVE_NAME, ANY_NAME, authority::PermissionLevel, authority_checker::AuthorityChecker};

pub struct AuthorizationManager;

impl AuthorizationManager {
    pub fn check_authorization(
        db: &mut Database,
        actions: &Vec<Action>,
        provided_keys: &HashSet<PublicKey>,
        provided_permissions: &HashSet<PermissionLevel>,
        satisfied_authorizations: &HashSet<PermissionLevel>,
    ) -> Result<(), ChainError> {
        let mut permissions_to_satisfy = HashSet::<PermissionLevel>::new();

        for act in actions.iter() {
            let mut special_case = false;

            if act.account().as_u64() == PULSE_NAME {
                special_case = true;

                match *act.name() {
                    UPDATEAUTH_NAME => Self::check_updateauth_authorization(db, act, act.authorization())?,
                    DELETEAUTH_NAME => Self::check_deleteauth_authorization(db, act)?,
                    LINKAUTH_NAME => Self::check_linkauth_authorization(db, act)?,
                    UNLINKAUTH_NAME => Self::check_unlinkauth_authorization(db, act)?,
                    _ => special_case = false,
                }
            }

            for declared_auth in act.authorization() {
                if !special_case {
                    let min_permission_name = Self::lookup_minimum_permission(db, &declared_auth.actor.into(), act.account(), act.name())?;

                    if let Some(min_permission_name) = min_permission_name {
                        // since special cases were already handled, it should only be false if the permission is pulse.any
                        let min_permission = Self::get_permission(db, declared_auth.actor, min_permission_name.as_u64())?;
                        pulse_assert(
                            Self::get_permission(db, declared_auth.actor, declared_auth.permission)?.satisfies(&min_permission, db)?,
                            ChainError::IrrelevantAuth(format!(
                                "action declares irrelevant authority '{}'; minimum authority is {}",
                                declared_auth,
                                PermissionLevel::new(min_permission.get_owner().to_uint64_t(), min_permission.get_name().to_uint64_t())
                            )),
                        )?;
                    }
                }

                if !satisfied_authorizations.contains(declared_auth) {
                    permissions_to_satisfy.insert(declared_auth.clone());
                }
            }

            let global_properties = unsafe { &*db.get_global_properties()? };
            let chain_config = global_properties.get_chain_config();
            let mut authority_checker = AuthorityChecker::new(chain_config.get_max_authority_depth(), provided_keys);

            // Now verify that all the declared authorizations are satisfied
            for p in permissions_to_satisfy.iter() {
                // TODO: Fix this
                /* pulse_assert(
                    authority_checker.satisfied(
                        db,
                        &Authority::new_from_permission_level(p.clone()),
                        0,
                    )?,
                    ChainError::AuthorizationError(format!(
                        "transaction declares authority '{}' but does not have signatures for it",
                        p
                    )),
                )?; */
            }

            return Ok(());

            // Now verify that all the provided keys are used, otherwise we are wasting resources
            if !authority_checker.all_keys_used() {
                return Err(ChainError::AuthorizationError("transaction bears irrelevant signatures".to_string()));
            }
        }
        Ok(())
    }

    fn check_updateauth_authorization(db: &mut Database, action: &Action, auths: &[PermissionLevel]) -> Result<(), ChainError> {
        let update = action
            .data_as::<UpdateAuth>()
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        pulse_assert(
            auths.len() == 1,
            ChainError::IrrelevantAuth("updateauth action should only have one declared authorization".into()),
        )?;
        let auth = &auths[0];
        pulse_assert(
            auth.actor == update.account,
            ChainError::IrrelevantAuth("the owner of the affected permission needs to be the actor of the declared authorization".into()),
        )?;

        // Determine the minimum required permission:
        // - If the permission already exists, use it.
        // - Otherwise, we're creating a new permission, so use the parent.
        let requested_perm = PermissionLevel::new(update.account.as_u64(), update.permission.as_u64());
        let min_permission = if let Some(existing) = Self::find_permission(db, &requested_perm)? {
            existing
        } else {
            Self::get_permission(db, update.account.as_u64(), update.parent.as_u64())?
        };

        pulse_assert(
            Self::get_permission(db, auth.actor, auth.permission)?.satisfies(&min_permission, db)?,
            ChainError::IrrelevantAuth(format!(
                "updateauth action declares irrelevant authority '{}'; minimum authority is {}",
                auth,
                PermissionLevel::new(update.account.as_u64(), min_permission.get_name().to_uint64_t())
            )),
        )?;

        Ok(())
    }

    fn check_deleteauth_authorization(db: &mut Database, action: &Action) -> Result<(), ChainError> {
        let del = action
            .data_as::<DeleteAuth>()
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        pulse_assert(
            action.authorization().len() == 1,
            ChainError::AuthorizationError("deleteauth action should only have one declared authorization".to_string()),
        )?;
        let auth = &action.authorization()[0];
        pulse_assert(
            auth.actor == del.account,
            ChainError::AuthorizationError("the owner of the permission to delete needs to be the actor of the declared authorization".to_string()),
        )?;
        let min_permission = Self::get_permission(db, del.account.as_u64(), del.permission.as_u64())?;
        pulse_assert(
            Self::get_permission(db, auth.actor, auth.permission)?.satisfies(&min_permission, db)?,
            ChainError::AuthorizationError(format!(
                "deleteauth action declares irrelevant authority '{}'; minimum authority is {}",
                auth,
                PermissionLevel::new(min_permission.get_owner().to_uint64_t(), min_permission.get_name().to_uint64_t())
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
            ChainError::AuthorizationError("link action should only have one declared authorization".to_string()),
        )?;
        let auth = &action.authorization()[0];
        pulse_assert(
            auth.actor == link.account,
            ChainError::AuthorizationError("the owner of the linked permission needs to be the actor of the declared authorization".to_string()),
        )?;
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
        let linked_permission_name = Self::lookup_minimum_permission(db, &link.account, &link.code, &link.message_type)?;

        match linked_permission_name {
            None => {
                return Ok(()); // if action is linked to pulse.any permission
            }
            Some(linked_permission_name) => {
                let min_permission = Self::get_permission(db, link.account.as_u64(), linked_permission_name.as_u64())?;
                pulse_assert(
                    Self::get_permission(db, auth.actor, auth.permission)?.satisfies(&min_permission, db)?,
                    ChainError::AuthorizationError(format!(
                        "link action declares irrelevant authority '{}'; minimum authority is {}",
                        auth,
                        PermissionLevel::new(link.account.as_u64(), linked_permission_name.as_u64())
                    )),
                )?;
            }
        }

        Ok(())
    }

    fn check_unlinkauth_authorization(db: &mut Database, action: &Action) -> Result<(), ChainError> {
        let unlink = action
            .data_as::<UnlinkAuth>()
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        pulse_assert(
            action.authorization().len() == 1,
            ChainError::AuthorizationError("unlink action should only have one declared authorization".to_string()),
        )?;
        let auth = &action.authorization()[0];
        pulse_assert(
            auth.actor == unlink.account,
            ChainError::AuthorizationError("the owner of the linked permission needs to be the actor of the declared authorization".to_string()),
        )?;
        let unlinked_permission_name = Self::lookup_minimum_permission(db, &unlink.account, &unlink.code, &unlink.message_type)?;
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
                let min_permission = Self::get_permission(db, unlink.account.as_u64(), unlinked_permission_name.as_u64())?;
                pulse_assert(
                    Self::get_permission(db, auth.actor, auth.permission)?.satisfies(&min_permission, db)?,
                    ChainError::AuthorizationError(format!(
                        "unlink action declares irrelevant authority '{}'; minimum authority is {}",
                        auth,
                        PermissionLevel::new(unlink.account.as_u64(), unlinked_permission_name.as_u64())
                    )),
                )?;
            }
        }
        Ok(())
    }

    pub fn find_permission<'a>(db: &Database, level: &PermissionLevel) -> Result<Option<&'a PermissionObject>, ChainError> {
        pulse_assert(
            level.actor != 0 && level.permission != 0,
            ChainError::AuthorizationError("invalid permission".to_string()),
        )?;
        let result = db.find_permission_by_actor_and_permission(level.actor, level.permission)?;

        if result.is_null() {
            Ok(None)
        } else {
            let perm = unsafe { &*result };
            Ok(Some(perm))
        }
    }

    pub fn get_permission<'a>(db: &mut Database, actor: u64, permission: u64) -> Result<&'a PermissionObject, ChainError> {
        pulse_assert(
            actor != 0 && permission != 0,
            ChainError::AuthorizationError("invalid permission".to_string()),
        )?;
        let result = db.get_permission_by_actor_and_permission(actor, permission)?;

        Ok(unsafe { &*result })
    }

    fn lookup_minimum_permission(db: &mut Database, authorizer_account: &Name, scope: &Name, act_name: &Name) -> Result<Option<Name>, ChainError> {
        // Special case native actions cannot be linked to a minimum permission, so there is no need to check.
        if scope.as_u64() == PULSE_NAME {
            pulse_assert(
                act_name.as_u64() != UPDATEAUTH_NAME
                    && act_name.as_u64() != DELETEAUTH_NAME
                    && act_name.as_u64() != LINKAUTH_NAME
                    && act_name.as_u64() != UNLINKAUTH_NAME,
                ChainError::AuthorizationError(
                    "cannot call lookup_minimum_permission on native actions that are not allowed to be linked to minimum permissions".to_string(),
                ),
            )?;
        }

        let linked_permission = Self::lookup_linked_permission(db, authorizer_account, scope, act_name)?;

        if let Some(linked_permission) = linked_permission {
            if linked_permission == ANY_NAME {
                return Ok(None);
            }

            return Ok(Some(linked_permission));
        } else {
            return Ok(Some(ACTIVE_NAME.into())); // default to active permission
        }
    }

    fn lookup_linked_permission(db: &mut Database, authorizer_account: &Name, scope: &Name, act_name: &Name) -> Result<Option<Name>, ChainError> {
        let res = db.lookup_linked_permission(authorizer_account.as_u64(), scope.as_u64(), act_name.as_u64())?;

        match res {
            Some(name_ptr) => Ok(Some(Name::new(name_ptr))),
            None => Ok(None),
        }
    }

    pub fn create_permission(
        db: &mut Database,
        account: &Name,
        name: &Name,
        parent: u64,
        auth: &Authority,
        pending_block_time: &CxxTimePoint,
    ) -> Result<*const PermissionObject, ChainError> {
        db.create_permission(account.as_u64(), name.as_u64(), parent, auth, pending_block_time)
    }

    pub fn modify_permission(
        db: &mut Database,
        permission: &PermissionObject,
        auth: &Authority,
        pending_block_time: &CxxTimePoint,
    ) -> Result<(), ChainError> {
        db.modify_permission(permission, auth, pending_block_time)
    }

    pub fn remove_permission(db: &mut Database, permission: &PermissionObject) -> Result<(), ChainError> {
        db.remove_permission(permission)
    }
}
