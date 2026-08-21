use std::collections::BTreeSet;

use pulsevm_database::{
    Authority,
    Database,
    DbRead,
    Microseconds,
    PermissionInfo,
    TimePoint,
    seconds,
};
use pulsevm_error::ChainError;
use pulsevm_crypto::AuthorityPublicKey;

use crate::{
    PULSE_NAME,
    chain::{
        name::Name,
        pulse_contract::{
            DeleteAuth,
            LinkAuth,
            UnlinkAuth,
            UpdateAuth,
        },
        transaction::Action,
    },
    config::{
        DELETEAUTH_NAME,
        LINKAUTH_NAME,
        UNLINKAUTH_NAME,
        UPDATEAUTH_NAME,
    },
    transaction::Transaction,
    utils::pulse_assert,
};

use super::{
    ACTIVE_NAME,
    ANY_NAME,
    authority::PermissionLevel,
    authority_checker::AuthorityChecker,
};

const WEBAUTHN_KEY_FEATURE_DIGEST: [u8; 32] = [
    0x92, 0x7f, 0xdf, 0x78, 0xc5, 0x1e, 0x77, 0xa8, 0x99, 0xf2, 0xdb, 0x93, 0x82, 0x49,
    0xfb, 0x1f, 0x8b, 0xb3, 0x8f, 0x4e, 0x43, 0xd9, 0xc1, 0xf7, 0x5b, 0x19, 0x04, 0x92,
    0x08, 0x0c, 0xbc, 0x34,
];
const FIX_LINKAUTH_RESTRICTION_FEATURE_DIGEST: [u8; 32] = [
    0xa9, 0x82, 0x41, 0xc8, 0x35, 0x11, 0xdc, 0x86, 0xc8, 0x57, 0x22, 0x1b, 0x93, 0x72,
    0xb4, 0xaa, 0x7c, 0xea, 0x3a, 0xae, 0xbc, 0x56, 0x7a, 0x48, 0x04, 0xe1, 0xd3, 0xdb,
    0x35, 0x57, 0x05, 0x0,
];
const ONLY_LINK_TO_EXISTING_PERMISSION_FEATURE_DIGEST: [u8; 32] = [
    0xf3, 0xc3, 0xd9, 0x1c, 0x46, 0x03, 0xcd, 0xe2, 0x39, 0x72, 0x68, 0xbf, 0xed, 0x4e, 0x66,
    0x24, 0x65, 0x29, 0x3a, 0xab, 0x10, 0xcd, 0x94, 0x16, 0xdb, 0x0d, 0x44, 0x2b, 0x8c, 0xec,
    0x29, 0x49,
];

fn validate_protocol_key_features(
    db: &Database,
    provided_keys: &BTreeSet<AuthorityPublicKey>,
) -> Result<(), ChainError> {
    if provided_keys
        .iter()
        .any(|key| matches!(key, AuthorityPublicKey::WebAuthn { .. }))
        && !db.protocol_feature_activated(WEBAUTHN_KEY_FEATURE_DIGEST)
    {
        return Err(ChainError::AuthorizationError(
            "WebAuthn authority keys require the active WEBAUTHN_KEY protocol feature".into(),
        ));
    }
    Ok(())
}

pub struct AuthorizationManager;

impl AuthorizationManager {
    pub fn check_authorization(
        db: &Database,
        actions: &Vec<Action>,
        provided_keys: &BTreeSet<AuthorityPublicKey>,
        provided_permissions: &BTreeSet<PermissionLevel>,
        provided_delay: Microseconds,
        satisfied_authorizations: &BTreeSet<PermissionLevel>,
    ) -> Result<(), ChainError> {
        validate_protocol_key_features(db, provided_keys)?;
        // Config is served as an owned value, so no database object is held
        // across the pass.
        let chain_config = db.chain_config()?;
        // Use one consistent read view for the whole authorization pass.
        let r = db.read()?;
        let delay_max_limit = seconds(chain_config.max_transaction_delay as i64);
        let effective_provided_delay = if provided_delay >= delay_max_limit {
            Microseconds::maximum()
        } else {
            provided_delay
        };
        let max_authority_depth = chain_config.max_authority_depth;
        let mut permissions_to_satisfy = BTreeSet::<PermissionLevel>::new();
        let mut authority_checker = AuthorityChecker::new(
            max_authority_depth,
            provided_keys,
            provided_permissions,
            effective_provided_delay,
        );

        for act in actions.iter() {
            let mut special_case = false;

            if act.account().as_u64() == PULSE_NAME {
                special_case = true;

                match *act.name() {
                    UPDATEAUTH_NAME => {
                        Self::check_updateauth_authorization(&r, act, act.authorization())?
                    }
                    DELETEAUTH_NAME => Self::check_deleteauth_authorization(&r, act)?,
                    LINKAUTH_NAME => Self::check_linkauth_authorization(db, &r, act)?,
                    UNLINKAUTH_NAME => Self::check_unlinkauth_authorization(&r, act)?,
                    _ => special_case = false,
                }
            }

            for declared_auth in act.authorization() {
                if !special_case {
                    let min_permission_name = Self::lookup_minimum_permission(
                        &r,
                        &declared_auth.actor.into(),
                        act.account(),
                        act.name(),
                    )?;

                    if let Some(min_permission_name) = min_permission_name {
                        // since special cases were already handled, it should only be false if the
                        // permission is pulse.any
                        let min_permission = Self::get_permission(
                            &r,
                            declared_auth.actor,
                            min_permission_name.as_u64(),
                        )?;
                        // A scheduler/inline receiver may provide its implicit
                        // `receiver@eosio.code` permission. That permission is
                        // virtual and therefore has no chainbase authority row;
                        // the provided permission itself is the authorization.
                        if !(declared_auth.permission == crate::CODE_NAME.as_u64()
                            && provided_permissions.contains(declared_auth))
                        {
                            pulse_assert(
                                Self::get_permission(
                                    &r,
                                    declared_auth.actor,
                                    declared_auth.permission,
                                )?
                                .satisfies(&min_permission, &r)?,
                                ChainError::IrrelevantAuth(format!(
                                    "action declares irrelevant authority '{}'; minimum authority is {}",
                                    declared_auth,
                                    PermissionLevel::new(min_permission.owner(), min_permission.name())
                                )),
                            )?;
                        }
                    }
                }

                if !satisfied_authorizations.contains(declared_auth) {
                    permissions_to_satisfy.insert(declared_auth.clone());
                }
            }
        }

        // Now verify that all the declared authorizations are satisfied
        for p in permissions_to_satisfy.iter() {
            let auth = Authority::new_from_permission_level(p);

            pulse_assert(
                authority_checker.satisfied(&r, &auth, 0)?,
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

        Ok(())
    }

    pub fn check_permission_authorization(
        db: &Database,
        permission: PermissionLevel,
        provided_keys: &BTreeSet<AuthorityPublicKey>,
        provided_permissions: &BTreeSet<PermissionLevel>,
        provided_delay: Microseconds,
        allow_unused_keys: bool,
    ) -> Result<(), ChainError> {
        validate_protocol_key_features(db, provided_keys)?;
        let auth = Authority::new_from_permission_level(&permission);
        let chain_config = db.chain_config()?;
        let r = db.read()?;
        let delay_max_limit = seconds(chain_config.max_transaction_delay as i64);
        let mut authority_checker = AuthorityChecker::new(
            chain_config.max_authority_depth,
            provided_keys,
            provided_permissions,
            if provided_delay >= delay_max_limit {
                Microseconds::maximum()
            } else {
                provided_delay
            },
        );

        pulse_assert(
            authority_checker.satisfied(&r, &auth, 0)?,
            ChainError::AuthorizationError(format!(
                "permission '{}' is not satisfied by the provided keys and permissions",
                permission
            )),
        )?;

        if !allow_unused_keys && !authority_checker.all_keys_used() {
            return Err(ChainError::AuthorizationError(
                "irrelevant keys provided".to_string(),
            ));
        }

        Ok(())
    }

    pub fn get_required_keys(
        db: &mut Database,
        trx: &Transaction,
        candidate_keys: &BTreeSet<AuthorityPublicKey>,
        provided_delay: Microseconds,
    ) -> Result<BTreeSet<AuthorityPublicKey>, ChainError> {
        validate_protocol_key_features(db, candidate_keys)?;
        let chain_config = db.chain_config()?;
        let r = db.read()?;
        let provided_permissions = BTreeSet::<PermissionLevel>::new();
        let mut authority_checker = AuthorityChecker::new(
            chain_config.max_authority_depth,
            candidate_keys,
            &provided_permissions,
            provided_delay,
        );

        for act in trx.actions.iter() {
            for declared_auth in act.authorization() {
                let auth = Authority::new_from_permission_level(declared_auth);

                pulse_assert(
                    authority_checker.satisfied(&r, &auth, 0)?,
                    ChainError::AuthorizationError(format!(
                        "transaction declares authority '{}' but does not have signatures for it",
                        declared_auth
                    )),
                )?;
            }
        }

        Ok(authority_checker.used_keys().clone())
    }

    fn check_updateauth_authorization(
        db: &DbRead<'_>,
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
        pulse_assert(
            auth.actor == update.account,
            ChainError::IrrelevantAuth("the owner of the affected permission needs to be the actor of the declared authorization".into()),
        )?;

        // Determine the minimum required permission:
        // - If the permission already exists, use it.
        // - Otherwise, we're creating a new permission, so use the parent.
        let requested_perm =
            PermissionLevel::new(update.account.as_u64(), update.permission.as_u64());
        let min_permission = if let Some(existing) = Self::find_permission(db, &requested_perm)? {
            existing
        } else {
            Self::get_permission(db, update.account.as_u64(), update.parent.as_u64())?
        };

        pulse_assert(
            Self::get_permission(db, auth.actor, auth.permission)?
                .satisfies(&min_permission, db)?,
            ChainError::IrrelevantAuth(format!(
                "updateauth action declares irrelevant authority '{}'; minimum authority is {}",
                auth,
                PermissionLevel::new(update.account.as_u64(), min_permission.name())
            )),
        )?;

        Ok(())
    }

    fn check_deleteauth_authorization(db: &DbRead<'_>, action: &Action) -> Result<(), ChainError> {
        let del = action
            .data_as::<DeleteAuth>()
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        pulse_assert(
            action.authorization().len() == 1,
            ChainError::AuthorizationError(
                "deleteauth action should only have one declared authorization".to_string(),
            ),
        )?;
        let auth = &action.authorization()[0];
        pulse_assert(
            auth.actor == del.account,
            ChainError::AuthorizationError("the owner of the permission to delete needs to be the actor of the declared authorization".to_string()),
        )?;
        let min_permission =
            Self::get_permission(db, del.account.as_u64(), del.permission.as_u64())?;
        pulse_assert(
            Self::get_permission(db, auth.actor, auth.permission)?
                .satisfies(&min_permission, db)?,
            ChainError::AuthorizationError(format!(
                "deleteauth action declares irrelevant authority '{}'; minimum authority is {}",
                auth,
                PermissionLevel::new(min_permission.owner(), min_permission.name())
            )),
        )?;
        Ok(())
    }

    fn check_linkauth_authorization(
        database: &Database,
        db: &DbRead<'_>,
        action: &Action,
    ) -> Result<(), ChainError> {
        let link = action
            .data_as::<LinkAuth>()
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        pulse_assert(
            action.authorization().len() == 1,
            ChainError::AuthorizationError(
                "link action should only have one declared authorization".to_string(),
            ),
        )?;
        let auth = &action.authorization()[0];
        pulse_assert(
            auth.actor == link.account,
            ChainError::AuthorizationError("the owner of the linked permission needs to be the actor of the declared authorization".to_string()),
        )?;
        if database.protocol_feature_activated(ONLY_LINK_TO_EXISTING_PERMISSION_FEATURE_DIGEST)
            && link.requirement != ANY_NAME
            && db
                .find_permission_info(link.account.as_u64(), link.requirement.as_u64())?
                .is_none()
        {
            return Err(ChainError::AuthorizationError(format!(
                "permission {} does not exist for account {}",
                link.requirement, link.account
            )));
        }
        if link.code == PULSE_NAME
            || !database.protocol_feature_activated(FIX_LINKAUTH_RESTRICTION_FEATURE_DIGEST)
        {
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
            Self::lookup_minimum_permission(db, &link.account, &link.code, &link.message_type)?;

        match linked_permission_name {
            None => {
                return Ok(()); // if action is linked to pulse.any permission
            }
            Some(linked_permission_name) => {
                let min_permission = Self::get_permission(
                    db,
                    link.account.as_u64(),
                    linked_permission_name.as_u64(),
                )?;
                pulse_assert(
                    Self::get_permission(db, auth.actor, auth.permission)?
                        .satisfies(&min_permission, db)?,
                    ChainError::AuthorizationError(format!(
                        "link action declares irrelevant authority '{}'; minimum authority is {}",
                        auth,
                        PermissionLevel::new(
                            link.account.as_u64(),
                            linked_permission_name.as_u64()
                        )
                    )),
                )?;
            }
        }

        Ok(())
    }

    fn check_unlinkauth_authorization(db: &DbRead<'_>, action: &Action) -> Result<(), ChainError> {
        let unlink = action
            .data_as::<UnlinkAuth>()
            .map_err(|e| ChainError::AuthorizationError(format!("{}", e)))?;
        pulse_assert(
            action.authorization().len() == 1,
            ChainError::AuthorizationError(
                "unlink action should only have one declared authorization".to_string(),
            ),
        )?;
        let auth = &action.authorization()[0];
        pulse_assert(
            auth.actor == unlink.account,
            ChainError::AuthorizationError("the owner of the linked permission needs to be the actor of the declared authorization".to_string()),
        )?;
        let unlinked_permission_name = Self::lookup_minimum_permission(
            db,
            &unlink.account,
            &unlink.code,
            &unlink.message_type,
        )?;
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
                    unlink.account.as_u64(),
                    unlinked_permission_name.as_u64(),
                )?;
                pulse_assert(
                    Self::get_permission(db, auth.actor, auth.permission)?
                        .satisfies(&min_permission, db)?,
                    ChainError::AuthorizationError(format!(
                        "unlink action declares irrelevant authority '{}'; minimum authority is {}",
                        auth,
                        PermissionLevel::new(
                            unlink.account.as_u64(),
                            unlinked_permission_name.as_u64()
                        )
                    )),
                )?;
            }
        }
        Ok(())
    }

    pub fn find_permission(
        db: &DbRead<'_>,
        level: &PermissionLevel,
    ) -> Result<Option<PermissionInfo>, ChainError> {
        pulse_assert(
            level.actor != 0 && level.permission != 0,
            ChainError::AuthorizationError("invalid permission".to_string()),
        )?;
        db.find_permission_info(level.actor, level.permission)
    }

    pub fn get_permission(
        db: &DbRead<'_>,
        actor: u64,
        permission: u64,
    ) -> Result<PermissionInfo, ChainError> {
        pulse_assert(
            actor != 0 && permission != 0,
            ChainError::AuthorizationError("invalid permission".to_string()),
        )?;
        db.find_permission_info(actor, permission)?.ok_or_else(|| {
            ChainError::AuthorizationError(format!(
                "permission {}/{} does not exist",
                Name::new(actor),
                Name::new(permission)
            ))
        })
    }

    fn lookup_minimum_permission(
        db: &DbRead<'_>,
        authorizer_account: &Name,
        scope: &Name,
        act_name: &Name,
    ) -> Result<Option<Name>, ChainError> {
        // Special case native actions cannot be linked to a minimum permission, so there is no need
        // to check.
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

        let linked_permission =
            Self::lookup_linked_permission(db, authorizer_account, scope, act_name)?;

        if let Some(linked_permission) = linked_permission {
            if linked_permission == ANY_NAME {
                return Ok(None);
            }

            return Ok(Some(linked_permission));
        } else {
            return Ok(Some(ACTIVE_NAME.into())); // default to active permission
        }
    }

    fn lookup_linked_permission(
        db: &DbRead<'_>,
        authorizer_account: &Name,
        scope: &Name,
        act_name: &Name,
    ) -> Result<Option<Name>, ChainError> {
        let mut res = db.lookup_linked_permission(
            authorizer_account.as_u64(),
            scope.as_u64(),
            act_name.as_u64(),
        )?;

        // A link registered for every action of `scope` uses the empty message
        // type (message_type 0); linkauth with an empty type records it. When no
        // link matches the specific action, fall back to that catch-all link, as
        // EOSIO's lookup_linked_permission does — otherwise a "link to any action"
        // never takes effect.
        if res.is_none() {
            res = db.lookup_linked_permission(authorizer_account.as_u64(), scope.as_u64(), 0)?;
        }

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
        pending_block_time: &TimePoint,
    ) -> Result<(), ChainError> {
        db.create_permission(
            account.as_u64(),
            name.as_u64(),
            parent,
            auth,
            pending_block_time,
        )
    }

    pub fn modify_permission(
        db: &mut Database,
        actor: u64,
        permission: u64,
        auth: &Authority,
        pending_block_time: &TimePoint,
    ) -> Result<(), ChainError> {
        db.modify_permission(actor, permission, auth, pending_block_time)
    }

    pub fn update_permission_usage(
        db: &mut Database,
        actor: u64,
        permission: u64,
        pending_block_time: &TimePoint,
    ) -> Result<(), ChainError> {
        db.update_permission_usage(actor, permission, pending_block_time)
            .map_err(|e| {
                ChainError::DatabaseError(format!("failed to update permission usage: {}", e))
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn rejects_webauthn_keys_before_feature_activation() {
        let dir = TempDir::new().unwrap();
        let db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();
        let mut keys = BTreeSet::new();
        keys.insert(AuthorityPublicKey::WebAuthn {
            point: [2; 33],
            user_presence: 1,
            rpid: "example.com".into(),
        });

        let error = validate_protocol_key_features(&db, &keys).unwrap_err();
        assert!(error.to_string().contains("WEBAUTHN_KEY"));
    }
}
