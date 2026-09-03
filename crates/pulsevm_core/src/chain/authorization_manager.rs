use std::collections::{
    BTreeMap,
    BTreeSet,
};

use pulsevm_crypto::AuthorityPublicKey;
use pulsevm_database::{
    Authority,
    Database,
    DbRead,
    Microseconds,
    PermissionInfo,
    SystemAccountNames,
    TimePoint,
    seconds,
};
use pulsevm_error::ChainError;
use pulsevm_serialization::Read;

use crate::{
    chain::{
        name::Name,
        pulse_contract::{
            CancelDelay,
            DeleteAuth,
            LinkAuth,
            UnlinkAuth,
            UpdateAuth,
        },
        transaction::Action,
    },
    config::{
        CANCELDELAY_NAME,
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
    authority::PermissionLevel,
    authority_checker::AuthorityChecker,
};

const WEBAUTHN_KEY_FEATURE_DIGEST: [u8; 32] = [
    0x4f, 0xca, 0x8b, 0xd8, 0x2b, 0xd1, 0x81, 0xe7, 0x14, 0xe2, 0x83, 0xf8, 0x3e, 0x1b, 0x45, 0xd9,
    0x5c, 0xa5, 0xaf, 0x40, 0xfb, 0x89, 0xad, 0x39, 0x77, 0xb6, 0x53, 0xc4, 0x48, 0xf7, 0x8c, 0x2,
];
const FIX_LINKAUTH_RESTRICTION_FEATURE_DIGEST: [u8; 32] = [
    0xe0, 0xfb, 0x64, 0xb1, 0x08, 0x5c, 0xc5, 0x53, 0x89, 0x7, 0x01, 0x58, 0xd0, 0x5a, 0x00, 0x9c,
    0x4e, 0x27, 0x6f, 0xb9, 0x4e, 0x1a, 0x0b, 0xf6, 0xa5, 0x28, 0xb4, 0x8f, 0xbc, 0x4f, 0xf5, 0x26,
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
        let system = db.system_accounts();
        let mut permissions_to_satisfy = BTreeMap::<PermissionLevel, Microseconds>::new();
        let mut authority_checker = AuthorityChecker::new(
            max_authority_depth,
            provided_keys,
            provided_permissions,
            effective_provided_delay,
        );

        for act in actions.iter() {
            let mut special_case = false;
            let mut delay = effective_provided_delay;

            if *act.account() == system.system {
                special_case = true;

                match *act.name() {
                    UPDATEAUTH_NAME => {
                        Self::check_updateauth_authorization(&r, act, act.authorization())?
                    }
                    DELETEAUTH_NAME => Self::check_deleteauth_authorization(&r, act)?,
                    LINKAUTH_NAME => Self::check_linkauth_authorization(db, &r, act, system)?,
                    UNLINKAUTH_NAME => Self::check_unlinkauth_authorization(&r, act, system)?,
                    CANCELDELAY_NAME => {
                        delay = delay.max(Self::check_canceldelay_authorization(db, &r, act)?)
                    }
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
                        system,
                    )?;

                    if let Some(min_permission_name) = min_permission_name {
                        // since special cases were already handled, it should only be false if the
                        // permission is <system>.any
                        let min_permission = Self::get_permission(
                            &r,
                            declared_auth.actor,
                            min_permission_name.as_u64(),
                        )?;
                        // A scheduler/inline receiver may provide its implicit
                        // `receiver@eosio.code` permission. That permission is
                        // virtual and therefore has no chainbase authority row;
                        // the provided permission itself is the authorization.
                        if !(declared_auth.permission == system.code.as_u64()
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
                                    PermissionLevel::new(
                                        min_permission.owner(),
                                        min_permission.name()
                                    )
                                )),
                            )?;
                        }
                    }
                }

                if !satisfied_authorizations.contains(declared_auth) {
                    permissions_to_satisfy
                        .entry(declared_auth.clone())
                        .and_modify(|existing| *existing = (*existing).min(delay))
                        .or_insert(delay);
                }
            }
        }

        // Now verify that all the declared authorizations are satisfied
        for (permission, delay) in permissions_to_satisfy {
            let auth = Authority::new_from_permission_level(&permission);

            pulse_assert(
                authority_checker.satisfied_with_delay(&r, &auth, 0, delay)?,
                ChainError::AuthorizationError(format!(
                    "transaction declares authority '{}' but does not have signatures for it",
                    permission
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
        system: SystemAccountNames,
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
        // Leap checks ONLY_LINK_TO_EXISTING_PERMISSION while executing the
        // native linkauth action, not during this transaction-wide authority
        // pass. An updateauth earlier in the same transaction may create the
        // requirement that linkauth consumes.
        if link.code == system.system
            || !database.protocol_feature_activated(FIX_LINKAUTH_RESTRICTION_FEATURE_DIGEST)
        {
            match link.message_type {
                UPDATEAUTH_NAME => {
                    return Err(ChainError::AuthorizationError(format!(
                        "cannot link {}::updateauth to a minimum permission",
                        system.system
                    )));
                }
                DELETEAUTH_NAME => {
                    return Err(ChainError::AuthorizationError(format!(
                        "cannot link {}::deleteauth to a minimum permission",
                        system.system
                    )));
                }
                LINKAUTH_NAME => {
                    return Err(ChainError::AuthorizationError(format!(
                        "cannot link {}::linkauth to a minimum permission",
                        system.system
                    )));
                }
                UNLINKAUTH_NAME => {
                    return Err(ChainError::AuthorizationError(format!(
                        "cannot link {}::unlinkauth to a minimum permission",
                        system.system
                    )));
                }
                CANCELDELAY_NAME => {
                    return Err(ChainError::AuthorizationError(format!(
                        "cannot link {}::canceldelay to a minimum permission",
                        system.system
                    )));
                }
                _ => {}
            }
        }
        let linked_permission_name = Self::lookup_minimum_permission(
            db,
            &link.account,
            &link.code,
            &link.message_type,
            system,
        )?;

        match linked_permission_name {
            None => {
                return Ok(()); // if action is linked to <system>.any permission
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

    fn check_unlinkauth_authorization(
        db: &DbRead<'_>,
        action: &Action,
        system: SystemAccountNames,
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
            system,
        )?;
        match unlinked_permission_name {
            None => {
                return Err(ChainError::AuthorizationError(format!(
                    "cannot unlink non-existent permission link of account '{}' for actions matching '{}::{}'",
                    unlink.account, unlink.code, unlink.message_type
                )));
            }
            Some(name) if name == system.any => {
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

    fn check_canceldelay_authorization(
        db: &Database,
        read: &DbRead<'_>,
        action: &Action,
    ) -> Result<Microseconds, ChainError> {
        let cancel = action
            .data_as::<CancelDelay>()
            .map_err(|error| ChainError::AuthorizationError(error.to_string()))?;
        pulse_assert(
            action.authorization().len() == 1,
            ChainError::AuthorizationError(
                "canceldelay action should only have one declared authorization".to_string(),
            ),
        )?;
        let declared = &action.authorization()[0];
        let declared_permission = Self::get_permission(read, declared.actor, declared.permission)?;
        let canceling_permission = Self::get_permission(
            read,
            cancel.canceling_auth.actor,
            cancel.canceling_auth.permission,
        )?;
        pulse_assert(
            declared_permission.satisfies(&canceling_permission, read)?,
            ChainError::AuthorizationError(format!(
                "canceldelay action declares irrelevant authority '{declared}'; specified authority to satisfy is {}",
                cancel.canceling_auth
            )),
        )?;

        let deferred = db
            .arena_deferred_transaction(cancel.trx_id.0)
            .filter(|transaction| transaction.sender == 0)
            .ok_or_else(|| {
                ChainError::TransactionError(format!(
                    "cannot cancel transaction {}, no matching user deferred transaction exists",
                    cancel.trx_id
                ))
            })?;
        let transaction = Transaction::read(&deferred.packed_trx, &mut 0).map_err(|error| {
            ChainError::TransactionError(format!(
                "decode deferred transaction {}: {error}",
                cancel.trx_id
            ))
        })?;
        let contains_canceling_auth = transaction.actions.iter().any(|deferred_action| {
            deferred_action
                .authorization()
                .contains(&cancel.canceling_auth)
        });
        pulse_assert(
            contains_canceling_auth,
            ChainError::AuthorizationError(format!(
                "canceling authority {} was not present in deferred transaction {}",
                cancel.canceling_auth, cancel.trx_id
            )),
        )?;
        let delay = deferred
            .delay_until
            .checked_sub(deferred.published)
            .ok_or_else(|| {
                ChainError::TransactionError(format!(
                    "deferred transaction {} has an invalid delay interval",
                    cancel.trx_id
                ))
            })?;
        Ok(Microseconds::new(delay))
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
        system: SystemAccountNames,
    ) -> Result<Option<Name>, ChainError> {
        // Special case native actions cannot be linked to a minimum permission, so there is no need
        // to check.
        if *scope == system.system {
            pulse_assert(
                act_name.as_u64() != UPDATEAUTH_NAME
                    && act_name.as_u64() != DELETEAUTH_NAME
                    && act_name.as_u64() != LINKAUTH_NAME
                    && act_name.as_u64() != UNLINKAUTH_NAME
                    && act_name.as_u64() != CANCELDELAY_NAME,
                ChainError::AuthorizationError(
                    "cannot call lookup_minimum_permission on native actions that are not allowed to be linked to minimum permissions".to_string(),
                ),
            )?;
        }

        let linked_permission =
            Self::lookup_linked_permission(db, authorizer_account, scope, act_name)?;

        if let Some(linked_permission) = linked_permission {
            if linked_permission == system.any {
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
    use std::str::FromStr;

    use super::*;
    use pulsevm_serialization::Write;
    use tempfile::TempDir;

    const PREACTIVATE_FEATURE_DIGEST: [u8; 32] = [
        0x0e, 0xc7, 0xe0, 0x80, 0x17, 0x7b, 0x2c, 0x02, 0xb2, 0x78, 0xd5, 0x08, 0x86, 0x11, 0x68,
        0x6b, 0x49, 0xd7, 0x39, 0x92, 0x5a, 0x92, 0xd9, 0xbf, 0xca, 0xcd, 0x7f, 0xc6, 0xb7, 0x40,
        0x53, 0xbd,
    ];
    const ONLY_LINK_TO_EXISTING_PERMISSION_FEATURE_DIGEST: [u8; 32] = [
        0x1a, 0x99, 0xa5, 0x9d, 0x87, 0xe0, 0x6e, 0x09, 0xec, 0x5b, 0x02, 0x8a, 0x9c, 0xbb, 0x77,
        0x49, 0xb4, 0xa5, 0xad, 0x88, 0x19, 0x00, 0x43, 0x65, 0xd0, 0x2d, 0xc4, 0x37, 0x9a, 0x8b,
        0x72, 0x41,
    ];

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

    #[test]
    fn linkauth_precheck_allows_requirement_created_earlier_in_transaction() {
        let dir = TempDir::new().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), 256 * 1024 * 1024).unwrap();
        let genesis =
            pulsevm_database::GenesisState::from_bytes(include_bytes!("../../../../genesis.json"))
                .unwrap();
        let eosio = Name::from_str("eosio").unwrap();
        db.initialize_database_with_system_account(&genesis, eosio)
            .unwrap();
        db.activate_protocol_features(&[PREACTIVATE_FEATURE_DIGEST], 2)
            .unwrap();
        db.preactivate_protocol_feature(ONLY_LINK_TO_EXISTING_PERMISSION_FEATURE_DIGEST)
            .unwrap();
        db.activate_protocol_features(&[ONLY_LINK_TO_EXISTING_PERMISSION_FEATURE_DIGEST], 3)
            .unwrap();

        let active = PermissionLevel::new(eosio.as_u64(), ACTIVE_NAME.as_u64());
        let committee = Name::from_str("committee").unwrap();
        let committee_authority = db
            .read()
            .unwrap()
            .permission_authority(eosio.as_u64(), ACTIVE_NAME.as_u64())
            .unwrap()
            .unwrap();
        let updateauth = Action::new(
            eosio,
            UPDATEAUTH_NAME.into(),
            UpdateAuth {
                account: eosio,
                permission: committee,
                parent: ACTIVE_NAME.into(),
                auth: committee_authority,
            }
            .pack()
            .unwrap(),
            vec![active.clone()],
        );
        let linkauth = Action::new(
            eosio,
            LINKAUTH_NAME.into(),
            LinkAuth {
                account: eosio,
                code: Name::from_str("admin.proton").unwrap(),
                message_type: Name::from_str("kickbp").unwrap(),
                requirement: committee,
            }
            .pack()
            .unwrap(),
            vec![active.clone()],
        );
        assert!(
            db.read()
                .unwrap()
                .find_permission_info(eosio.as_u64(), committee.as_u64())
                .unwrap()
                .is_none()
        );

        AuthorizationManager::check_authorization(
            &db,
            &vec![updateauth, linkauth],
            &BTreeSet::new(),
            &BTreeSet::from([active]),
            Microseconds::new(0),
            &BTreeSet::new(),
        )
        .unwrap();
    }
}
