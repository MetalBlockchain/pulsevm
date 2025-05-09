use std::{
    collections::HashSet,
    fmt::{self},
    sync::Arc,
};

use pulsevm_chainbase::{Database, UndoSession};
use pulsevm_proc_macros::name;
use pulsevm_serialization::Serialize;
use tokio::sync::Mutex;

use super::{
    ACTIVE_NAME, ANY_NAME, Action, DeleteAuth, Id, LinkAuth, Name, PublicKey, Transaction,
    UnlinkAuth, UpdateAuth,
    authority::{
        self, Authority, Permission, PermissionByOwnerIndex, PermissionLevel, PermissionLink,
        PermissionLinkByActionNameIndex,
    },
    authority_checker::AuthorityChecker,
};

#[derive(Debug, Clone)]
pub enum AuthorityError {
    PermissionNotFound(Name, Name),
    RecursionDepthExceeded,
    InternalError,
    NotSatisfied,
    SignatureRecoverError(String),
    DataError(String),
    InvalidPermission,
    IrrelevantAuth(String),
    AuthorizationError(String),
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorityError::PermissionNotFound(actor, permission) => write!(
                f,
                "Permission not found for actor: {}, permission: {}",
                actor, permission
            ),
            AuthorityError::RecursionDepthExceeded => write!(f, "Recursion depth exceeded"),
            AuthorityError::InternalError => write!(f, "Internal error"),
            AuthorityError::NotSatisfied => write!(f, "Authority not satisfied"),
            AuthorityError::SignatureRecoverError(msg) => {
                write!(f, "Signature recover error: {}", msg)
            }
            AuthorityError::DataError(msg) => write!(f, "Data error: {}", msg),
            AuthorityError::InvalidPermission => write!(f, "Invalid permission"),
            AuthorityError::IrrelevantAuth(msg) => write!(f, "Irrelevant auth: {}", msg),
            AuthorityError::AuthorizationError(msg) => {
                write!(f, "{}", msg)
            }
        }
    }
}

pub struct AuthorizationManager;

impl AuthorizationManager {
    pub fn new() -> Self {
        Self {}
    }

    pub fn check_authorization(
        &self,
        session: &UndoSession,
        actions: &Vec<Action>,
        provided_keys: &HashSet<PublicKey>,
        provided_permissions: &HashSet<PermissionLevel>,
        satisfied_authorizations: &HashSet<PermissionLevel>,
    ) -> Result<(), AuthorityError> {
        let mut permissions_to_satisfy = HashSet::<PermissionLevel>::new();

        for act in actions.iter() {
            let mut special_case = false;

            if act.account().as_u64() == name!("pulse") {
                special_case = true;

                match act.name().as_u64() {
                    name!("updateauth") => self.check_updateauth_authorization(session, act)?,
                    name!("deleteauth") => self.check_deleteauth_authorization(session, act)?,
                    name!("linkauth") => self.check_linkauth_authorization(session, act)?,
                    name!("unlinkauth") => self.check_unlinkauth_authorization(session, act)?,
                    _ => special_case = false,
                }
            }

            for declared_auth in act.authorization() {
                if !special_case {
                    let min_permission_name = self.lookup_minimum_permission(
                        session,
                        declared_auth.actor(),
                        act.account(),
                        act.name(),
                    )?;
                    if min_permission_name.is_some() {
                        // since special cases were already handled, it should only be false if the permission is pulse.any
                        let min_permission_name = min_permission_name.unwrap();
                        let min_permission = self.get_permission(
                            session,
                            &PermissionLevel::new(declared_auth.actor(), min_permission_name),
                        )?;
                        self.get_permission(session, &declared_auth)?
                            .satisfies(&min_permission, session)
                            .map_err(|_| {
                                AuthorityError::IrrelevantAuth(format!(
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

            let mut authority_checker = AuthorityChecker::new();

            // Now verify that all the declared authorizations are satisfied
            for p in permissions_to_satisfy.iter() {
                let permission = self
                    .get_permission(session, p)
                    .map_err(|_| AuthorityError::InternalError)?;
                let satisfied = authority_checker.satisfied(session, &permission.authority)?;

                if !satisfied {
                    return Err(AuthorityError::AuthorizationError(format!(
                        "transaction declares authority '{}' but does not have signatures for it",
                        p
                    )));
                }
            }
        }
        Ok(())
    }

    fn check_updateauth_authorization(
        &self,
        session: &UndoSession,
        action: &Action,
    ) -> Result<(), AuthorityError> {
        let update = action
            .data_as::<UpdateAuth>()
            .map_err(|e| AuthorityError::DataError(format!("{}", e)))?;

        if action.authorization().len() != 1 {
            return Err(AuthorityError::IrrelevantAuth(
                "updateauth action should only have one declared authorization".to_string(),
            ));
        }
        let auth = action.authorization()[0];
        if auth.actor().as_u64() != update.account.as_u64() {
            return Err(AuthorityError::IrrelevantAuth(
                "the owner of the affected permission needs to be the actor of the declared authorization".to_string(),
            ));
        }

        let mut min_permission = self.find_permission(
            session,
            &PermissionLevel::new(update.account, update.permission),
        )?;
        if min_permission.is_none() {
            // creating a new permission
            min_permission = Some(self.get_permission(
                session,
                &PermissionLevel::new(update.account, update.parent),
            )?);
        }
        let min_permission = min_permission.unwrap();

        self.get_permission(session, &auth)?
            .satisfies(&min_permission, session)
            .map_err(|_| {
                AuthorityError::IrrelevantAuth(format!(
                    "updateauth action declares irrelevant authority '{}'; minimum authority is {}",
                    auth,
                    PermissionLevel::new(update.account, min_permission.name)
                ))
            })?;

        Ok(())
    }

    fn check_deleteauth_authorization(
        &self,
        session: &UndoSession,
        action: &Action,
    ) -> Result<(), AuthorityError> {
        let del = action
            .data_as::<DeleteAuth>()
            .map_err(|e| AuthorityError::DataError(format!("{}", e)))?;

        if action.authorization().len() != 1 {
            return Err(AuthorityError::IrrelevantAuth(
                "deleteauth action should only have one declared authorization".to_string(),
            ));
        }
        let auth = action.authorization()[0];
        if auth.actor().as_u64() != del.account.as_u64() {
            return Err(AuthorityError::IrrelevantAuth(
                "the owner of the permission to delete needs to be the actor of the declared authorization".to_string(),
            ));
        }
        let min_permission =
            self.get_permission(session, &PermissionLevel::new(del.account, del.permission))?;
        self.get_permission(session, &auth)?
            .satisfies(&min_permission, session)
            .map_err(|_| {
                AuthorityError::IrrelevantAuth(format!(
                    "deleteauth action declares irrelevant authority '{}'; minimum authority is {}",
                    auth,
                    PermissionLevel::new(min_permission.owner, min_permission.name)
                ))
            })?;
        Ok(())
    }

    fn check_linkauth_authorization(
        &self,
        session: &UndoSession,
        action: &Action,
    ) -> Result<(), AuthorityError> {
        let link = action
            .data_as::<LinkAuth>()
            .map_err(|e| AuthorityError::DataError(format!("{}", e)))?;
        if action.authorization().len() != 1 {
            return Err(AuthorityError::IrrelevantAuth(
                "link action should only have one declared authorization".to_string(),
            ));
        }
        let auth = action.authorization()[0];
        if auth.actor().as_u64() != link.account.as_u64() {
            return Err(AuthorityError::IrrelevantAuth(
                "the owner of the linked permission needs to be the actor of the declared authorization".to_string(),
            ));
        }
        if link.code.as_u64() == name!("pulse") {
            match link.message_type.as_u64() {
                name!("updateauth") => {
                    return Err(AuthorityError::AuthorizationError(
                        "cannot link pulse::updateauth to a minimum permission".to_string(),
                    ));
                }
                name!("deleteauth") => {
                    return Err(AuthorityError::AuthorizationError(
                        "cannot link pulse::deleteauth to a minimum permission".to_string(),
                    ));
                }
                name!("linkauth") => {
                    return Err(AuthorityError::AuthorizationError(
                        "cannot link pulse::linkauth to a minimum permission".to_string(),
                    ));
                }
                name!("unlinkauth") => {
                    return Err(AuthorityError::AuthorizationError(
                        "cannot link pulse::unlinkauth to a minimum permission".to_string(),
                    ));
                }
                _ => {}
            }
        }
        let linked_permission_name =
            self.lookup_minimum_permission(session, link.account, link.code, link.message_type)?;
        if linked_permission_name.is_none() {
            return Ok(()); // if action is linked to pulse.any permission
        }
        let linked_permission_name = linked_permission_name.unwrap();
        let min_permission = self.get_permission(
            session,
            &PermissionLevel::new(link.account, linked_permission_name),
        )?;
        self.get_permission(session, &auth)?
            .satisfies(&min_permission, session)
            .map_err(|_| {
                AuthorityError::IrrelevantAuth(format!(
                    "link action declares irrelevant authority '{}'; minimum authority is {}",
                    auth,
                    PermissionLevel::new(link.account, linked_permission_name)
                ))
            })?;
        Ok(())
    }

    fn check_unlinkauth_authorization(
        &self,
        session: &UndoSession,
        action: &Action,
    ) -> Result<(), AuthorityError> {
        let unlink = action
            .data_as::<UnlinkAuth>()
            .map_err(|e| AuthorityError::DataError(format!("{}", e)))?;
        if action.authorization().len() != 1 {
            return Err(AuthorityError::IrrelevantAuth(
                "unlink action should only have one declared authorization".to_string(),
            ));
        }
        let auth = action.authorization()[0];
        if auth.actor() != unlink.account {
            return Err(AuthorityError::IrrelevantAuth(
                "the owner of the linked permission needs to be the actor of the declared authorization".to_string(),
            ));
        }
        let unlinked_permission_name = self.lookup_minimum_permission(
            session,
            unlink.account,
            unlink.code,
            unlink.message_type,
        )?;
        if unlinked_permission_name.is_none() {
            return Err(AuthorityError::IrrelevantAuth(format!(
                "cannot unlink non-existent permission link of account '{}' for actions matching '{}::{}'",
                unlink.account, unlink.code, unlink.message_type
            )));
        }
        let unlinked_permission_name = unlinked_permission_name.unwrap();
        if unlinked_permission_name == ANY_NAME {
            return Ok(());
        }
        let min_permission = self.get_permission(
            session,
            &PermissionLevel::new(unlink.account, unlinked_permission_name),
        )?;
        self.get_permission(session, &auth)?
            .satisfies(&min_permission, session)
            .map_err(|_| {
                AuthorityError::IrrelevantAuth(format!(
                    "unlink action declares irrelevant authority '{}'; minimum authority is {}",
                    auth,
                    PermissionLevel::new(unlink.account, unlinked_permission_name)
                ))
            })?;
        Ok(())
    }

    fn find_permission(
        &self,
        session: &UndoSession,
        level: &PermissionLevel,
    ) -> Result<Option<Permission>, AuthorityError> {
        if level.actor().empty() || level.permission().empty() {
            return Err(AuthorityError::InvalidPermission);
        }
        let result = session
            .find_by_secondary::<Permission, PermissionByOwnerIndex>((
                level.actor(),
                level.permission(),
            ))
            .map_err(|_| AuthorityError::InternalError)?;
        if result.is_none() {
            return Ok(None);
        }
        Ok(Some(result.unwrap()))
    }

    fn get_permission(
        &self,
        session: &UndoSession,
        level: &PermissionLevel,
    ) -> Result<Permission, AuthorityError> {
        if level.actor().empty() || level.permission().empty() {
            return Err(AuthorityError::InvalidPermission);
        }
        let result = session
            .find_by_secondary::<Permission, PermissionByOwnerIndex>((
                level.actor(),
                level.permission(),
            ))
            .map_err(|_| AuthorityError::InternalError)?;
        if result.is_none() {
            return Err(AuthorityError::PermissionNotFound(
                level.actor().clone(),
                level.permission().clone(),
            ));
        }
        Ok(result.unwrap())
    }

    fn lookup_minimum_permission(
        &self,
        session: &UndoSession,
        authorizer_account: Name,
        scope: Name,
        act_name: Name,
    ) -> Result<Option<Name>, AuthorityError> {
        if scope == name!("pulse") {
            if act_name == name!("updateauth")
                || act_name == name!("deleteauth")
                || act_name == name!("linkauth")
                || act_name == name!("unlinkauth")
            {
                return Err(AuthorityError::AuthorizationError(
                    "cannot call lookup_minimum_permission on native actions that are not allowed to be linked to minimum permissions".to_string(),
                ));
            }
        }

        let linked_permission =
            self.lookup_linked_permission(session, authorizer_account, scope, act_name)?;

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
        &self,
        session: &UndoSession,
        authorizer_account: Name,
        scope: Name,
        act_name: Name,
    ) -> Result<Option<Name>, AuthorityError> {
        // First look up a specific link for this message act_name
        let mut key = (authorizer_account, scope, act_name);
        let mut link = session
            .find_by_secondary::<PermissionLink, PermissionLinkByActionNameIndex>(key)
            .map_err(|_| AuthorityError::InternalError)?;
        // If no specific link found, check for a contract-wide default
        if link.is_none() {
            key = (authorizer_account, scope, Name::default());
            link = session
                .find_by_secondary::<PermissionLink, PermissionLinkByActionNameIndex>(key)
                .map_err(|_| AuthorityError::InternalError)?;
        }

        if link.is_some() {
            return Ok(Some(link.unwrap().required_permission()));
        }

        Ok(None)
    }

    pub fn create_permission(
        &self,
        session: &mut UndoSession,
        account: Name,
        name: Name,
        parent: u64,
        auth: Authority,
    ) -> Result<Permission, AuthorityError> {
        let id = session.generate_id::<Permission>().map_err(|e| {
            AuthorityError::AuthorizationError(format!("Failed to generate permission ID: {}", e))
        })?;
        let permission = Permission::new(id, parent, account, name, auth);
        session.insert(&permission).map_err(|e| {
            AuthorityError::AuthorizationError(format!("Failed to create permission: {}", e))
        })?;
        Ok(permission)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::chain::{Id, authority::Authority, authority::KeyWeight};

    use super::*;
    use pulsevm_chainbase::Database;
    use pulsevm_serialization::Deserialize;

    #[test]
    fn test_authority_checker() {
        // Create a mock database
        let path = Path::new("test.db");
        let shared_db = Arc::new(Mutex::new(Database::temporary(path).unwrap()));
        let our_db = shared_db.clone();
        let db = our_db.try_lock().unwrap();
        println!("Database created at: {:?}", path);
        let mut undo_session = db.undo_session().unwrap();
        let owner_permission = Permission::new(
            0,
            0,
            name!("test").into(),
            name!("test").into(),
            Authority::new(
                1,
                vec![KeyWeight::new(
                    PublicKey::from_hex(
                        "027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c",
                    )
                    .unwrap(),
                    1,
                )],
                vec![],
            ),
        );
        undo_session.insert(&owner_permission).unwrap();
        let data = "0000e19b30bc0bfabfab01c9260469fab7529ae88987b2eb337dac5650305226b38e00000001aea38500000000009ab864229a9e40000000006eaea385000000000064553988000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c0001000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c00010000000000000001aea38500000000003232eda80000000000000001ada3bd9c65952513b98753bcc582cf368fb8bf8432e3e0389498a248756b209a0eb4e0846a1f85cad63fd2203cb1577514a902a54ae718a33552bb782fe11c960178ed5cd2";
        let tx_data = hex::decode(data).unwrap();
        let tx = Transaction::deserialize(&tx_data, &mut 0).unwrap();

        // Create an AuthorityChecker instance
        let mut checker = AuthorizationManager::new();
    }
}
