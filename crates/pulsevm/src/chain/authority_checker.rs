use std::{collections::HashSet, fmt::{self}, sync::Arc};

use pulsevm_chainbase::{Database, UndoSession};
use pulsevm_proc_macros::name;
use pulsevm_serialization::Serialize;
use tokio::sync::Mutex;

use super::{
    authority::{Permission, PermissionLevel}, name, Action, Name, PublicKey, Transaction
};

#[derive(Debug, Clone)]
pub enum AuthorityError {
    PermissionNotFound(Name, Name),
    RecursionDepthExceeded,
    InternalError,
    NotSatisfied,
    SignatureRecoverError(String),
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
        }
    }
}

pub struct AuthorityChecker<'a> {
    session: &'a UndoSession<'a>,
    satisfied_authorities: HashSet<PermissionLevel>,
    provided_keys: HashSet<PublicKey>,
    used_keys: HashSet<PublicKey>,
}

impl<'a> AuthorityChecker<'a> {
    pub fn new(tx: &Transaction, session: &'a UndoSession) -> Result<Self, AuthorityError> {
        let mut provided_keys: HashSet<PublicKey> = HashSet::new();
        let mut tx_data: Vec<u8> = Vec::new();
        tx.unsigned_tx.serialize(&mut tx_data);
        for signature in tx.signatures.iter() {
            let public_key = signature
                .recover_public_key(&tx_data)
                .map_err(|e| AuthorityError::SignatureRecoverError(format!("{}", e)))?;
            provided_keys.insert(public_key);
        }
        Ok(Self {
            session,
            satisfied_authorities: HashSet::new(),
            provided_keys,
            used_keys: HashSet::new(),
        })
    }

    pub fn check_authorization(
        &mut self,
        actions: &Vec<Action>,
        provided_keys: &HashSet<PublicKey>,
        provided_permissions: &HashSet<PermissionLevel>,
    ) -> Result<(), AuthorityError> {
        for action in actions.iter() {
            let mut special_case = false;

            if action.account().as_u64() == name!("pulsevm") {
                special_case = true;
                match action.name().as_u64() {
                    name!("updateauth") => self.check_updateauth_authorization()?,
                    name!("deleteauth") => (),
                    name!("linkauth") => (),
                    name!("unlinkauth") => (),
                    _ => special_case = false,
                }
            }

            println!("Action: {:?}", special_case);
        }
        Ok(())
    }

    fn check_updateauth_authorization(&self) -> Result<(), AuthorityError> {
        Ok(())
    }

    pub fn satisfies_permission_level(
        &mut self,
        level: &PermissionLevel,
        depth: u16,
    ) -> Result<(), AuthorityError> {
        if depth > 10 {
            return Err(AuthorityError::RecursionDepthExceeded);
        }
        if self.satisfied_authorities.contains(level) {
            return Ok(());
        }
        //let db_clone = self.db.clone();
        let permission: Option<Permission> = self
            .session
            .find_by_primary((level.actor(), level.permission()))
            .map_err(|_| AuthorityError::InternalError)?;
        if permission.is_none() {
            return Err(AuthorityError::PermissionNotFound(
                level.actor().clone(),
                level.permission().clone(),
            ));
        }

        let permission = permission.unwrap();
        let mut weight = 0u16;
        let threshold = permission.authority.threshold() as u16;
        for key_weight in permission.authority.keys() {
            if self.provided_keys.contains(key_weight.key()) {
                self.used_keys.insert(key_weight.key().clone());
                weight += key_weight.weight();
            }
        }

        if weight >= threshold {
            self.satisfied_authorities.insert(level.clone());
            return Ok(());
        }

        for account in permission.authority.accounts() {
            let perm_level = account.permission().clone();
            self.satisfies_permission_level(&perm_level, depth + 1)?;
            weight += account.weight();
        }

        if weight >= threshold {
            self.satisfied_authorities.insert(level.clone());
            return Ok(());
        }

        Err(AuthorityError::NotSatisfied)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::chain::{Id, authority::Authority, authority::KeyWeight, name};

    use super::*;
    use pulsevm_chainbase::Database;
    use pulsevm_proc_macros::name;
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
            Id::zero(),
            Id::zero(),
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
        let mut checker = AuthorityChecker::new(&tx, &undo_session).unwrap();

        // Test satisfies_permission_level
        let level = PermissionLevel::new(name!("test").into(), name!("test").into());
        assert!(checker.satisfies_permission_level(&level, 0).is_ok());
    }
}
