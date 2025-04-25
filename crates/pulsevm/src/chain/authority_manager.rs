use std::{collections::HashSet, sync::{Arc}};

use pulsevm_chainbase::Database;
use tokio::sync::Mutex;

use super::{PermissionLevel, Signature};

pub enum AuthorityError {
    PermissionNotFound,
    RecursionDepthExceeded,
}

pub struct AuthorityManager {
    db: Arc<Mutex<Database>>,
    signatures: Vec<Signature>,
    satisfied_authorities: HashSet<PermissionLevel>,
}

impl AuthorityManager {
    pub fn new(db: Arc<Mutex<Database>>, signatures: Vec<Signature>) -> Self {
        Self { db, signatures, satisfied_authorities: HashSet::new() }
    }

    pub fn satisfies_permission_level(&mut self, level: &PermissionLevel) -> Result<(), AuthorityError> {
        self.satisfies_permission_level_internal(level, 0)
    }

    async fn satisfies_permission_level_internal(&mut self, level: &PermissionLevel, depth: u16) -> Result<(), AuthorityError> {
        if depth > 10 {
            return Err(AuthorityError::RecursionDepthExceeded);
        }
        if self.satisfied_authorities.contains(level) {
            return Ok(());
        }
        let db = self.db.lock().await;

        Err(AuthorityError::PermissionNotFound)
    }
}