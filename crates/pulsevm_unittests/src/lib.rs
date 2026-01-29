#[cfg(test)]
mod unittests;

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs, path::Path, str::FromStr, sync::Arc, vec};

    use pulsevm_core::{
        ACTIVE_NAME, CODE_NAME, ChainError, Database, OWNER_NAME, PULSE_NAME, authority::{Authority, KeyWeight, PermissionLevel, PermissionLevelWeight}, block::{BlockStatus, BlockTimestamp}, config::{DELETEAUTH_NAME, LINKAUTH_NAME, NEWACCOUNT_NAME, SETCODE_NAME, UNLINKAUTH_NAME, UPDATEAUTH_NAME}, controller::Controller, crypto::{PrivateKey, PublicKey}, name::Name, pulse_contract::{DeleteAuth, LinkAuth, NewAccount, SetCode, UnlinkAuth, UpdateAuth}, transaction::{Action, PackedTransaction, SignedTransaction, Transaction, TransactionTrace}, utils::pulse_assert
    };
    use pulsevm_crypto::{Bytes, Digest};
    use pulsevm_name_macro::name;
    use pulsevm_serialization::{VarUint32, Write};
    use serde_json::json;

    #[derive(Clone)]
    pub struct PendingBlockState {
        pub timestamp: BlockTimestamp,
        pub db: Database,
    }

    pub struct Testing {
        pub controller: Controller,
        pub pending_block_state: Option<PendingBlockState>,
    }

    impl Testing {
        pub fn new() -> Self {
            let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
            let mut controller = Controller::new();
            let private_key = get_private_key(PULSE_NAME.into(), "active");
            let genesis = generate_genesis(&private_key);

            // Initialize controller
            controller
                .initialize(&genesis, temp_dir.path().to_str().unwrap())
                .expect("Failed to initialize controller");

            let mut suite = Testing {
                controller,
                pending_block_state: None,
            };

            suite.set_bios_contract().expect("Failed to set bios contract");

            suite
        }

        pub fn create_accounts(&mut self, accounts: Vec<Name>, multisig: bool, include_code: bool) -> Result<Vec<TransactionTrace>, ChainError> {
            let mut traces: Vec<TransactionTrace> = Vec::with_capacity(accounts.len());

            for account in accounts.iter() {
                let trace = { self.create_account(account.clone(), PULSE_NAME.into(), multisig, include_code)? };
                traces.push(trace);
            }

            Ok(traces)
        }

        pub fn create_account(&mut self, account: Name, creator: Name, multisig: bool, include_code: bool) -> Result<TransactionTrace, ChainError> {
            let mut trx = Transaction::default();
            self.set_transaction_headers(&mut trx, 6, 0);
            let mut owner_auth = Authority::new(1, vec![KeyWeight::new(get_public_key(account, "owner").inner(), 1)], vec![], vec![]);

            if multisig {
                owner_auth = Authority::new(
                    2,
                    vec![KeyWeight::new(get_public_key(account, "owner").inner(), 1)],
                    vec![PermissionLevelWeight::new(PermissionLevel::new(creator.as_u64(), ACTIVE_NAME.as_u64()), 1)],
                    vec![],
                );
            }

            let mut active_auth = Authority::new(1, vec![KeyWeight::new(get_public_key(account, "active").inner(), 1)], vec![], vec![]);

            let sort_permissions = |auth: &mut Authority| {
                auth.accounts.sort_by(|lhs, rhs| lhs.permission.cmp(&rhs.permission));
            };

            if include_code {
                pulse_assert(
                    owner_auth.threshold() <= u16::MAX as u32,
                    ChainError::InternalError("threshold too high".to_string()),
                )?;
                pulse_assert(
                    active_auth.threshold() <= u16::MAX as u32,
                    ChainError::InternalError("threshold too high".to_string()),
                )?;
                owner_auth.accounts.push(PermissionLevelWeight::new(
                    PermissionLevel::new(account.as_u64(), CODE_NAME.as_u64()),
                    owner_auth.threshold() as u16,
                ));
                sort_permissions(&mut owner_auth);
                active_auth.accounts.push(PermissionLevelWeight::new(
                    PermissionLevel::new(account.as_u64(), CODE_NAME.as_u64()),
                    active_auth.threshold() as u16,
                ));
                sort_permissions(&mut active_auth);
            }

            trx.actions.push(Action::new(
                PULSE_NAME.into(),
                NEWACCOUNT_NAME.into(),
                NewAccount {
                    creator,
                    name: account,
                    owner: owner_auth,
                    active: active_auth,
                }
                .pack()
                .unwrap(),
                vec![PermissionLevel::new(creator.as_u64(), ACTIVE_NAME.as_u64())],
            ));

            self.set_transaction_headers(&mut trx, 6, 0);
            let signed = trx.sign(&get_private_key(creator, "active"), &self.controller.chain_id()).unwrap();
            let result = self.push_transaction(signed).unwrap();
            Ok(result)
        }

        pub fn push_transaction(&mut self, trx: SignedTransaction) -> Result<TransactionTrace, ChainError> {
            let pbs = self.get_pending_block_state();
            let packed = PackedTransaction::from_signed_transaction(trx).map_err(|e| {
                ChainError::DatabaseError(format!("failed to pack transaction for pushing: {}", e))
            })?;
            let block_status = BlockStatus::Verifying;
            println!("Pushing transaction with {}", serde_json::to_string(&packed).unwrap());
            let result = self.controller.execute_transaction(&packed, &pbs.timestamp, &block_status)?;
            Ok(result.trace)
        }

        pub fn push_reqauth(&mut self, from: Name, role: &str, multi_sig: bool) -> Result<TransactionTrace, ChainError> {
            if !multi_sig {
                return self.push_reqauth2(from, vec![PermissionLevel::new(from.as_u64(), OWNER_NAME.as_u64())], vec![get_private_key(from, role)]);
            } else {
                return self.push_reqauth2(
                    from,
                    vec![PermissionLevel::new(from.as_u64(), OWNER_NAME.as_u64())],
                    vec![get_private_key(from, role), get_private_key(PULSE_NAME.into(), "active")],
                );
            }
        }

        pub fn push_reqauth2(&mut self, from: Name, auths: Vec<PermissionLevel>, keys: Vec<PrivateKey>) -> Result<TransactionTrace, ChainError> {
            let mut trx = Transaction::default();
            trx.actions
                .push(Action::new(PULSE_NAME.into(), name!("reqauth").into(), from.pack().unwrap(), auths));

            self.set_transaction_headers(&mut trx, 6, 0);
            let mut signed: SignedTransaction = SignedTransaction::new(trx, HashSet::new(), vec![]);
            for key in keys.iter() {
                signed = signed.sign(key, &self.controller.chain_id())?;
            }
            let result = self.push_transaction(signed)?;
            Ok(result)
        }

        pub fn get_pending_block_state(&mut self) -> PendingBlockState {
            if let Some(pending_block_state) = &self.pending_block_state {
                pending_block_state.clone()
            } else {
                self.pending_block_state = Some(PendingBlockState {
                    timestamp: BlockTimestamp::now(),
                    db: self.controller.database(),
                });

                self.pending_block_state.as_ref().unwrap().clone()
            }
        }

        pub fn set_transaction_headers(&self, trx: &mut Transaction, _expiration: u32, delay_sec: u32) {
            trx.header.max_net_usage_words = VarUint32(0); // No limit
            trx.header.max_cpu_usage = 0; // No limit
            trx.header.delay_sec = VarUint32(delay_sec);
        }

        pub fn set_code(&mut self, account: Name, wasm: Bytes) -> Result<(), ChainError> {
            let mut trx = Transaction::default();
            self.set_transaction_headers(&mut trx, 6, 0);
            trx.actions.push(Action::new(
                PULSE_NAME.into(),
                SETCODE_NAME.into(),
                SetCode {
                    account: account,
                    vm_type: 0,
                    vm_version: 0,
                    code: Arc::new(wasm),
                }
                .pack()
                .unwrap(),
                vec![PermissionLevel::new(PULSE_NAME.as_u64(), ACTIVE_NAME.as_u64())],
            ));

            let signed = trx.sign(&get_private_key(PULSE_NAME, "active"), &self.controller.chain_id())?;
            self.push_transaction(signed)?;
            Ok(())
        }

        pub fn set_bios_contract(&mut self) -> Result<(), ChainError> {
            let bios_wasm_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("reference_contracts")
                .join("pulse_bios.wasm");
            let wasm = fs::read(bios_wasm_path).expect("Failed to read bios wasm file");
            self.set_code(PULSE_NAME, Bytes::from(wasm))?;
            Ok(())
        }

        pub fn set_authority(
            &mut self,
            account: Name,
            permission: Name,
            authority: Authority,
            parent: Name,
            auths: Vec<PermissionLevel>,
            keys: Vec<PrivateKey>,
        ) -> Result<(), ChainError> {
            let mut trx = Transaction::default();
            trx.actions.push(Action::new(
                PULSE_NAME,
                UPDATEAUTH_NAME,
                UpdateAuth {
                    account,
                    permission,
                    parent: parent,
                    auth: authority,
                }
                .pack()
                .unwrap(),
                auths,
            ));
            self.set_transaction_headers(&mut trx, 6, 0);

            let mut signed: SignedTransaction = SignedTransaction::new(trx, HashSet::new(), vec![]);
            for key in keys.iter() {
                signed = signed.sign(key, &self.controller.chain_id())?;
            }
            self.push_transaction(signed)?;
            Ok(())
        }

        pub fn set_authority2(&mut self, account: Name, permission: Name, authority: Authority, parent: Name) -> Result<(), ChainError> {
            let auths = vec![PermissionLevel::new(account.as_u64(), OWNER_NAME.as_u64())];
            let keys = vec![get_private_key(account, "owner")];
            self.set_authority(account, permission, authority, parent, auths, keys)
        }

        pub fn delete_authority(
            &mut self,
            account: Name,
            permission: Name,
            auths: Vec<PermissionLevel>,
            keys: Vec<PrivateKey>,
        ) -> Result<(), ChainError> {
            let mut trx = Transaction::default();
            trx.actions.push(Action::new(
                PULSE_NAME,
                DELETEAUTH_NAME,
                DeleteAuth { account, permission }.pack().unwrap(),
                auths,
            ));
            self.set_transaction_headers(&mut trx, 6, 0);

            let mut signed: SignedTransaction = SignedTransaction::new(trx, HashSet::new(), vec![]);
            for key in keys.iter() {
                signed = signed.sign(key, &self.controller.chain_id())?;
            }
            self.push_transaction(signed)?;
            Ok(())
        }

        pub fn delete_authority2(&mut self, account: Name, permission: Name) -> Result<(), ChainError> {
            let auths = vec![PermissionLevel::new(account.as_u64(), OWNER_NAME.as_u64())];
            let keys = vec![get_private_key(account, "owner")];
            self.delete_authority(account, permission, auths, keys)
        }

        pub fn link_authority(&mut self, account: Name, code: Name, requirement: Name, message_type: Name) -> Result<(), ChainError> {
            let mut trx = Transaction::default();
            trx.actions.push(Action::new(
                PULSE_NAME,
                LINKAUTH_NAME,
                LinkAuth {
                    account,
                    code,
                    message_type,
                    requirement,
                }
                .pack()
                .unwrap(),
                vec![PermissionLevel::new(account.as_u64(), ACTIVE_NAME.as_u64())],
            ));
            self.set_transaction_headers(&mut trx, 6, 0);

            let signed = trx.sign(&get_private_key(account, "active"), &self.controller.chain_id())?;
            self.push_transaction(signed)?;
            Ok(())
        }

        pub fn unlink_authority(&mut self, account: Name, code: Name, message_type: Name) -> Result<(), ChainError> {
            let mut trx = Transaction::default();
            trx.actions.push(Action::new(
                PULSE_NAME,
                UNLINKAUTH_NAME,
                UnlinkAuth { account, code, message_type }.pack().unwrap(),
                vec![PermissionLevel::new(account.as_u64(), ACTIVE_NAME.as_u64())],
            ));
            self.set_transaction_headers(&mut trx, 6, 0);

            let signed = trx.sign(&get_private_key(account, "active"), &self.controller.chain_id())?;
            self.push_transaction(signed)?;
            Ok(())
        }
    }

    pub fn get_private_key(key_name: Name, role: &str) -> PrivateKey {
        let secret = key_name.to_string() + "_" + role;
        let private_key = PrivateKey::new_k1_from_string(&secret).expect("Failed to create private key");
        private_key
    }

    pub fn get_public_key(key_name: Name, role: &str) -> PublicKey {
        let private_key = get_private_key(key_name, role);
        private_key.get_public_key()
    }

    pub fn generate_genesis(private_key: &PrivateKey) -> Vec<u8> {
        let genesis = json!(
        {
            "initial_timestamp": "2023-01-01T00:00:00",
            "initial_key": private_key.get_public_key().to_string(),
            "initial_configuration": {
                "max_block_net_usage": 1048576,
                "target_block_net_usage_pct": 1000,
                "max_transaction_net_usage": 524288,
                "base_per_transaction_net_usage": 12,
                "net_usage_leeway": 500,
                "context_free_discount_net_usage_num": 20,
                "context_free_discount_net_usage_den": 100,
                "max_block_cpu_usage": 200000,
                "target_block_cpu_usage_pct": 2500,
                "max_transaction_cpu_usage": 150000,
                "min_transaction_cpu_usage": 100,
                "max_transaction_lifetime": 3600,
                "max_inline_action_size": 4096,
                "max_inline_action_depth": 6,
                "max_authority_depth": 6,
                "max_action_return_value_size": 256
            }
        });
        genesis.to_string().into_bytes()
    }
}
