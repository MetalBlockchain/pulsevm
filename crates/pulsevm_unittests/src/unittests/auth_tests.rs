#[cfg(test)]
mod auth_tests {
    use std::collections::BTreeSet;

    use anyhow::Result;
    use pulsevm_core::{
        ACTIVE_NAME,
        ChainError,
        OWNER_NAME,
        PULSE_NAME,
        authority::{
            Authority,
            KeyWeight,
            PermissionLevel,
            PermissionLevelWeight,
        },
        authorization_manager::AuthorizationManager,
        crypto::{
            PrivateKey,
            PublicKey,
        },
        name::Name,
        transaction::{
            Action,
            SignedTransaction,
            Transaction,
            TransactionTrace,
        },
    };
    use pulsevm_serialization::Write;

    use crate::tests::{
        DEFAULT_EXPIRATION_DELTA,
        Testing,
        get_private_key,
    };
    use pulsevm_name_macro::name;

    /// Guards the DB read-API soundness fix. `get_permission` now returns a
    /// `&PermissionObject` bound to a `DbRead` guard, so a permission reference
    /// cannot be held across a mutation — the aliasing UB is a compile error.
    ///
    /// The pre-fix version of this test held the reference across the mutation:
    ///
    /// ```ignore
    /// let perm = AuthorizationManager::get_permission(&db, alice, spending)?;
    /// let before = perm.get_authority().to_authority();
    /// chain.set_authority2(alice, spending, new_auth, active)?; // mutates *perm
    /// let after = perm.get_authority().to_authority();          // UB: reads through shared &
    /// ```
    ///
    /// That no longer type-checks: `get_permission` wants `&DbRead`, and the
    /// reference borrows the guard, so it cannot outlive a `db.read()` scope or
    /// coexist with a `&mut db` mutation. The safe pattern below reads each
    /// value inside its own read scope and mutates in between.
    #[tokio::test]
    async fn test_permission_ref_is_guard_scoped() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        chain.create_account(alice, PULSE_NAME.into(), false, true)?;

        let key1 = get_private_key(alice, "spend_one").get_public_key();
        chain.set_authority2(
            alice,
            name!("spending").into(),
            Authority::new_from_public_key(key1.k1().clone()),
            ACTIVE_NAME.into(),
        )?;

        let db = chain.get_pending_block_state().db;

        // The reference is confined to this read scope and dropped at its end.
        let auth_before = {
            let r = db.read()?;
            let perm = AuthorizationManager::get_permission(&r, alice.as_u64(), name!("spending"))?;
            r.permission_authority(perm.owner(), perm.name())?
                .expect("permission exists")
        };

        let key2 = get_private_key(alice, "spend_two").get_public_key();
        chain.set_authority2(
            alice,
            name!("spending").into(),
            Authority::new_from_public_key(key2.k1().clone()),
            ACTIVE_NAME.into(),
        )?;

        let auth_after = {
            let r = db.read()?;
            let perm = AuthorizationManager::get_permission(&r, alice.as_u64(), name!("spending"))?;
            r.permission_authority(perm.owner(), perm.name())?
                .expect("permission exists")
        };

        assert_ne!(auth_before, auth_after);
        Ok(())
    }

    /// Pushes a single transaction holding one `reqauth` action per entry in
    /// `reqs`, each declaring its own authorization, signed by `keys`.
    fn push_multi_reqauth(
        chain: &mut Testing,
        reqs: Vec<(Name, PermissionLevel)>,
        keys: Vec<PrivateKey>,
    ) -> Result<TransactionTrace, ChainError> {
        let mut trx = Transaction::default();
        for (from, auth) in reqs {
            trx.actions.push(Action::new(
                PULSE_NAME.into(),
                name!("reqauth").into(),
                from.pack().unwrap(),
                vec![auth],
            ));
        }

        chain.set_transaction_headers(&mut trx, DEFAULT_EXPIRATION_DELTA, 0);
        let mut signed: SignedTransaction = SignedTransaction::new(trx, BTreeSet::new(), vec![]);
        for key in keys.iter() {
            signed = signed.sign(key, &chain.controller.chain_id())?;
        }
        chain.push_transaction(signed)
    }

    /// A transaction may carry actions whose authorities share no keys. Every
    /// signature is relevant to the transaction as a whole even though none is
    /// relevant to every individual action.
    #[tokio::test]
    async fn test_multi_action_disjoint_auths() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        let bob: Name = name!("bob").into();
        chain.create_accounts(vec![alice, bob], false, true)?;

        push_multi_reqauth(
            &mut chain,
            vec![
                (
                    alice,
                    PermissionLevel::new(alice.as_u64(), ACTIVE_NAME.as_u64()),
                ),
                (
                    bob,
                    PermissionLevel::new(bob.as_u64(), ACTIVE_NAME.as_u64()),
                ),
            ],
            vec![
                get_private_key(alice, "active"),
                get_private_key(bob, "active"),
            ],
        )?;
        Ok(())
    }

    /// The irrelevant-signature check still fires for a multi-action
    /// transaction when a key is needed by no action at all.
    #[tokio::test]
    async fn test_multi_action_irrelevant_sig() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        let bob: Name = name!("bob").into();
        chain.create_accounts(vec![alice, bob], false, true)?;

        assert_eq!(
            push_multi_reqauth(
                &mut chain,
                vec![
                    (
                        alice,
                        PermissionLevel::new(alice.as_u64(), ACTIVE_NAME.as_u64())
                    ),
                    (
                        bob,
                        PermissionLevel::new(bob.as_u64(), ACTIVE_NAME.as_u64())
                    ),
                ],
                vec![
                    get_private_key(alice, "active"),
                    get_private_key(bob, "active"),
                    get_private_key(alice, "unrelated"),
                ],
            )
            .err(),
            Some(ChainError::AuthorizationError(
                "transaction bears irrelevant signatures".into()
            ))
        );
        Ok(())
    }

    /// alice@active is satisfied by K1 + carol@active; the bob@active branch is
    /// visited but fails, so K2 is an irrelevant signature and must be rejected.
    #[tokio::test]
    async fn test_irrelevant_key_in_failed_subauthority() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        let bob: Name = name!("bob").into();
        let carol: Name = name!("carol").into();
        chain.create_accounts(vec![alice, bob, carol], false, true)?;

        let k1 = get_private_key(alice, "k1");
        let k1_pub = k1.get_public_key();
        let k2 = get_private_key(bob, "k2");
        let k2_pub = k2.get_public_key();
        let k2b_pub = get_private_key(bob, "k2b").get_public_key();
        let k3 = get_private_key(carol, "k3");
        let k3_pub = k3.get_public_key();

        // carol@active = threshold 1, [K3]
        chain.set_authority2(
            carol,
            ACTIVE_NAME.into(),
            Authority::new(
                1,
                vec![KeyWeight::new(k3_pub.k1().clone(), 1)],
                vec![],
                vec![],
            ),
            OWNER_NAME.into(),
        )?;

        // bob@active = threshold 2, [K2, K2b] — valid, but needs BOTH keys.
        // An authority's keys must be supplied in sorted order.
        let mut bob_keys = vec![k2_pub.clone(), k2b_pub.clone()];
        bob_keys.sort();
        chain.set_authority2(
            bob,
            ACTIVE_NAME.into(),
            Authority::new(
                2,
                bob_keys
                    .iter()
                    .map(|k| KeyWeight::new(k.k1().clone(), 1))
                    .collect(),
                vec![],
                vec![],
            ),
            OWNER_NAME.into(),
        )?;

        // alice@active = threshold 2, keys[K1], accounts[bob@active, carol@active]
        let mut alice_accounts = vec![
            PermissionLevelWeight::new(PermissionLevel::new(bob.as_u64(), ACTIVE_NAME.as_u64()), 1),
            PermissionLevelWeight::new(
                PermissionLevel::new(carol.as_u64(), ACTIVE_NAME.as_u64()),
                1,
            ),
        ];
        alice_accounts.sort_by(|a, b| a.permission.cmp(&b.permission));
        chain.set_authority2(
            alice,
            ACTIVE_NAME.into(),
            Authority::new(
                2,
                vec![KeyWeight::new(k1_pub.k1().clone(), 1)],
                alice_accounts,
                vec![],
            ),
            OWNER_NAME.into(),
        )?;

        // Declaring alice@active, signed by K1 + K2 + K3: K2 is irrelevant.
        assert_eq!(
            chain
                .push_reqauth2(
                    alice,
                    vec![PermissionLevel::new(alice.as_u64(), ACTIVE_NAME.as_u64())],
                    vec![k1.clone(), k2.clone(), k3.clone()],
                )
                .err(),
            Some(ChainError::AuthorizationError(
                "transaction bears irrelevant signatures".into()
            ))
        );

        // Without the irrelevant K2, the same transaction is accepted.
        chain.push_reqauth2(
            alice,
            vec![PermissionLevel::new(alice.as_u64(), ACTIVE_NAME.as_u64())],
            vec![k1, k3],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn test_missing_sigs() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("alice").into()], false, true)?;
        assert_eq!(
            chain
                .push_reqauth2(
                    name!("alice").into(),
                    vec![PermissionLevel::new(
                        name!("alice").into(),
                        ACTIVE_NAME.as_u64()
                    )],
                    vec![],
                )
                .err(),
            Some(ChainError::AuthorizationError(
                "transaction declares authority 'alice@active' but does not have signatures for it"
                    .into()
            ))
        );
        chain.push_reqauth(name!("alice").into(), "owner", false)?;
        Ok(())
    }

    #[tokio::test]
    async fn test_missing_multi_sigs() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_account(name!("alice").into(), PULSE_NAME.into(), true, true)?;
        assert_eq!(
            chain
                .push_reqauth(name!("alice").into(), "owner", false,)
                .err(),
            Some(ChainError::AuthorizationError(
                "transaction declares authority 'alice@owner' but does not have signatures for it"
                    .into()
            ))
        );
        chain.push_reqauth(name!("alice").into(), "owner", true)?;
        Ok(())
    }

    #[tokio::test]
    async fn test_missing_auths() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(
            vec![name!("alice").into(), name!("bob").into()],
            false,
            true,
        )?;
        // action not provided from authority
        assert_eq!(
            chain
                .push_reqauth2(
                    name!("alice").into(),
                    vec![PermissionLevel::new(
                        name!("bob").into(),
                        ACTIVE_NAME.as_u64()
                    )],
                    vec![get_private_key(name!("bob").into(), "active")],
                )
                .err(),
            Some(ChainError::ApplyError("missing authority of alice".into()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_delegate_auth() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(
            vec![name!("alice").into(), name!("bob").into()],
            false,
            true,
        )?;
        let delegated_auth = Authority::new(
            1,
            vec![],
            vec![PermissionLevelWeight::new(
                (name!("bob"), ACTIVE_NAME.as_u64()).into(),
                1,
            )],
            vec![],
        );
        chain.set_authority2(
            name!("alice").into(),
            ACTIVE_NAME.into(),
            delegated_auth.clone(),
            OWNER_NAME.into(),
        )?;
        let pending_block_state = chain.get_pending_block_state();
        let db = pending_block_state.db.clone();
        // Read the permission in a scope that drops the guard before push_reqauth2
        // below, which needs the write lock on the same db.
        let new_authority = {
            let r = db.read()?;
            let new_auth =
                AuthorizationManager::get_permission(&r, name!("alice"), ACTIVE_NAME.as_u64())?;
            r.permission_authority(new_auth.owner(), new_auth.name())?
                .expect("permission exists")
        };
        assert!(new_authority == delegated_auth);
        // execute nonce from alice signed by bob
        chain.push_reqauth2(
            name!("alice").into(),
            vec![PermissionLevel::new(
                name!("alice").into(),
                ACTIVE_NAME.as_u64(),
            )],
            vec![get_private_key(name!("bob").into(), "active")],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn test_update_auths() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_account(name!("alice").into(), PULSE_NAME.into(), false, true)?;
        chain.create_account(name!("bob").into(), PULSE_NAME.into(), false, true)?;
        // Deleting active or owner should fail
        assert_eq!(
            chain
                .delete_authority2(name!("alice").into(), ACTIVE_NAME.into())
                .err(),
            Some(ChainError::ActionValidationError(format!(
                "cannot delete active authority"
            )))
        );
        assert_eq!(
            chain
                .delete_authority2(name!("alice").into(), OWNER_NAME.into())
                .err(),
            Some(ChainError::ActionValidationError(format!(
                "cannot delete owner authority"
            )))
        );

        // Change owner permission
        let new_owner_priv_key = get_private_key(name!("alice").into(), "new_owner");
        let new_owner_pub_key = new_owner_priv_key.get_public_key();
        chain.set_authority2(
            name!("alice").into(),
            OWNER_NAME.into(),
            Authority::new_from_public_key(new_owner_pub_key.k1().clone()),
            Name::default(),
        )?;

        // Ensure the permission is updated
        let pending_block_state = chain.get_pending_block_state();
        let r = pending_block_state.db.read()?;
        let info = r
            .find_permission_info(name!("alice"), OWNER_NAME.as_u64())?
            .expect("owner permission exists");
        let owner_id = info.get_id();
        assert!(info.get_parent_id() == 0);
        let authority = r
            .permission_authority(name!("alice"), OWNER_NAME.as_u64())?
            .expect("owner authority");
        assert!(authority.threshold == 1);
        assert!(authority.keys.len() == 1);
        assert!(authority.accounts.len() == 0);
        assert!(authority.keys[0].key.to_string() == new_owner_pub_key.to_string());
        assert!(authority.keys[0].weight == 1);
        drop(r);

        // Change active permission, remember that the owner key has been changed
        let new_active_priv_key = get_private_key(name!("alice").into(), "new_active");
        let new_active_pub_key = new_active_priv_key.get_public_key();
        chain.set_authority(
            name!("alice").into(),
            ACTIVE_NAME,
            Authority::new_from_public_key(new_active_pub_key.k1().clone()),
            OWNER_NAME,
            vec![PermissionLevel::new(
                name!("alice").into(),
                ACTIVE_NAME.as_u64(),
            )],
            vec![get_private_key(name!("alice").into(), "active")],
        )?;

        let r = pending_block_state.db.read()?;
        let info = r
            .find_permission_info(name!("alice"), ACTIVE_NAME.as_u64())?
            .expect("active permission exists");
        assert!(info.get_parent_id() == owner_id);
        let authority = r
            .permission_authority(name!("alice"), ACTIVE_NAME.as_u64())?
            .expect("active authority");
        assert!(authority.threshold == 1);
        assert!(authority.keys.len() == 1);
        assert!(authority.accounts.len() == 0);
        assert!(authority.keys[0].key.to_string() == new_active_pub_key.to_string());
        assert!(authority.keys[0].weight == 1);
        drop(r);

        let spending_priv_key = get_private_key(name!("alice").into(), "spending");
        let spending_pub_key = spending_priv_key.get_public_key();
        let trading_priv_key = get_private_key(name!("alice").into(), "trading");
        let trading_pub_key = trading_priv_key.get_public_key();

        // Bob attempts to create new spending auth for Alice
        assert_eq!(
            chain
                .set_authority(
                    name!("alice").into(),
                    name!("spending").into(),
                    Authority::new_from_public_key(spending_pub_key.k1().clone()),
                    ACTIVE_NAME,
                    vec![PermissionLevel::new(name!("bob").into(), ACTIVE_NAME.as_u64())],
                    vec![get_private_key(name!("bob").into(), "active")],
                )
                .err(),
            Some(ChainError::IrrelevantAuth(
                "the owner of the affected permission needs to be the actor of the declared authorization".into()
            ))
        );

        // Create new spending auth
        chain.set_authority(
            name!("alice").into(),
            name!("spending").into(),
            Authority::new_from_public_key(spending_pub_key.k1().clone()),
            ACTIVE_NAME,
            vec![PermissionLevel::new(
                name!("alice").into(),
                ACTIVE_NAME.as_u64(),
            )],
            vec![new_active_priv_key.clone()],
        )?;
        let r = pending_block_state.db.read()?;
        let spending = r
            .find_permission_info(name!("alice"), name!("spending"))?
            .expect("spending permission exists");
        let active = r
            .find_permission_info(name!("alice"), ACTIVE_NAME.as_u64())?
            .expect("active permission exists");
        // spending's parent is active
        assert!(spending.get_parent_id() == active.get_id());
        drop(r);

        // Update spending auth parent to be its own, should fail
        assert_eq!(
            chain
                .set_authority(
                    name!("alice").into(),
                    name!("spending").into(),
                    Authority::new_from_public_key(spending_pub_key.k1().clone()),
                    name!("spending").into(),
                    vec![PermissionLevel::new(
                        name!("alice").into(),
                        name!("spending").into()
                    )],
                    vec![spending_priv_key.clone()],
                )
                .err(),
            Some(ChainError::ActionValidationError(
                "cannot set an authority as its own parent".into()
            ))
        );

        // Update spending auth parent to be owner, should fail
        assert_eq!(
            chain
                .set_authority(
                    name!("alice").into(),
                    name!("spending").into(),
                    Authority::new_from_public_key(spending_pub_key.k1().clone()),
                    OWNER_NAME,
                    vec![PermissionLevel::new(
                        name!("alice").into(),
                        name!("spending").into()
                    )],
                    vec![spending_priv_key.clone()],
                )
                .err(),
            Some(ChainError::ActionValidationError(
                "changing parent authority is not currently supported".into()
            ))
        );

        // Remove spending auth
        chain.delete_authority(
            name!("alice").into(),
            name!("spending").into(),
            vec![PermissionLevel::new(
                name!("alice").into(),
                ACTIVE_NAME.as_u64(),
            )],
            vec![new_active_priv_key.clone()],
        )?;
        assert!(
            pending_block_state
                .db
                .read()?
                .find_permission_info(name!("alice"), name!("spending"))?
                .is_none()
        );

        // Create new trading auth
        chain.set_authority(
            name!("alice").into(),
            name!("trading").into(),
            Authority::new_from_public_key(trading_pub_key.k1().clone()),
            ACTIVE_NAME,
            vec![PermissionLevel::new(
                name!("alice").into(),
                ACTIVE_NAME.as_u64(),
            )],
            vec![new_active_priv_key.clone()],
        )?;

        // Recreate spending auth again, however this time, it's under trading instead of owner
        chain.set_authority(
            name!("alice").into(),
            name!("spending").into(),
            Authority::new_from_public_key(spending_pub_key.k1().clone()),
            name!("trading").into(),
            vec![PermissionLevel::new(
                name!("alice").into(),
                name!("trading").into(),
            )],
            vec![trading_priv_key.clone()],
        )?;

        // Verify correctness of trading and spending
        let r = pending_block_state.db.read()?;
        let trading = r
            .find_permission_info(name!("alice"), name!("trading"))?
            .expect("trading permission exists");
        let spending = r
            .find_permission_info(name!("alice"), name!("spending"))?
            .expect("spending permission exists");
        let active = r
            .find_permission_info(name!("alice"), ACTIVE_NAME.as_u64())?
            .expect("active permission exists");
        // spending is now parented on trading, and trading on active
        assert!(spending.get_parent_id() == trading.get_id());
        assert!(trading.get_parent_id() == active.get_id());
        drop(r);

        // Delete trading, should fail since it has children (spending)
        assert_eq!(
            chain
                .delete_authority(
                    name!("alice").into(),
                    name!("trading").into(),
                    vec![PermissionLevel::new(
                        name!("alice").into(),
                        ACTIVE_NAME.as_u64()
                    )],
                    vec![new_active_priv_key.clone()]
                )
                .err(),
            Some(ChainError::InternalError(
                "cannot delete permission 'alice@trading' because it has child permissions".into()
            ))
        );

        // Update trading parent to be spending, should fail since changing parent authority is not
        // supported
        assert_eq!(
            chain
                .set_authority(
                    name!("alice").into(),
                    name!("trading").into(),
                    Authority::new_from_public_key(trading_pub_key.k1().clone()),
                    name!("spending").into(),
                    vec![PermissionLevel::new(
                        name!("alice").into(),
                        name!("trading").into()
                    )],
                    vec![trading_priv_key.clone()],
                )
                .err(),
            Some(ChainError::ActionValidationError(
                "changing parent authority is not currently supported".into()
            ))
        );

        chain.delete_authority(
            name!("alice").into(),
            name!("spending").into(),
            vec![PermissionLevel::new(
                name!("alice").into(),
                ACTIVE_NAME.as_u64(),
            )],
            vec![new_active_priv_key.clone()],
        )?;
        assert!(
            pending_block_state
                .db
                .read()?
                .find_permission_info(name!("alice"), name!("spending"))?
                .is_none()
        );
        chain.delete_authority(
            name!("alice").into(),
            name!("trading").into(),
            vec![PermissionLevel::new(
                name!("alice").into(),
                ACTIVE_NAME.as_u64(),
            )],
            vec![new_active_priv_key.clone()],
        )?;
        assert!(
            pending_block_state
                .db
                .read()?
                .find_permission_info(name!("alice"), name!("trading"))?
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_update_auth_unknown_private_key() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_account(name!("alice").into(), PULSE_NAME, false, true)?;
        // public key with no corresponding private key
        let new_owner_pub_key = <PublicKey as std::str::FromStr>::from_str(
            "PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H",
        )
        .unwrap();
        chain.set_authority2(
            name!("alice").into(),
            OWNER_NAME,
            Authority::new_from_public_key(new_owner_pub_key.k1().clone()),
            Name::default(),
        )?;
        // Ensure the permission is updated
        let pending_block_state = chain.get_pending_block_state();
        let r = pending_block_state.db.read()?;
        let info = r
            .find_permission_info(name!("alice"), OWNER_NAME.as_u64())?
            .expect("owner permission exists");
        assert!(info.get_parent_id() == 0);
        let authority = r
            .permission_authority(name!("alice"), OWNER_NAME.as_u64())?
            .expect("owner authority");
        assert!(authority.threshold == 1);
        assert!(authority.keys.len() == 1);
        assert!(authority.accounts.len() == 0);
        assert!(authority.keys[0].key.to_string() == new_owner_pub_key.to_string());
        assert!(authority.keys[0].weight == 1);
        drop(r);
        Ok(())
    }

    #[tokio::test]
    async fn test_link_auths() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(
            vec![name!("alice").into(), name!("bob").into()],
            false,
            true,
        )?;

        let spending_priv_key = get_private_key(name!("alice").into(), "spending");
        let spending_pub_key = spending_priv_key.get_public_key();
        let scud_priv_key = get_private_key(name!("alice").into(), "scud");
        let scud_pub_key = scud_priv_key.get_public_key();

        chain.set_authority2(
            name!("alice").into(),
            name!("spending").into(),
            Authority::new_from_public_key(spending_pub_key.k1().clone()),
            ACTIVE_NAME,
        )?;
        chain.set_authority2(
            name!("alice").into(),
            name!("scud").into(),
            Authority::new_from_public_key(scud_pub_key.k1().clone()),
            name!("spending").into(),
        )?;

        // Send req auth action with alice's spending key, it should fail
        assert_eq!(
            chain
                .push_reqauth2(
                    name!("alice").into(),
                    vec![PermissionLevel::new(name!("alice").into(), name!("spending").into())],
                    vec![spending_priv_key.clone()]
                )
                .err(),
            Some(ChainError::IrrelevantAuth(
                "action declares irrelevant authority 'alice@spending'; minimum authority is alice@active".into()
            ))
        );
        // Link authority for pulse reqauth action with alice's spending key
        chain.link_authority(
            name!("alice").into(),
            name!("pulse").into(),
            name!("spending").into(),
            name!("reqauth").into(),
        )?;
        // Now, req auth action with alice's spending key should succeed
        chain.push_reqauth2(
            name!("alice").into(),
            vec![PermissionLevel::new(
                name!("alice").into(),
                name!("spending").into(),
            )],
            vec![spending_priv_key.clone()],
        )?;
        // Relink the same auth should fail
        assert_eq!(
            chain
                .link_authority(
                    name!("alice").into(),
                    name!("pulse").into(),
                    name!("spending").into(),
                    name!("reqauth").into()
                )
                .err(),
            Some(ChainError::ActionValidationError(
                "attempting to update required authority, but new requirement is same as old"
                    .into()
            ))
        );
        // Unlink alice with pulse reqauth
        chain.unlink_authority(
            name!("alice").into(),
            name!("pulse").into(),
            name!("reqauth").into(),
        )?;
        // Now, req auth action with alice's spending key should fail
        assert_eq!(
            chain
                .push_reqauth2(
                    name!("alice").into(),
                    vec![PermissionLevel::new(name!("alice").into(), name!("spending").into())],
                    vec![spending_priv_key.clone()]
                )
                .err(),
            Some(ChainError::IrrelevantAuth(
                "action declares irrelevant authority 'alice@spending'; minimum authority is alice@active".into()
            ))
        );
        // Send req auth action with scud key, it should fail
        assert_eq!(
            chain
                .push_reqauth2(
                    name!("alice").into(),
                    vec![PermissionLevel::new(name!("alice").into(), name!("scud").into())],
                    vec![scud_priv_key.clone()]
                )
                .err(),
            Some(ChainError::IrrelevantAuth(
                "action declares irrelevant authority 'alice@scud'; minimum authority is alice@active".into()
            ))
        );
        // Link authority for any pulse action with alice's scud key
        chain.link_authority(
            name!("alice").into(),
            name!("pulse").into(),
            name!("scud").into(),
            Name::default(),
        )?;
        // Now, req auth action with alice's scud key should succeed
        chain.push_reqauth2(
            name!("alice").into(),
            vec![PermissionLevel::new(
                name!("alice").into(),
                name!("scud").into(),
            )],
            vec![scud_priv_key.clone()],
        )?;
        // req auth action with alice's spending key should also be fine, since it is the parent of
        // alice's scud key
        chain.push_reqauth2(
            name!("alice").into(),
            vec![PermissionLevel::new(
                name!("alice").into(),
                name!("spending").into(),
            )],
            vec![spending_priv_key.clone()],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn test_link_then_update_auth() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_account(name!("alice").into(), PULSE_NAME, false, true)?;

        let first_priv_key = get_private_key(name!("alice").into(), "first");
        let first_pub_key = first_priv_key.get_public_key();
        let second_priv_key = get_private_key(name!("alice").into(), "second");
        let second_pub_key = second_priv_key.get_public_key();

        chain.set_authority2(
            name!("alice").into(),
            name!("first").into(),
            Authority::new_from_public_key(first_pub_key.k1().clone()),
            ACTIVE_NAME,
        )?;
        chain.link_authority(
            name!("alice").into(),
            PULSE_NAME,
            name!("first").into(),
            name!("reqauth").into(),
        )?;
        chain.push_reqauth2(
            name!("alice").into(),
            vec![PermissionLevel::new(
                name!("alice").into(),
                name!("first").into(),
            )],
            vec![first_priv_key.clone()],
        )?;

        // Update "first" auth public key
        chain.set_authority2(
            name!("alice").into(),
            name!("first").into(),
            Authority::new_from_public_key(second_pub_key.k1().clone()),
            ACTIVE_NAME,
        )?;
        // Authority updated, using previous "first" auth should fail on linked auth
        assert_eq!(
            chain
                .push_reqauth2(
                    name!("alice").into(),
                    vec![PermissionLevel::new(
                        name!("alice").into(),
                        name!("first").into()
                    )],
                    vec![first_priv_key.clone()]
                )
                .err(),
            Some(ChainError::AuthorizationError(
                "transaction declares authority 'alice@first' but does not have signatures for it"
                    .into()
            ))
        );
        // Using updated authority, should succeed
        chain.push_reqauth2(
            name!("alice").into(),
            vec![PermissionLevel::new(
                name!("alice").into(),
                name!("first").into(),
            )],
            vec![second_priv_key.clone()],
        )?;
        Ok(())
    }

    /// Regression for the re-entrant permission fix in #13.
    ///
    ///   alice@active = threshold 1, accounts[bob@active, carol@active]
    ///   bob@active   = threshold 1, accounts[alice@active]  (back-edge)
    ///   carol@active = default single-key authority
    ///
    /// Declaring alice@active signed by carol's key: bob@active sorts before
    /// carol@active, so the bob branch is evaluated first and re-enters
    /// alice@active while it is still `BeingEvaluated`. nodeos's
    /// weight_tally_visitor tallies that re-entry as weight 0 and moves on to
    /// the sibling carol branch, which satisfies the threshold — so the
    /// transaction must succeed. Failing the whole authorization on the
    /// back-edge instead rejects satisfiable multi-path authorities.
    #[tokio::test]
    async fn test_reentrant_permission_contributes_zero_weight() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        let bob: Name = name!("bob").into();
        let carol: Name = name!("carol").into();
        chain.create_accounts(vec![alice, bob, carol], false, true)?;

        // bob@active = threshold 1, accounts[alice@active] — the back-edge.
        chain.set_authority2(
            bob,
            ACTIVE_NAME.into(),
            Authority::new(
                1,
                vec![],
                vec![PermissionLevelWeight::new(
                    PermissionLevel::new(alice.as_u64(), ACTIVE_NAME.as_u64()),
                    1,
                )],
                vec![],
            ),
            OWNER_NAME.into(),
        )?;

        // alice@active = threshold 1, accounts[bob@active, carol@active].
        let mut alice_accounts = vec![
            PermissionLevelWeight::new(PermissionLevel::new(bob.as_u64(), ACTIVE_NAME.as_u64()), 1),
            PermissionLevelWeight::new(
                PermissionLevel::new(carol.as_u64(), ACTIVE_NAME.as_u64()),
                1,
            ),
        ];
        alice_accounts.sort_by(|a, b| a.permission.cmp(&b.permission));
        chain.set_authority2(
            alice,
            ACTIVE_NAME.into(),
            Authority::new(1, vec![], alice_accounts, vec![]),
            OWNER_NAME.into(),
        )?;

        // Satisfied via alice@active -> carol@active -> carol's key; the
        // re-entrant bob branch contributes 0 weight instead of failing.
        chain.push_reqauth2(
            alice,
            vec![PermissionLevel::new(alice.as_u64(), ACTIVE_NAME.as_u64())],
            vec![get_private_key(carol, "active")],
        )?;
        Ok(())
    }

    /// A genuinely unsatisfiable cycle — alice@active referencing only itself —
    /// must surface as the ordinary missing-signature authorization failure,
    /// exactly like any other unsatisfied authority, not as a special error.
    #[tokio::test]
    async fn test_true_permission_cycle_is_unsatisfied_not_error() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        chain.create_account(alice, PULSE_NAME.into(), false, true)?;

        chain.set_authority2(
            alice,
            ACTIVE_NAME.into(),
            Authority::new(
                1,
                vec![],
                vec![PermissionLevelWeight::new(
                    PermissionLevel::new(alice.as_u64(), ACTIVE_NAME.as_u64()),
                    1,
                )],
                vec![],
            ),
            OWNER_NAME.into(),
        )?;

        assert_eq!(
            chain
                .push_reqauth2(
                    alice,
                    vec![PermissionLevel::new(alice.as_u64(), ACTIVE_NAME.as_u64())],
                    vec![],
                )
                .err(),
            Some(ChainError::AuthorizationError(
                "transaction declares authority 'alice@active' but does not have signatures for it"
                    .into()
            ))
        );
        Ok(())
    }
}
