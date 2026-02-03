#[cfg(test)]
mod auth_tests {
    use anyhow::Result;
    use pulsevm_core::{
        ACTIVE_NAME, ChainError, OWNER_NAME, PULSE_NAME,
        authority::{self, Authority, PermissionLevel, PermissionLevelWeight},
        authorization_manager::AuthorizationManager,
        crypto::PublicKey,
        name::Name,
    };

    use crate::tests::{Testing, get_private_key};
    use pulsevm_name_macro::name;

    #[test]
    fn test_missing_sigs() -> Result<()> {
        let mut chain = Testing::new();
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

    #[test]
    fn test_missing_multi_sigs() -> Result<()> {
        let mut chain = Testing::new();
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

    #[test]
    fn test_missing_auths() -> Result<()> {
        let mut chain = Testing::new();
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
            Some(ChainError::WasmRuntimeError(
                "apply error: RuntimeError: missing authority of alice".into()
            ))
        );
        Ok(())
    }

    #[test]
    fn test_delegate_auth() -> Result<()> {
        let mut chain = Testing::new();
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
        let new_auth = AuthorizationManager::get_permission(
            &mut pending_block_state.db.clone(),
            name!("alice"),
            ACTIVE_NAME.as_u64(),
        )?;
        assert!(new_auth.get_authority().to_authority() == delegated_auth);
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

    #[test]
    fn test_update_auths() -> Result<()> {
        let mut chain = Testing::new();
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
            Authority::new_from_public_key(new_owner_pub_key.inner()),
            Name::default(),
        )?;

        // Ensure the permission is updated
        let pending_block_state = chain.get_pending_block_state();
        let obj = pending_block_state
            .db
            .find_permission_by_actor_and_permission(name!("alice"), OWNER_NAME.as_u64())?;
        assert!(!obj.is_null());
        let obj = unsafe { obj.as_ref().unwrap() };
        let owner_id = obj.get_id();
        assert!(obj.get_owner().to_uint64_t() == name!("alice"));
        assert!(obj.get_name().to_uint64_t() == OWNER_NAME);
        assert!(obj.get_parent_id() == 0);
        let authority = obj.get_authority().to_authority();
        assert!(authority.threshold == 1);
        assert!(authority.keys.len() == 1);
        assert!(authority.accounts.len() == 0);
        assert!(authority.keys[0].key.to_string() == new_owner_pub_key.to_string());
        assert!(authority.keys[0].weight == 1);

        // Change active permission, remember that the owner key has been changed
        let new_active_priv_key = get_private_key(name!("alice").into(), "new_active");
        let new_active_pub_key = new_active_priv_key.get_public_key();
        chain.set_authority(
            name!("alice").into(),
            ACTIVE_NAME,
            Authority::new_from_public_key(new_active_pub_key.inner()),
            OWNER_NAME,
            vec![PermissionLevel::new(
                name!("alice").into(),
                ACTIVE_NAME.as_u64(),
            )],
            vec![get_private_key(name!("alice").into(), "active")],
        )?;

        let obj = pending_block_state
            .db
            .find_permission_by_actor_and_permission(name!("alice"), ACTIVE_NAME.as_u64())?;
        assert!(!obj.is_null());
        let obj = unsafe { obj.as_ref().unwrap() };
        assert!(obj.get_owner().to_uint64_t() == name!("alice"));
        assert!(obj.get_name().to_uint64_t() == ACTIVE_NAME);
        assert!(obj.get_parent_id() == owner_id);
        let authority = obj.get_authority().to_authority();
        assert!(authority.threshold == 1);
        assert!(authority.keys.len() == 1);
        assert!(authority.accounts.len() == 0);
        assert!(authority.keys[0].key.to_string_rust() == new_active_pub_key.to_string());
        assert!(authority.keys[0].weight == 1);

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
                    Authority::new_from_public_key(spending_pub_key.inner()),
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
            Authority::new_from_public_key(spending_pub_key.inner()),
            ACTIVE_NAME,
            vec![PermissionLevel::new(
                name!("alice").into(),
                ACTIVE_NAME.as_u64(),
            )],
            vec![new_active_priv_key.clone()],
        )?;
        let obj = pending_block_state
            .db
            .find_permission_by_actor_and_permission(name!("alice"), name!("spending"))?;
        assert!(!obj.is_null());
        let obj = unsafe { obj.as_ref().unwrap() };
        assert!(obj.get_owner().to_uint64_t() == name!("alice"));
        assert!(obj.get_name().to_uint64_t() == name!("spending"));
        let parent = pending_block_state
            .db
            .find_permission(obj.get_parent_id())?;
        assert!(!parent.is_null());
        let parent = unsafe { parent.as_ref().unwrap() };
        assert!(parent.get_owner().to_uint64_t() == name!("alice"));
        assert!(parent.get_name().to_uint64_t() == ACTIVE_NAME);

        // Update spending auth parent to be its own, should fail
        assert_eq!(
            chain
                .set_authority(
                    name!("alice").into(),
                    name!("spending").into(),
                    Authority::new_from_public_key(spending_pub_key.inner()),
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
                    Authority::new_from_public_key(spending_pub_key.inner()),
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
        let obj = pending_block_state
            .db
            .find_permission_by_actor_and_permission(name!("alice"), name!("spending"))?;
        assert!(obj.is_null());

        // Create new trading auth
        chain.set_authority(
            name!("alice").into(),
            name!("trading").into(),
            Authority::new_from_public_key(trading_pub_key.inner()),
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
            Authority::new_from_public_key(spending_pub_key.inner()),
            name!("trading").into(),
            vec![PermissionLevel::new(
                name!("alice").into(),
                name!("trading").into(),
            )],
            vec![trading_priv_key.clone()],
        )?;

        // Verify correctness of trading and spending
        let trading = pending_block_state
            .db
            .find_permission_by_actor_and_permission(name!("alice"), name!("trading"))?;
        let spending = pending_block_state
            .db
            .find_permission_by_actor_and_permission(name!("alice"), name!("spending"))?;
        assert!(!trading.is_null());
        assert!(!spending.is_null());
        let trading = unsafe { trading.as_ref().unwrap() };
        let spending = unsafe { spending.as_ref().unwrap() };
        assert!(trading.get_owner().to_uint64_t() == name!("alice"));
        assert!(spending.get_owner().to_uint64_t() == name!("alice"));
        assert!(trading.get_name().to_uint64_t() == name!("trading"));
        assert!(spending.get_name().to_uint64_t() == name!("spending"));
        assert!(spending.get_parent_id() == trading.get_id());
        let parent = pending_block_state
            .db
            .find_permission(trading.get_parent_id())?;
        assert!(!parent.is_null());
        let parent = unsafe { parent.as_ref().unwrap() };
        assert!(parent.get_owner().to_uint64_t() == name!("alice"));
        assert!(parent.get_name().to_uint64_t() == ACTIVE_NAME);

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

        // Update trading parent to be spending, should fail since changing parent authority is not supported
        assert_eq!(
            chain
                .set_authority(
                    name!("alice").into(),
                    name!("trading").into(),
                    Authority::new_from_public_key(trading_pub_key.inner()),
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
        let res = pending_block_state
            .db
            .find_permission_by_actor_and_permission(name!("alice"), name!("spending"))?;
        assert!(res.is_null());
        chain.delete_authority(
            name!("alice").into(),
            name!("trading").into(),
            vec![PermissionLevel::new(
                name!("alice").into(),
                ACTIVE_NAME.as_u64(),
            )],
            vec![new_active_priv_key.clone()],
        )?;
        let res = pending_block_state
            .db
            .find_permission_by_actor_and_permission(name!("alice"), name!("trading"))?;
        assert!(res.is_null());
        Ok(())
    }

    #[test]
    fn test_update_auth_unknown_private_key() -> Result<()> {
        let mut chain = Testing::new();
        chain.create_account(name!("alice").into(), PULSE_NAME, false, true)?;
        // public key with no corresponding private key
        let new_owner_pub_key = PublicKey::new_unknown();
        chain.set_authority2(
            name!("alice").into(),
            OWNER_NAME,
            Authority::new_from_public_key(new_owner_pub_key.inner()),
            Name::default(),
        )?;
        // Ensure the permission is updated
        let pending_block_state = chain.get_pending_block_state();
        let obj = pending_block_state
            .db
            .find_permission_by_actor_and_permission(name!("alice"), OWNER_NAME.as_u64())?;
        assert!(!obj.is_null());
        let obj = unsafe { obj.as_ref().unwrap() };
        assert!(obj.get_owner().to_uint64_t() == name!("alice"));
        assert!(obj.get_name().to_uint64_t() == OWNER_NAME.as_u64());
        assert!(obj.get_parent_id() == 0);
        let authority = obj.get_authority().to_authority();
        assert!(authority.threshold == 1);
        assert!(authority.keys.len() == 1);
        assert!(authority.accounts.len() == 0);
        assert!(authority.keys[0].key.to_string_rust() == new_owner_pub_key.to_string());
        assert!(authority.keys[0].weight == 1);
        Ok(())
    }

    #[test]
    fn test_link_auths() -> Result<()> {
        let mut chain = Testing::new();
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
            Authority::new_from_public_key(spending_pub_key.inner()),
            ACTIVE_NAME,
        )?;
        chain.set_authority2(
            name!("alice").into(),
            name!("scud").into(),
            Authority::new_from_public_key(scud_pub_key.inner()),
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
        // req auth action with alice's spending key should also be fine, since it is the parent of alice's scud key
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

    #[test]
    fn test_link_then_update_auth() -> Result<()> {
        let mut chain = Testing::new();
        chain.create_account(name!("alice").into(), PULSE_NAME, false, true)?;

        let first_priv_key = get_private_key(name!("alice").into(), "first");
        let first_pub_key = first_priv_key.get_public_key();
        let second_priv_key = get_private_key(name!("alice").into(), "second");
        let second_pub_key = second_priv_key.get_public_key();

        chain.set_authority2(
            name!("alice").into(),
            name!("first").into(),
            Authority::new_from_public_key(first_pub_key.inner()),
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
            Authority::new_from_public_key(second_pub_key.inner()),
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
}
