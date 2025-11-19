#[cfg(test)]
mod auth_tests {
    use anyhow::Result;
    use pulsevm_core::{
        authority::{
            Authority, Permission, PermissionByOwnerIndex, PermissionLevel, PermissionLevelWeight,
        }, authorization_manager::AuthorizationManager, error::ChainError, name::{self, Name}, secp256k1::PublicKey, ACTIVE_NAME, OWNER_NAME, PULSE_NAME
    };
    use pulsevm_proc_macros::name;

    use crate::tests::{Testing, get_private_key};

    #[test]
    fn test_missing_sigs() -> Result<()> {
        let mut chain = Testing::new();
        chain.create_accounts(vec![name!("alice").into()], false, true)?;
        assert_eq!(
            chain
                .push_reqauth2(
                    name!("alice").into(),
                    vec![PermissionLevel::new(name!("alice").into(), ACTIVE_NAME)],
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
        chain.create_account(name!("alice").into(), PULSE_NAME, true, true)?;
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
                    vec![PermissionLevel::new(name!("bob").into(), ACTIVE_NAME)],
                    vec![get_private_key(name!("bob").into(), "active")],
                )
                .err(),
            Some(ChainError::MissingAuthError(
                "missing authority of alice".into()
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
                (name!("bob").into(), ACTIVE_NAME).into(),
                1,
            )],
            vec![],
        );
        chain.set_authority2(
            name!("alice").into(),
            ACTIVE_NAME,
            delegated_auth.clone(),
            OWNER_NAME,
        )?;
        let pending_block_state = chain.get_pending_block_state();
        let mut undo_session = pending_block_state.undo_session.clone();
        let new_auth = AuthorizationManager::get_permission(
            &mut undo_session,
            &(name!("alice").into(), ACTIVE_NAME).into(),
        )?
        .authority;
        assert!(new_auth == delegated_auth);
        // execute nonce from alice signed by bob
        chain.push_reqauth2(
            name!("alice").into(),
            vec![PermissionLevel::new(name!("alice").into(), ACTIVE_NAME)],
            vec![get_private_key(name!("bob").into(), "active")],
        )?;
        Ok(())
    }

    #[test]
    fn test_update_auths() -> Result<()> {
        let mut chain = Testing::new();
        chain.create_account(name!("alice").into(), PULSE_NAME, false, true)?;
        chain.create_account(name!("bob").into(), PULSE_NAME, false, true)?;
        // Deleting active or owner should fail
        assert_eq!(
            chain
                .delete_authority2(name!("alice").into(), ACTIVE_NAME)
                .err(),
            Some(ChainError::ActionValidationError(format!(
                "cannot delete active authority"
            )))
        );
        assert_eq!(
            chain
                .delete_authority2(name!("alice").into(), OWNER_NAME)
                .err(),
            Some(ChainError::ActionValidationError(format!(
                "cannot delete owner authority"
            )))
        );

        // Change owner permission
        let new_owner_priv_key = get_private_key(name!("alice").into(), "new_owner");
        let new_owner_pub_key = new_owner_priv_key.public_key();
        chain.set_authority2(
            name!("alice").into(),
            OWNER_NAME,
            Authority::new_from_public_key(new_owner_pub_key.clone()),
            Name::default(),
        )?;

        // Ensure the permission is updated
        let pending_block_state = chain.get_pending_block_state();
        let mut undo_session = pending_block_state.undo_session.clone();
        let obj = undo_session.find_by_secondary::<Permission, PermissionByOwnerIndex>((
            name!("alice").into(),
            OWNER_NAME,
        ))?;
        assert!(obj.is_some());
        let obj = obj.unwrap();
        let owner_id = obj.id;
        assert!(obj.owner == name!("alice"));
        assert!(obj.name == OWNER_NAME);
        assert!(obj.parent == 0);
        assert!(obj.authority.threshold == 1);
        assert!(obj.authority.keys.len() == 1);
        assert!(obj.authority.accounts.len() == 0);
        assert!(obj.authority.keys[0].key().to_string() == new_owner_pub_key.to_string());
        assert!(obj.authority.keys[0].key().clone() == new_owner_pub_key);
        assert!(obj.authority.keys[0].weight() == 1);

        // Change active permission, remember that the owner key has been changed
        let new_active_priv_key = get_private_key(name!("alice").into(), "new_active");
        let new_active_pub_key = new_active_priv_key.public_key();
        chain.set_authority(
            name!("alice").into(),
            ACTIVE_NAME,
            Authority::new_from_public_key(new_active_pub_key.clone()),
            OWNER_NAME,
            vec![PermissionLevel::new(name!("alice").into(), ACTIVE_NAME)],
            vec![get_private_key(name!("alice").into(), "active")],
        )?;

        let obj = undo_session.find_by_secondary::<Permission, PermissionByOwnerIndex>((
            name!("alice").into(),
            ACTIVE_NAME,
        ))?;
        assert!(obj.is_some());
        let obj = obj.unwrap();
        assert!(obj.owner == name!("alice"));
        assert!(obj.name == ACTIVE_NAME);
        assert!(obj.parent == owner_id);
        assert!(obj.authority.threshold == 1);
        assert!(obj.authority.keys.len() == 1);
        assert!(obj.authority.accounts.len() == 0);
        assert!(obj.authority.keys[0].key().clone() == new_active_pub_key);
        assert!(obj.authority.keys[0].weight() == 1);

        let spending_priv_key = get_private_key(name!("alice").into(), "spending");
        let spending_pub_key = spending_priv_key.public_key();
        let trading_priv_key = get_private_key(name!("alice").into(), "trading");
        let trading_pub_key = trading_priv_key.public_key();

        // Bob attempts to create new spending auth for Alice
        assert_eq!(
            chain
                .set_authority(
                    name!("alice").into(),
                    name!("spending").into(),
                    Authority::new_from_public_key(spending_pub_key.clone()),
                    ACTIVE_NAME,
                    vec![PermissionLevel::new(name!("bob").into(), ACTIVE_NAME)],
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
            Authority::new_from_public_key(spending_pub_key.clone()),
            ACTIVE_NAME,
            vec![PermissionLevel::new(name!("alice").into(), ACTIVE_NAME)],
            vec![new_active_priv_key.clone()],
        )?;
        let obj = undo_session.find_by_secondary::<Permission, PermissionByOwnerIndex>((
            name!("alice").into(),
            name!("spending").into(),
        ))?;
        assert!(obj.is_some());
        let obj = obj.unwrap();
        assert!(obj.owner == name!("alice"));
        assert!(obj.name == name!("spending"));
        let parent = undo_session.get::<Permission>(obj.parent)?;
        assert!(parent.owner == name!("alice"));
        assert!(parent.name == ACTIVE_NAME);

        // Update spending auth parent to be its own, should fail
        assert_eq!(
            chain
                .set_authority(
                    name!("alice").into(),
                    name!("spending").into(),
                    Authority::new_from_public_key(spending_pub_key.clone()),
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
                    Authority::new_from_public_key(spending_pub_key.clone()),
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
        chain.delete_authority(name!("alice").into(), name!("spending").into(), vec![
            PermissionLevel::new(name!("alice").into(), ACTIVE_NAME)
        ], vec![
            new_active_priv_key.clone()
        ])?;
        let obj = undo_session.find_by_secondary::<Permission, PermissionByOwnerIndex>((
            name!("alice").into(),
            name!("spending").into(),
        ))?;
        assert!(obj.is_none());

        // Create new trading auth
        chain.set_authority(
            name!("alice").into(),
            name!("trading").into(),
            Authority::new_from_public_key(trading_pub_key.clone()),
            ACTIVE_NAME,
            vec![PermissionLevel::new(name!("alice").into(), ACTIVE_NAME)],
            vec![new_active_priv_key.clone()],
        )?;

        // Recreate spending auth again, however this time, it's under trading instead of owner
        chain.set_authority(
            name!("alice").into(),
            name!("spending").into(),
            Authority::new_from_public_key(spending_pub_key.clone()),
            name!("trading").into(),
            vec![PermissionLevel::new(name!("alice").into(), name!("trading").into())],
            vec![trading_priv_key.clone()],
        )?;

        // Verify correctness of trading and spending
        let trading = undo_session.find_by_secondary::<Permission, PermissionByOwnerIndex>((
            name!("alice").into(),
            name!("trading").into(),
        ))?;
        let spending = undo_session.find_by_secondary::<Permission, PermissionByOwnerIndex>((
            name!("alice").into(),
            name!("spending").into(),
        ))?;
        assert!(trading.is_some());
        assert!(spending.is_some());
        let trading = trading.unwrap();
        let spending = spending.unwrap();
        assert!(trading.owner == name!("alice"));
        assert!(spending.owner == name!("alice"));
        assert!(trading.name == name!("trading"));
        assert!(spending.name == name!("spending"));
        assert!(spending.parent == trading.id);
        let parent = undo_session.get::<Permission>(trading.parent)?;
        assert!(parent.owner == name!("alice"));
        assert!(parent.name == ACTIVE_NAME);

        // Delete trading, should fail since it has children (spending)
        assert_eq!(chain.delete_authority(name!("alice").into(), name!("trading").into(), vec![
            PermissionLevel::new(name!("alice").into(), ACTIVE_NAME)
        ], vec![
            new_active_priv_key.clone()
        ]).err(), Some(ChainError::ActionValidationError(
            "cannot delete permission 'alice@trading' because it has child permissions".into()
        )));

        // Update trading parent to be spending, should fail since changing parent authority is not supported
        assert_eq!(chain.set_authority(
            name!("alice").into(),
            name!("trading").into(),
            Authority::new_from_public_key(trading_pub_key.clone()),
            name!("spending").into(),
            vec![PermissionLevel::new(name!("alice").into(), name!("trading").into())],
            vec![trading_priv_key.clone()],
        ).err(), Some(ChainError::ActionValidationError(
            "changing parent authority is not currently supported".into()
        )));

        chain.delete_authority(name!("alice").into(), name!("spending").into(), vec![
            PermissionLevel::new(name!("alice").into(), ACTIVE_NAME)
        ], vec![
            new_active_priv_key.clone()
        ])?;
        assert_eq!(undo_session.find_by_secondary::<Permission, PermissionByOwnerIndex>((
            name!("alice").into(),
            name!("spending").into(),
        ))?, None);
        chain.delete_authority(name!("alice").into(), name!("trading").into(), vec![
            PermissionLevel::new(name!("alice").into(), ACTIVE_NAME)
        ], vec![
            new_active_priv_key.clone()
        ])?;
        assert_eq!(undo_session.find_by_secondary::<Permission, PermissionByOwnerIndex>((
            name!("alice").into(),
            name!("trading").into(),
        ))?, None);
        Ok(())
    }

    #[test]
    fn test_update_auth_unknown_private_key() -> Result<()> {
        let mut chain = Testing::new();
        chain.create_account(name!("alice").into(), PULSE_NAME, false, true)?;
        // public key with no corresponding private key
        let new_owner_pub_key = PublicKey::default();
        chain.set_authority2(
            name!("alice").into(),
            OWNER_NAME,
            Authority::new_from_public_key(new_owner_pub_key.clone()),
            Name::default(),
        )?;
        // Ensure the permission is updated
        let pending_block_state = chain.get_pending_block_state();
        let mut undo_session = pending_block_state.undo_session.clone();
        let obj = undo_session.find_by_secondary::<Permission, PermissionByOwnerIndex>((
            name!("alice").into(),
            OWNER_NAME,
        ))?;
        assert!(obj.is_some());
        let obj = obj.unwrap();
        assert!(obj.owner == name!("alice"));
        assert!(obj.name == OWNER_NAME);
        assert!(obj.parent == 0);
        assert!(obj.authority.threshold == 1);
        assert!(obj.authority.keys.len() == 1);
        assert!(obj.authority.accounts.len() == 0);
        assert!(obj.authority.keys[0].key().clone() == new_owner_pub_key);
        assert!(obj.authority.keys[0].weight() == 1);
        Ok(())
    }
}
