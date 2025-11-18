#[cfg(test)]
mod auth_tests {
    use anyhow::Result;
    use pulsevm_core::{
        ACTIVE_NAME, OWNER_NAME, PULSE_NAME,
        authority::{Authority, PermissionLevel, PermissionLevelWeight},
        authorization_manager::AuthorizationManager,
        error::ChainError,
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
}
