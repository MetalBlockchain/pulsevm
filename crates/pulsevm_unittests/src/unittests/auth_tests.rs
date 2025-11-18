#[cfg(test)]
mod auth_tests {
    use anyhow::Result;
    use pulsevm_core::{ACTIVE_NAME, PULSE_NAME, authority::PermissionLevel, error::ChainError};
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
                "missing authority of alice"
                    .into()
            ))
        );
        Ok(())
    }
}
