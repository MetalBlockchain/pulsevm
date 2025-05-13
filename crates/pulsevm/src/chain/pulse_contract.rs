use pulsevm_chainbase::UndoSession;

use super::{
    ACTIVE_NAME, Account, AccountMetadata, CODE_NAME, NewAccount, OWNER_NAME,
    apply_context::ApplyContext,
    assert_or_err,
    authority::{Authority, Permission, PermissionByOwnerIndex},
    config,
    error::ChainError,
};

pub fn newaccount(context: &mut ApplyContext, session: &mut UndoSession) -> Result<(), ChainError> {
    let create = context
        .get_action()
        .data_as::<NewAccount>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(create.creator)?;
    assert_or_err(
        create.owner.validate(),
        ChainError::TransactionError("invalid owner authority".to_string()),
    )?;
    assert_or_err(
        create.active.validate(),
        ChainError::TransactionError("invalid active authority".to_string()),
    )?;
    let name_str = create.name.to_string();
    assert_or_err(
        !create.name.empty(),
        ChainError::TransactionError("account name cannot be empty".to_string()),
    )?;
    assert_or_err(
        name_str.len() <= 12,
        ChainError::TransactionError("account names can only be 12 chars long".to_string()),
    )?;

    // Check if the creator is privileged
    let creator = session
        .get::<AccountMetadata>(create.creator)
        .map_err(|_| ChainError::TransactionError(format!("failed to find creator account")))?;
    if !creator.is_privileged() {
        assert_or_err(
            !name_str.starts_with("pulse."),
            ChainError::TransactionError(
                "only privileged accounts can have names that start with 'pulse.'".to_string(),
            ),
        )?;
    }
    let existing_account = session
        .find::<Account>(create.name)
        .map_err(|_| ChainError::TransactionError(format!("failed to find account")))?;
    assert_or_err(
        existing_account.is_none(),
        ChainError::TransactionError(format!(
            "cannot create account named {}, as that name is already taken",
            create.name
        )),
    )?;
    session
        .insert(&Account::new(create.name, 0, vec![]))
        .map_err(|_| ChainError::TransactionError(format!("failed to insert account")))?;
    session
        .insert(&AccountMetadata::new(create.name))
        .map_err(|_| ChainError::TransactionError(format!("failed to insert account metadata")))?;

    validate_authority_precondition(session, &create.owner)?;
    validate_authority_precondition(session, &create.active)?;

    let owner_permission = context
        .controller
        .get_authorization_manager()
        .create_permission(session, create.name, OWNER_NAME, 0, create.owner)?;
    let active_permission = context
        .controller
        .get_authorization_manager()
        .create_permission(
            session,
            create.name,
            ACTIVE_NAME,
            owner_permission.id(),
            create.active,
        )?;

    context
        .controller
        .get_resource_limits_manager()
        .initialize_account(session, create.name)?;

    let mut ram_delta: i64 = config::OVERHEAD_PER_ACCOUNT_RAM_BYTES as i64;
    ram_delta += 2 * config::billable_size_v::<Permission>() as i64;
    ram_delta += owner_permission.authority.get_billable_size() as i64;
    ram_delta += active_permission.authority.get_billable_size() as i64;

    context.add_ram_usage(create.name, ram_delta);

    Ok(())
}

fn validate_authority_precondition(
    session: &mut UndoSession,
    auth: &Authority,
) -> Result<(), ChainError> {
    for a in auth.accounts() {
        let account = session
            .find::<Account>(a.permission().actor())
            .map_err(|_| ChainError::TransactionError(format!("failed to query db",)))?;
        assert_or_err(
            account.is_some(),
            ChainError::TransactionError(format!(
                "account {} does not exist",
                a.permission().actor()
            )),
        )?;

        if a.permission().permission() == OWNER_NAME || a.permission().permission() == ACTIVE_NAME {
            continue; // account was already checked to exist, so its owner and active permissions should exist
        }

        if a.permission().permission() == CODE_NAME {
            continue; // virtual pulse.code permission does not really exist but is allowed
        }

        let permission = session
            .find_by_secondary::<Permission, PermissionByOwnerIndex>((
                a.permission().actor(),
                a.permission().permission(),
            ))
            .map_err(|_| {
                ChainError::TransactionError(format!(
                    "failed to query db for permission {}",
                    a.permission().permission()
                ))
            })?;
        assert_or_err(
            permission.is_some(),
            ChainError::TransactionError(format!("permission {} does not exist", a.permission())),
        )?;
    }
    Ok(())
}
