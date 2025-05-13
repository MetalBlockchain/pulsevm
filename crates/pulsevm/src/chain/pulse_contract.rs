use pulsevm_chainbase::UndoSession;
use sha2::{
    Digest, Sha256,
    digest::{consts::U32, generic_array::GenericArray},
};

use super::{
    ACTIVE_NAME, Account, AccountMetadata, CODE_NAME, CodeObject, Id, NewAccount, OWNER_NAME,
    SetAbi, SetCode,
    apply_context::ApplyContext,
    authority::{Authority, Permission, PermissionByOwnerIndex},
    config,
    error::ChainError,
    pulse_assert, zero_hash,
};

pub fn newaccount(context: &mut ApplyContext, session: &mut UndoSession) -> Result<(), ChainError> {
    let create = context
        .get_action()
        .data_as::<NewAccount>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(create.creator)?;
    pulse_assert(
        create.owner.validate(),
        ChainError::TransactionError("invalid owner authority".to_string()),
    )?;
    pulse_assert(
        create.active.validate(),
        ChainError::TransactionError("invalid active authority".to_string()),
    )?;
    let name_str = create.name.to_string();
    pulse_assert(
        !create.name.empty(),
        ChainError::TransactionError("account name cannot be empty".to_string()),
    )?;
    pulse_assert(
        name_str.len() <= 12,
        ChainError::TransactionError("account names can only be 12 chars long".to_string()),
    )?;

    // Check if the creator is privileged
    let creator = session
        .get::<AccountMetadata>(create.creator)
        .map_err(|_| ChainError::TransactionError(format!("failed to find creator account")))?;
    if !creator.is_privileged() {
        pulse_assert(
            !name_str.starts_with("pulse."),
            ChainError::TransactionError(
                "only privileged accounts can have names that start with 'pulse.'".to_string(),
            ),
        )?;
    }
    let existing_account = session
        .find::<Account>(create.name)
        .map_err(|_| ChainError::TransactionError(format!("failed to find account")))?;
    pulse_assert(
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

pub fn setcode(context: &mut ApplyContext, session: &mut UndoSession) -> Result<(), ChainError> {
    let act = context
        .get_action()
        .data_as::<SetCode>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(act.account)?;

    pulse_assert(
        act.vm_type == 0,
        ChainError::TransactionError(format!("code should be 0")),
    )?;
    pulse_assert(
        act.vm_version == 0,
        ChainError::TransactionError(format!("version should be 0")),
    )?;

    let mut code_hash: Id = Id::default();
    let code_size = act.code.len() as u64;

    if code_size > 0 {
        code_hash = Id::from_sha256(act.code.as_slice());
        // TODO: validate wasm
    }

    let mut account = session
        .get::<AccountMetadata>(act.account)
        .map_err(|_| ChainError::TransactionError(format!("failed to find account")))?;
    let existing_code = account.code_hash != Id::default();

    pulse_assert(
        code_size > 0 || existing_code,
        ChainError::TransactionError(format!("contract is already cleared")),
    )?;

    let mut old_size = 0i64;
    let new_size: i64 = code_size as i64 * config::SETCODE_RAM_BYTES_MULTIPLIER as i64;

    if existing_code {
        let mut old_code_entry = session
            .get::<CodeObject>(account.code_hash.clone())
            .map_err(|_| ChainError::TransactionError(format!("failed to find code")))?;
        pulse_assert(
            old_code_entry.code_hash != code_hash,
            ChainError::TransactionError(format!(
                "contract is already running this version of code"
            )),
        )?;

        old_size = old_code_entry.code.len() as i64 * config::SETCODE_RAM_BYTES_MULTIPLIER as i64;

        if old_code_entry.code_ref_count == 1 {
            session
                .remove::<CodeObject>(old_code_entry)
                .map_err(|_| ChainError::TransactionError(format!("failed to remove code")))?;
        } else {
            session
                .modify(&mut old_code_entry, |code| {
                    code.code_ref_count -= 1;
                })
                .map_err(|_| ChainError::TransactionError(format!("failed to update code")))?;
        }
    }

    if code_size > 0 {
        let new_code_entry = session
            .find::<CodeObject>(code_hash.clone())
            .map_err(|_| ChainError::TransactionError(format!("failed to find code")))?;

        if new_code_entry.is_some() {
            let mut new_code_entry = new_code_entry.unwrap();
            session
                .modify(&mut new_code_entry, |code| {
                    code.code_ref_count += 1;
                })
                .map_err(|_| {
                    ChainError::TransactionError(format!("failed to update code reference count"))
                })?;
        } else {
            let new_code_entry = CodeObject {
                code_hash: code_hash.clone(),
                code: act.code.clone(),
                code_ref_count: 1,
                first_block_used: 0, // TODO: set to current block number
                vm_type: act.vm_type,
                vm_version: act.vm_version,
            };
            session
                .insert(&new_code_entry)
                .map_err(|_| ChainError::TransactionError(format!("failed to insert code")))?;
        }
    }

    session
        .modify(&mut account, |a| {
            a.code_sequence += 1;
            a.code_hash = code_hash.clone();
            a.vm_type = act.vm_type;
            a.vm_version = act.vm_version;
            // TODO: a.last_code_update = current_block_number;
        })
        .map_err(|_| ChainError::TransactionError(format!("failed to update account")))?;

    if new_size != old_size {
        context.add_ram_usage(act.account, new_size - old_size);
    }

    Ok(())
}

pub fn setabi(context: &mut ApplyContext, session: &mut UndoSession) -> Result<(), ChainError> {
    let act = context
        .get_action()
        .data_as::<SetAbi>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(act.account)?;

    let mut account = session
        .get::<Account>(act.account)
        .map_err(|_| ChainError::TransactionError(format!("failed to find account")))?;

    let old_size: i64 = account.abi.len() as i64;
    let new_size: i64 = act.abi.len() as i64;

    session
        .modify(&mut account, |a| {
            a.abi = act.abi.clone();
        })
        .map_err(|_| ChainError::TransactionError(format!("failed to update account")))?;

    let mut account_metadata = session
        .get::<AccountMetadata>(act.account)
        .map_err(|_| ChainError::TransactionError(format!("failed to find account")))?;
    session
        .modify(&mut account_metadata, |a| {
            a.abi_sequence += 1;
        })
        .map_err(|_| ChainError::TransactionError(format!("failed to update account metadata")))?;

    if new_size != old_size {
        context.add_ram_usage(act.account, new_size - old_size);
    }

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
        pulse_assert(
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
        pulse_assert(
            permission.is_some(),
            ChainError::TransactionError(format!("permission {} does not exist", a.permission())),
        )?;
    }
    Ok(())
}
