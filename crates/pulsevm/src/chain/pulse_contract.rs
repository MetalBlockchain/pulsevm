use pulsevm_chainbase::UndoSession;
use pulsevm_serialization::Write;
use secp256k1::hashes::{Hash, sha256};
use serde::Deserialize;

use crate::chain::{AbiDefinition, AuthorizationManager, resource_limits::ResourceLimitsManager};

use super::{
    ACTIVE_NAME, Account, AccountMetadata, CODE_NAME, CodeObject, DeleteAuth, Id, NewAccount,
    OWNER_NAME, SetAbi, SetCode, UpdateAuth,
    apply_context::ApplyContext,
    authority::{Authority, Permission, PermissionByOwnerIndex, PermissionLevel},
    config,
    error::ChainError,
    pulse_assert,
};

pub fn newaccount(context: &mut ApplyContext) -> Result<(), ChainError> {
    let create = context
        .get_action()
        .data_as::<NewAccount>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(create.creator, None)?;
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
    let mut session = context.undo_session();
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
        .insert(&Account::new(
            create.name,
            context.pending_block_timestamp(),
            vec![],
        ))
        .map_err(|_| ChainError::TransactionError(format!("failed to insert account")))?;
    session
        .insert(&AccountMetadata::new(create.name))
        .map_err(|_| ChainError::TransactionError(format!("failed to insert account metadata")))?;

    validate_authority_precondition(&mut session, &create.owner)?;
    validate_authority_precondition(&mut session, &create.active)?;

    let owner_permission = AuthorizationManager::create_permission(
        &mut session,
        create.name,
        OWNER_NAME,
        0,
        create.owner,
    )?;
    let active_permission = AuthorizationManager::create_permission(
        &mut session,
        create.name,
        ACTIVE_NAME,
        owner_permission.id(),
        create.active,
    )?;

    ResourceLimitsManager::initialize_account(&mut session, create.name)?;

    let mut ram_delta: i64 = config::OVERHEAD_PER_ACCOUNT_RAM_BYTES as i64;
    ram_delta += 2 * config::billable_size_v::<Permission>() as i64;
    ram_delta += owner_permission.authority.get_billable_size() as i64;
    ram_delta += active_permission.authority.get_billable_size() as i64;

    context.add_ram_usage(create.name, ram_delta);

    Ok(())
}

pub fn setcode(context: &mut ApplyContext) -> Result<(), ChainError> {
    let act = context
        .get_action()
        .data_as::<SetCode>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(act.account, None)?;

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
        let digest = sha256::Hash::hash(act.code.as_slice());
        code_hash = Id::from_sha256(&digest);
        // TODO: validate wasm
    }

    let mut session = context.undo_session();
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

pub fn setabi(context: &mut ApplyContext) -> Result<(), ChainError> {
    let mut session = context.undo_session();
    let act = context
        .get_action()
        .data_as::<SetAbi>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(act.account, None)?;

    let mut account = session
        .get::<Account>(act.account)
        .map_err(|_| ChainError::TransactionError(format!("failed to find account")))?;
    let abi_def: AbiDefinition = serde_json::from_str(std::str::from_utf8(&act.abi).unwrap())
        .map_err(|e| ChainError::InvalidArgument(format!("failed to deserialize ABI: {}", e)))?;
    let abi_def_packed = abi_def
        .pack()
        .map_err(|e| ChainError::TransactionError(format!("failed to serialize ABI: {}", e)))?;
    let old_size: i64 = account.abi.len() as i64;
    let new_size: i64 = abi_def_packed.len() as i64;

    session
        .modify(&mut account, |a| {
            a.abi = abi_def_packed.clone();
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
        //context.add_ram_usage(act.account, new_size - old_size);
    }

    Ok(())
}

pub fn updateauth(context: &mut ApplyContext) -> Result<(), ChainError> {
    let update = context
        .get_action()
        .data_as::<UpdateAuth>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(update.account, None)?;

    pulse_assert(
        !update.permission.empty(),
        ChainError::TransactionError(format!("cannot create authority with empty name")),
    )?;
    pulse_assert(
        !update.permission.to_string().starts_with("pulse."),
        ChainError::TransactionError(format!(
            "permission names that start with 'pulse.' are reserved"
        )),
    )?;
    pulse_assert(
        update.permission != update.parent,
        ChainError::TransactionError(format!("cannot set an authority as its own parent")),
    )?;

    let mut session = context.undo_session();

    session.get::<Account>(update.account).map_err(|_| {
        ChainError::TransactionError(format!("failed to find account {}", update.account))
    })?;

    pulse_assert(
        update.auth.validate(),
        ChainError::TransactionError(format!("invalid authority: {}", update.auth)),
    )?;

    if update.permission == ACTIVE_NAME {
        pulse_assert(
            update.parent == OWNER_NAME,
            ChainError::TransactionError(format!(
                "cannot change active authority's parent from owner"
            )),
        )?;
    } else if update.permission == OWNER_NAME {
        pulse_assert(
            update.parent.empty(),
            ChainError::TransactionError(format!("cannot change owner authority's parent")),
        )?;
    } else {
        pulse_assert(
            !update.permission.empty(),
            ChainError::TransactionError(format!("only owner permission can have empty parent")),
        )?;
    }

    validate_authority_precondition(&mut session, &update.auth)?;

    let permission = AuthorizationManager::find_permission(
        &mut session,
        &PermissionLevel::new(update.account, update.permission),
    )?;

    let mut parent_id = 0u64;
    if (update.permission != OWNER_NAME) {
        let parent = AuthorizationManager::get_permission(
            &mut session,
            &PermissionLevel::new(update.account, update.parent),
        )?;
        parent_id = parent.id();
    }

    if permission.is_some() {
        let mut permission = permission.unwrap();
        pulse_assert(
            parent_id == permission.parent_id(),
            ChainError::TransactionError(format!(
                "changing parent authority is not currently supported"
            )),
        )?;

        let old_size: i64 = config::billable_size_v::<Permission>() as i64
            + permission.authority.get_billable_size() as i64;
        AuthorizationManager::modify_permission(&mut session, &mut permission, &update.auth)?;
        let new_size: i64 = config::billable_size_v::<Permission>() as i64
            + permission.authority.get_billable_size() as i64;

        context.add_ram_usage(permission.owner, new_size - old_size);
    } else {
        let p = AuthorizationManager::create_permission(
            &mut session,
            update.account,
            update.permission,
            parent_id,
            update.auth,
        )?;

        let new_size: i64 =
            config::billable_size_v::<Permission>() as i64 + p.authority.get_billable_size() as i64;

        context.add_ram_usage(update.account, new_size);
    }

    Ok(())
}

pub fn deleteauth(context: &mut ApplyContext) -> Result<(), ChainError> {
    let remove = context
        .get_action()
        .data_as::<DeleteAuth>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(remove.account, None)?;

    pulse_assert(
        remove.permission != ACTIVE_NAME,
        ChainError::TransactionError(format!("cannot delete active authority")),
    )?;
    pulse_assert(
        remove.permission != OWNER_NAME,
        ChainError::TransactionError(format!("cannot delete owner authority")),
    )?;

    //let authorization = controller.get_authorization_manager();

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
