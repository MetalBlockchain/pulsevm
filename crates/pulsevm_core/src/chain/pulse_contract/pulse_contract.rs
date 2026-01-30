use core::panic;

use pulsevm_billable_size::billable_size_v;
use pulsevm_constants::{OVERHEAD_PER_ACCOUNT_RAM_BYTES, SETCODE_RAM_BYTES_MULTIPLIER};
use pulsevm_error::ChainError;
use pulsevm_ffi::{CxxDigest, Database, PermissionObject};
use pulsevm_serialization::Write;

use crate::{
    ACTIVE_NAME, CODE_NAME, OWNER_NAME,
    chain::{
        abi::AbiDefinition,
        apply_context::ApplyContext,
        authority::{Authority, PermissionLevel},
        authorization_manager::AuthorizationManager,
        pulse_contract::pulse_contract_types::{DeleteAuth, LinkAuth, NewAccount, SetAbi, SetCode, UnlinkAuth, UpdateAuth},
        resource_limits::ResourceLimitsManager,
        utils::pulse_assert,
    },
    transaction::Action,
};

pub fn newaccount(context: &mut ApplyContext, db: &mut Database, act: &Action) -> Result<(), ChainError> {
    let create = act
        .data_as::<NewAccount>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(&create.creator, None)?;
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
    let creator = db.find_account_metadata(create.creator.as_u64())?;
    let creator = unsafe { &*creator };

    if !creator.is_privileged() {
        pulse_assert(
            !name_str.starts_with("pulse."),
            ChainError::TransactionError("only privileged accounts can have names that start with 'pulse.'".to_string()),
        )?;
    }

    let existing_account = db.find_account(create.name.as_u64())?;
    pulse_assert(
        existing_account.is_null(),
        ChainError::TransactionError(format!("cannot create account named {}, as that name is already taken", create.name)),
    )?;

    db.create_account(create.name.as_u64(), context.pending_block_timestamp().slot())?;
    db.create_account_metadata(create.name.as_u64(), false)?;

    validate_authority_precondition(db, &create.owner)?;
    validate_authority_precondition(db, &create.active)?;

    let owner_permission = unsafe {
        &*AuthorizationManager::create_permission(
            db,
            &create.name,
            &OWNER_NAME.into(),
            0,
            &create.owner.into(),
            context.pending_block_timestamp().to_time_point().as_ref().unwrap(),
        )?
    };
    let active_permission = unsafe { &*AuthorizationManager::create_permission(
        db,
        &create.name,
        &ACTIVE_NAME.into(),
        owner_permission.get_id() as u64,
        &create.active.into(),
        context.pending_block_timestamp().to_time_point().as_ref().unwrap(),
    )? };

    ResourceLimitsManager::initialize_account(db, &create.name)?;

    let mut ram_delta: i64 = OVERHEAD_PER_ACCOUNT_RAM_BYTES as i64;
    ram_delta += 2 * billable_size_v::<PermissionObject>() as i64;
    ram_delta += owner_permission.get_authority().get_billable_size() as i64;
    ram_delta += active_permission.get_authority().get_billable_size() as i64;

    context.add_ram_usage(&create.name, ram_delta)?;

    Ok(())
}

pub fn setcode(context: &mut ApplyContext, db: &mut Database, act: &Action) -> Result<(), ChainError> {
    let act = act
        .data_as::<SetCode>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(&act.account, None)?;

    pulse_assert(act.vm_type == 0, ChainError::TransactionError(format!("code should be 0")))?;
    pulse_assert(act.vm_version == 0, ChainError::TransactionError(format!("version should be 0")))?;

    let mut code_hash = CxxDigest::new_empty();
    let code_size = act.code.len() as u64;

    if code_size > 0 {
        code_hash = CxxDigest::hash(act.code.as_slice())?;
        // TODO: validate wasm
    }

    let account = db.get_account_metadata(act.account.as_u64())?;
    let existing_code = !account.get_code_hash().empty();

    pulse_assert(
        code_size > 0 || existing_code,
        ChainError::TransactionError(format!("contract is already cleared")),
    )?;

    let mut old_size = 0i64;
    let new_size: i64 = code_size as i64 * SETCODE_RAM_BYTES_MULTIPLIER as i64;

    if existing_code {
        let old_code_entry = unsafe { &*db.get_code_object_by_hash(code_hash.as_ref().unwrap(), act.vm_type, act.vm_version)? };
        pulse_assert(
            old_code_entry.get_code_hash() != code_hash.as_ref().unwrap(),
            ChainError::TransactionError(format!("contract is already running this version of code")),
        )?;

        old_size = old_code_entry.get_code().size() as i64 * SETCODE_RAM_BYTES_MULTIPLIER as i64;

        db.unlink_account_code(old_code_entry)?;
    }

    db.update_account_code(
        account,
        act.code.as_slice(),
        context.get_head_block_num() + 1,
        context.get_pending_block_time().to_time_point().as_ref().unwrap(),
        code_hash.as_ref().unwrap(),
        act.vm_type,
        act.vm_version,
    )?;

    if new_size != old_size {
        context.add_ram_usage(&act.account, new_size - old_size)?;
    }

    Ok(())
}

pub fn setabi(context: &mut ApplyContext, db: &mut Database, act: &Action) -> Result<(), ChainError> {
    let act = act
        .data_as::<SetAbi>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(&act.account, None)?;

    let abi_def: AbiDefinition = serde_json::from_str(std::str::from_utf8(act.abi.as_slice()).unwrap())
        .map_err(|e| ChainError::InvalidArgument(format!("failed to deserialize ABI: {}", e)))?;
    let abi_def_packed = abi_def
        .pack()
        .map_err(|e| ChainError::TransactionError(format!("failed to serialize ABI: {}", e)))?;
    let account = db.get_account(act.account.as_u64())?;
    let old_size: i64 = account.get_abi().size() as i64;
    let new_size: i64 = abi_def_packed.len() as i64;
    let account_metadata = db.get_account_metadata(act.account.as_u64())?;

    db.update_account_abi(account, account_metadata, act.abi.as_slice())?;

    if new_size != old_size {
        context.add_ram_usage(&act.account, new_size - old_size)?;
    }

    Ok(())
}

pub fn updateauth(context: &mut ApplyContext, db: &mut Database, act: &Action) -> Result<(), ChainError> {
    let update = act
        .data_as::<UpdateAuth>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(&update.account, None)?;

    pulse_assert(
        !update.permission.empty(),
        ChainError::ActionValidationError(format!("cannot create authority with empty name")),
    )?;
    pulse_assert(
        !update.permission.to_string().starts_with("pulse."),
        ChainError::ActionValidationError(format!("permission names that start with 'pulse.' are reserved")),
    )?;
    pulse_assert(
        update.permission != update.parent,
        ChainError::ActionValidationError(format!("cannot set an authority as its own parent")),
    )?;

    db.get_account(update.account.as_u64())
        .map_err(|_| ChainError::TransactionError(format!("failed to find account {}", update.account)))?;

    pulse_assert(
        update.auth.validate(),
        ChainError::TransactionError(format!("invalid authority: {}", update.auth)),
    )?;

    if update.permission == ACTIVE_NAME {
        pulse_assert(
            update.parent == OWNER_NAME,
            ChainError::TransactionError(format!("cannot change active authority's parent from owner")),
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

    validate_authority_precondition(db, &update.auth)?;

    let permission = AuthorizationManager::find_permission(db, &PermissionLevel::new(update.account.as_u64(), update.permission.as_u64()))?;

    let mut parent_id = 0i64;
    if update.permission != OWNER_NAME {
        let parent = AuthorizationManager::get_permission(db, update.account.as_u64(), update.parent.as_u64())?;
        parent_id = parent.get_id();
    }

    if permission.is_some() {
        let permission = permission.unwrap();
        pulse_assert(
            parent_id == permission.get_parent_id(),
            ChainError::ActionValidationError(format!("changing parent authority is not currently supported")),
        )?;

        let old_size: i64 = billable_size_v::<PermissionObject>() as i64
            + permission.get_authority().get_billable_size() as i64;
        AuthorizationManager::modify_permission(db, permission, &update.auth, &context.get_pending_block_time().to_time_point())?;
        let new_size: i64 = billable_size_v::<PermissionObject>() as i64
            + permission.get_authority().get_billable_size() as i64;

        context.add_ram_usage(&permission.get_owner().to_uint64_t().into(), new_size - old_size)?;
    } else {
        let permission = unsafe { &*AuthorizationManager::create_permission(
            db,
            &update.account,
            &update.permission,
            parent_id as u64,
            &update.auth.into(),
            context.pending_block_timestamp().to_time_point().as_ref().unwrap(),
        )? };

        let new_size: i64 =
            billable_size_v::<PermissionObject>() as i64 + permission.get_authority().get_billable_size() as i64;

        context.add_ram_usage(&update.account, new_size)?;
    }

    Ok(())
}

pub fn deleteauth(context: &mut ApplyContext, db: &mut Database, act: &Action) -> Result<(), ChainError> {
    let remove = act
        .data_as::<DeleteAuth>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(&remove.account, None)?;

    pulse_assert(
        remove.permission != ACTIVE_NAME,
        ChainError::ActionValidationError(format!("cannot delete active authority")),
    )?;
    pulse_assert(
        remove.permission != OWNER_NAME,
        ChainError::ActionValidationError(format!("cannot delete owner authority")),
    )?;

    let old_size = db.delete_auth(remove.account.as_u64(), remove.permission.as_u64())?;
    context.add_ram_usage(&remove.account, -old_size)?;

    Ok(())
}

pub fn linkauth(context: &mut ApplyContext, db: &mut Database, act: &Action) -> Result<(), ChainError> {
    let requirement = act
        .data_as::<LinkAuth>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    pulse_assert(
        !requirement.requirement.empty(),
        ChainError::TransactionError(format!("required permission cannot be empty")),
    )?;
    context.require_authorization(&requirement.account, None)?;

    let delta = db.link_auth(
        requirement.account.as_u64(),
        requirement.code.as_u64(),
        requirement.requirement.as_u64(),
        requirement.message_type.as_u64(),
    )?;

    if delta != 0 {
        context.add_ram_usage(&requirement.account, delta)?;
    }

    Ok(())
}

pub fn unlinkauth(context: &mut ApplyContext, db: &mut Database, act: &Action) -> Result<(), ChainError> {
    let unlink = act
        .data_as::<UnlinkAuth>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(&unlink.account, None)?;

    let delta = db.unlink_auth(unlink.account.as_u64(), unlink.code.as_u64(), unlink.message_type.as_u64())?;

    if delta != 0 {
        context.add_ram_usage(&unlink.account, delta)?;
    }

    Ok(())
}

fn validate_authority_precondition(db: &mut Database, auth: &Authority) -> Result<(), ChainError> {
    for a in auth.accounts() {
        let _ = db
            .get_account(a.permission.actor)
            .map_err(|_| ChainError::TransactionError(format!("account {} does not exist", a.permission.actor)))?;

        if a.permission.permission == OWNER_NAME || a.permission.permission == ACTIVE_NAME {
            continue; // account was already checked to exist, so its owner and active permissions should exist
        }

        if a.permission.permission == CODE_NAME {
            continue; // virtual pulse.code permission does not really exist but is allowed
        }

        AuthorizationManager::get_permission(db, a.permission.actor, a.permission.permission)
            .map_err(|_| ChainError::TransactionError(format!("permission {}@{} does not exist", a.permission.actor, a.permission.permission)))?;
    }
    Ok(())
}
