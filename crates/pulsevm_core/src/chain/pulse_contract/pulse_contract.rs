use std::ops::Mul;

use pulsevm_error::ChainError;
use pulsevm_ffi::Database;
use pulsevm_serialization::Write;
use sha2::Digest;

use crate::{
    ACTIVE_NAME, ANY_NAME, CODE_NAME, OWNER_NAME,
    chain::{
        abi::AbiDefinition,
        account::{Account, AccountMetadata, CodeObject},
        apply_context::ApplyContext,
        authority::{Authority, Permission, PermissionLevel, PermissionLink},
        authorization_manager::AuthorizationManager,
        config,
        id::Id,
        pulse_contract::pulse_contract_types::{
            DeleteAuth, LinkAuth, NewAccount, SetAbi, SetCode, UnlinkAuth, UpdateAuth,
        },
        resource_limits::ResourceLimitsManager,
        utils::pulse_assert,
    },
};

pub fn newaccount(context: &mut ApplyContext, db: &mut Database) -> Result<(), ChainError> {
    let create = context
        .get_action()
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
    let creator = db.get_account_metadata(create.creator.as_ref())?;
    if !creator.is_privileged() {
        pulse_assert(
            !name_str.starts_with("pulse."),
            ChainError::TransactionError(
                "only privileged accounts can have names that start with 'pulse.'".to_string(),
            ),
        )?;
    }
    let existing_account = db.find_account(create.name.as_ref())?;
    pulse_assert(
        existing_account.is_none(),
        ChainError::TransactionError(format!(
            "cannot create account named {}, as that name is already taken",
            create.name
        )),
    )?;

    db.create_account(create.name.as_ref(), context.pending_block_timestamp().slot)?;
    db.create_account_metadata(create.name.as_ref(), false)?;

    validate_authority_precondition(db, &create.owner)?;
    validate_authority_precondition(db, &create.active)?;

    let owner_permission = AuthorizationManager::create_permission(
        db,
        create.name,
        OWNER_NAME.into(),
        0,
        create.owner,
    )?;
    let active_permission = AuthorizationManager::create_permission(
        db,
        create.name,
        ACTIVE_NAME.into(),
        owner_permission.id(),
        create.active,
    )?;

    ResourceLimitsManager::initialize_account(db, create.name.as_ref())?;

    let mut ram_delta: i64 = config::OVERHEAD_PER_ACCOUNT_RAM_BYTES as i64;
    ram_delta += 2 * config::billable_size_v::<Permission>() as i64;
    ram_delta += owner_permission.authority.get_billable_size() as i64;
    ram_delta += active_permission.authority.get_billable_size() as i64;

    context.add_ram_usage(&create.name, ram_delta);

    Ok(())
}

pub fn setcode(context: &mut ApplyContext, db: &mut Database) -> Result<(), ChainError> {
    let act = context
        .get_action()
        .data_as::<SetCode>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(&act.account, None)?;

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
        let digest = sha2::Sha256::digest(act.code.as_slice());
        code_hash = Id::new(digest.into());
        // TODO: validate wasm
    }

    let mut account = db.get_account_metadata(act.account.as_ref())?;
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
                    Ok(())
                })
                .map_err(|_| ChainError::TransactionError(format!("failed to update code")))?;
        }
    }

    if code_size > 0 {
        let new_code_entry = session
            .find::<CodeObject>(code_hash.clone())
            .map_err(|_| ChainError::TransactionError(format!("failed to find code")))?;

        if let Some(mut new_code_entry) = new_code_entry {
            session
                .modify(&mut new_code_entry, |code| {
                    code.code_ref_count += 1;
                    Ok(())
                })
                .map_err(|_| {
                    ChainError::TransactionError(format!("failed to update code reference count"))
                })?;
        } else {
            let new_code_entry = CodeObject {
                code_hash: code_hash.clone(),
                code: act.code,
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
            a.last_code_update = context.pending_block_timestamp();
            Ok(())
        })
        .map_err(|_| ChainError::TransactionError(format!("failed to update account")))?;

    if new_size != old_size {
        context.add_ram_usage(&act.account, new_size - old_size);
    }

    Ok(())
}

pub fn setabi(context: &mut ApplyContext, db: &mut Database) -> Result<(), ChainError> {
    let act = context
        .get_action()
        .data_as::<SetAbi>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(&act.account, None)?;

    let mut account = db.get_account(act.account.as_ref())?;
    let abi_def: AbiDefinition =
        serde_json::from_str(std::str::from_utf8(act.abi.as_slice()).unwrap()).map_err(|e| {
            ChainError::InvalidArgument(format!("failed to deserialize ABI: {}", e))
        })?;
    let abi_def_packed = abi_def
        .pack()
        .map_err(|e| ChainError::TransactionError(format!("failed to serialize ABI: {}", e)))?;
    let old_size: i64 = account.abi.len() as i64;
    let new_size: i64 = abi_def_packed.len() as i64;

    session
        .modify(&mut account, |a| {
            a.abi = abi_def_packed;
            Ok(())
        })
        .map_err(|_| ChainError::TransactionError(format!("failed to update account")))?;

    let mut account_metadata = db.get_account_metadata(act.account.as_ref())?;
    session
        .modify(&mut account_metadata, |a| {
            a.abi_sequence += 1;
            Ok(())
        })
        .map_err(|_| ChainError::TransactionError(format!("failed to update account metadata")))?;

    if new_size != old_size {
        context.add_ram_usage(&act.account, new_size - old_size);
    }

    Ok(())
}

pub fn updateauth(context: &mut ApplyContext, db: &mut Database) -> Result<(), ChainError> {
    let update = context
        .get_action()
        .data_as::<UpdateAuth>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(&update.account, None)?;

    pulse_assert(
        !update.permission.empty(),
        ChainError::ActionValidationError(format!("cannot create authority with empty name")),
    )?;
    pulse_assert(
        !update.permission.to_string().starts_with("pulse."),
        ChainError::ActionValidationError(format!(
            "permission names that start with 'pulse.' are reserved"
        )),
    )?;
    pulse_assert(
        update.permission != update.parent,
        ChainError::ActionValidationError(format!("cannot set an authority as its own parent")),
    )?;

    db.get_account(update.account.as_ref()).map_err(|_| {
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

    validate_authority_precondition(db, &update.auth)?;

    let permission = AuthorizationManager::find_permission(
        db,
        &PermissionLevel::new(update.account, update.permission),
    )?;

    let mut parent_id = 0u64;
    if update.permission != OWNER_NAME {
        let parent = AuthorizationManager::get_permission(
            db,
            &PermissionLevel::new(update.account, update.parent),
        )?;
        parent_id = parent.id();
    }

    if permission.is_some() {
        let mut permission = permission.unwrap();
        pulse_assert(
            parent_id == permission.parent,
            ChainError::ActionValidationError(format!(
                "changing parent authority is not currently supported"
            )),
        )?;

        let old_size: i64 = config::billable_size_v::<Permission>() as i64
            + permission.authority.get_billable_size() as i64;
        AuthorizationManager::modify_permission(db, &mut permission, &update.auth)?;
        let new_size: i64 = config::billable_size_v::<Permission>() as i64
            + permission.authority.get_billable_size() as i64;

        context.add_ram_usage(permission.owner, new_size - old_size);
    } else {
        let p = AuthorizationManager::create_permission(
            db,
            update.account,
            update.permission,
            parent_id,
            update.auth,
        )?;

        let new_size: i64 =
            config::billable_size_v::<Permission>() as i64 + p.authority.get_billable_size() as i64;

        context.add_ram_usage(&update.account, new_size);
    }

    Ok(())
}

pub fn deleteauth(context: &mut ApplyContext, db: &mut Database) -> Result<(), ChainError> {
    let remove = context
        .get_action()
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

    let mut index = session.get_index::<PermissionLink, PermissionLinkByPermissionNameIndex>();
    let mut range = index.lower_bound((remove.account, remove.permission))?;
    let obj = range.next()?;
    if let Some(obj) = obj {
        return Err(ChainError::TransactionError(format!(
            "cannot delete a linked authority, unlink the authority first, this authority is linked to {}::{}.",
            obj.code(),
            obj.message_type()
        )));
    }

    let permission = AuthorizationManager::get_permission(
        db,
        &PermissionLevel::new(remove.account, remove.permission),
    )?;
    let old_size = config::billable_size_v::<Permission>() as i64
        + permission.authority.get_billable_size() as i64;

    AuthorizationManager::remove_permission(db, &permission)?;

    context.add_ram_usage(&remove.account, -old_size);

    Ok(())
}

pub fn linkauth(context: &mut ApplyContext, db: &mut Database) -> Result<(), ChainError> {
    let requirement = context
        .get_action()
        .data_as::<LinkAuth>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    pulse_assert(
        !requirement.requirement.empty(),
        ChainError::TransactionError(format!("required permission cannot be empty")),
    )?;
    context.require_authorization(&requirement.account, None)?;
    db.get_account(requirement.account.as_ref()).map_err(|_| {
        ChainError::TransactionError(format!("failed to find account {}", requirement.account))
    })?;
    db.get_account(requirement.code.as_ref()).map_err(|_| {
        ChainError::TransactionError(format!("failed to find code account {}", requirement.code))
    })?;

    if requirement.requirement != ANY_NAME {
        let permission = session.find_by_secondary::<Permission, PermissionByOwnerIndex>((
            requirement.account,
            requirement.requirement,
        ))?;
        pulse_assert(
            permission.is_some(),
            ChainError::TransactionError(format!(
                "failed to retrieve permission: {}",
                requirement.requirement
            )),
        )?;
    }

    let link_key = (
        requirement.account,
        requirement.code,
        requirement.message_type,
    );
    let link =
        session.find_by_secondary::<PermissionLink, PermissionLinkByActionNameIndex>(link_key)?;

    if let Some(mut link) = link {
        pulse_assert(
            link.required_permission() != requirement.requirement,
            ChainError::ActionValidationError(format!(
                "attempting to update required authority, but new requirement is same as old"
            )),
        )?;
        session.modify(&mut link, |l| {
            l.required_permission = requirement.requirement;
            Ok(())
        })?;
    } else {
        let new_link = PermissionLink::new(
            session.generate_id::<PermissionLink>()?,
            requirement.account,
            requirement.code,
            requirement.message_type,
            requirement.requirement,
        );
        session.insert(&new_link)?;

        context.add_ram_usage(
            new_link.account(),
            config::billable_size_v::<PermissionLink>() as i64,
        );
    }

    Ok(())
}

pub fn unlinkauth(context: &mut ApplyContext, db: &mut Database) -> Result<(), ChainError> {
    let unlink = context
        .get_action()
        .data_as::<UnlinkAuth>()
        .map_err(|e| ChainError::TransactionError(format!("failed to deserialize data: {}", e)))?;
    context.require_authorization(&unlink.account, None)?;

    let link_key = (unlink.account, unlink.code, unlink.message_type);
    let link =
        session.find_by_secondary::<PermissionLink, PermissionLinkByActionNameIndex>(link_key)?;

    if let Some(link) = link {
        session.remove(link)?;
        context.add_ram_usage(
            unlink.account,
            -(config::billable_size_v::<PermissionLink>() as i64),
        );
    } else {
        return Err(ChainError::TransactionError(format!(
            "attempting to unlink authority, but no link found"
        )));
    }

    Ok(())
}

fn validate_authority_precondition(db: &Database, auth: &Authority) -> Result<(), ChainError> {
    for a in auth.accounts() {
        let account = db.get_account(a.permission().actor.as_ref()).map_err(|_| {
            ChainError::TransactionError(format!("account {} does not exist", a.permission().actor))
        })?;

        if a.permission().permission == OWNER_NAME || a.permission().permission == ACTIVE_NAME {
            continue; // account was already checked to exist, so its owner and active permissions should exist
        }

        if a.permission().permission == CODE_NAME {
            continue; // virtual pulse.code permission does not really exist but is allowed
        }

        let permission = session
            .find_by_secondary::<Permission, PermissionByOwnerIndex>((
                a.permission().actor,
                a.permission().permission,
            ))
            .map_err(|_| {
                ChainError::TransactionError(format!(
                    "failed to query db for permission {}",
                    a.permission().permission
                ))
            })?;
        pulse_assert(
            permission.is_some(),
            ChainError::TransactionError(format!("permission {} does not exist", a.permission())),
        )?;
    }
    Ok(())
}
