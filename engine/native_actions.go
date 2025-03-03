package engine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/MetalBlockchain/metalgo/database"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/hashing"
	"github.com/MetalBlockchain/pulsevm/chain/account"
	"github.com/MetalBlockchain/pulsevm/chain/authority"
	"github.com/MetalBlockchain/pulsevm/chain/contract"
	"github.com/MetalBlockchain/pulsevm/chain/name"
)

type nativeActionHandler func(*ActionContext) error

var (
	SystemContractName           = name.NewNameFromString("pulse")
	SystemContractActionHandlers = make(map[name.Name]nativeActionHandler)

	errDecodeActionData = errors.New("failed to decode action data")
)

func init() {
	SystemContractActionHandlers[name.NewNameFromString("newaccount")] = handleNewAccount
	SystemContractActionHandlers[name.NewNameFromString("setcode")] = handleSetCode
	SystemContractActionHandlers[name.NewNameFromString("setabi")] = handleSetAbi
}

// pulse.newaccount handles the creation of a new account
func handleNewAccount(actionContext *ActionContext) error {
	var actionData NewAccount
	if err := actionData.Unmarshal(actionContext.GetAction().Data); err != nil {
		return errDecodeActionData
	}
	// Must have creator's authorization
	if err := actionContext.RequireAuthorization(actionData.Creator); err != nil {
		return err
	}
	if err := actionData.Owner.Validate(); err != nil {
		return fmt.Errorf("owner authority is invalid: %w", err)
	}
	if err := actionData.Active.Validate(); err != nil {
		return fmt.Errorf("active authority is invalid: %w", err)
	}
	if actionData.Name.IsEmpty() {
		return errors.New("account name cannot be empty")
	}
	nameString := actionData.Name.String()
	if len(nameString) > 12 {
		return errors.New("account name is too long")
	}
	creator, err := actionContext.GetAccount(actionData.Creator)
	if err != nil {
		return fmt.Errorf("failed to get creator account: %w", err)
	}
	if strings.HasPrefix(nameString, "pulse.") && !creator.Priviliged {
		return errors.New("only privileged accounts can have names that start with 'pulse.'")
	}
	existingAccount, err := actionContext.GetAccount(actionData.Name)
	if err != nil && err != database.ErrNotFound {
		return err
	} else if existingAccount != nil {
		return errors.New("account already exists")
	}
	newAccount := &account.Account{
		Name:       actionData.Name,
		Priviliged: false,
	}
	// Add account to state
	actionContext.state.ModifyAccount(newAccount)

	// Add owner and active permissions
	ownerPermissionID, err := authority.GetPermissionID(actionData.Name, name.NewNameFromString("owner"))
	if err != nil {
		return err
	}
	ownerPermission := &authority.Permission{
		ID:     ownerPermissionID,
		Parent: ids.Empty,
		Owner:  actionData.Name,
		Name:   name.NewNameFromString("owner"),
		Auth:   actionData.Owner,
	}
	activePermissionID, err := authority.GetPermissionID(actionData.Name, name.NewNameFromString("active"))
	if err != nil {
		return err
	}
	activePermission := &authority.Permission{
		ID:     activePermissionID,
		Parent: ownerPermissionID,
		Owner:  actionData.Name,
		Name:   name.NewNameFromString("active"),
		Auth:   actionData.Active,
	}
	actionContext.state.AddPermission(ownerPermission)
	actionContext.state.AddPermission(activePermission)

	// TODO: Verify authority accounts and keys exist

	// Add RAM usage
	ramDelta := account.AccountBillableSize
	if size, err := ownerPermission.GetBillableSize(); err != nil {
		return err
	} else {
		ramDelta += size
	}
	if size, err := activePermission.GetBillableSize(); err != nil {
		return err
	} else {
		ramDelta += size
	}

	actionContext.AddRamUsage(actionData.Creator, ramDelta)

	return nil
}

func handleSetCode(actionContext *ActionContext) error {
	var actionData SetCode
	if err := actionData.Unmarshal(actionContext.GetAction().Data); err != nil {
		return errDecodeActionData
	}
	if err := actionContext.RequireAuthorization(actionData.Account); err != nil {
		return err
	}
	account, err := actionContext.GetAccount(actionData.Account)
	if err != nil {
		return err
	}

	// Previous contract size, for RAM purposes
	oldSize := 0
	newSize := len(actionData.Code)

	if account.CodeHash != ids.Empty {
		oldCode, err := actionContext.GetCode(account.CodeHash)
		if err != nil {
			return err
		}
		oldSize = len(oldCode.Code)
		if oldCode.RefCount == 1 {
			// TODO: Remove contract when no longer referenced
		} else {
			oldCode.RefCount--
			actionContext.state.ModifyCode(oldCode)
		}
	}

	if len(actionData.Code) > 0 {
		codeHash, err := ids.ToID(hashing.ComputeHash256(actionData.Code))
		if err != nil {
			return err
		}

		if account.CodeHash == codeHash {
			return errors.New("account is already running this version of the contract")
		} else {
			account.CodeHash = codeHash
			account.CodeSequence++
		}

		existingCode, err := actionContext.GetCode(codeHash)
		if err != nil && err != database.ErrNotFound {
			return err
		}

		if existingCode == nil {
			newCode := &contract.Code{
				Hash:     codeHash,
				Code:     actionData.Code,
				RefCount: 1,
			}
			actionContext.state.ModifyCode(newCode)
		} else {
			existingCode.RefCount++
			actionContext.state.ModifyCode(existingCode)
		}
	} else {
		account.CodeHash = ids.Empty
		account.CodeSequence++
	}

	actionContext.state.ModifyAccount(account)

	if oldSize != newSize {
		actionContext.AddRamUsage(actionData.Account, newSize-oldSize)
	}

	return nil
}

func handleSetAbi(actionContext *ActionContext) error {
	var actionData SetAbi
	if err := actionData.Unmarshal(actionContext.GetAction().Data); err != nil {
		return errDecodeActionData
	}
	if err := actionContext.RequireAuthorization(actionData.Account); err != nil {
		return err
	}
	account, err := actionContext.GetAccount(actionData.Account)
	if err != nil {
		return err
	}

	// Previous ABI size, for RAM purposes
	oldSize := 0
	newSize := len(actionData.Abi)

	account.Abi = actionData.Abi
	account.AbiSequence++
	actionContext.state.ModifyAccount(account)

	if oldSize != newSize {
		actionContext.AddRamUsage(actionData.Account, newSize-oldSize)
	}

	return nil
}
