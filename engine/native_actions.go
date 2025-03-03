package engine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/MetalBlockchain/metalgo/database"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/pulsevm/chain/account"
	"github.com/MetalBlockchain/pulsevm/chain/authority"
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
		return errors.New("creator account does not exist")
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
	actionContext.state.AddAccount(newAccount)

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
