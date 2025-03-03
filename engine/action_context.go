package engine

import (
	"fmt"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/pulsevm/chain/account"
	"github.com/MetalBlockchain/pulsevm/chain/action"
	"github.com/MetalBlockchain/pulsevm/chain/contract"
	"github.com/MetalBlockchain/pulsevm/chain/name"
	"github.com/MetalBlockchain/pulsevm/state"
)

type ActionContext struct {
	transactionContext *TransactionContext
	action             *action.Action
	state              state.Chain
}

func NewActionContext(
	transactionContext *TransactionContext,
	action *action.Action,
	state state.Chain,
) *ActionContext {
	return &ActionContext{
		transactionContext: transactionContext,
		action:             action,
		state:              state,
	}
}

func (a *ActionContext) Execute() error {
	nativeHandler := a.transactionContext.FindNativeActionHandler(a.action.Account, a.action.Name)
	if nativeHandler != nil {
		return nativeHandler(a)
	}

	return nil
}

func (a *ActionContext) GetAction() *action.Action {
	return a.action
}

func (a *ActionContext) RequireAuthorization(account name.Name) error {
	for _, level := range a.action.Authorization {
		if level.Actor == account {
			return nil
		}
	}

	return fmt.Errorf("missing authority of %s", account)
}

func (a *ActionContext) GetAccount(accountName name.Name) (*account.Account, error) {
	return a.state.GetAccount(accountName)
}

func (a *ActionContext) AddRamUsage(account name.Name, delta int) {
	a.transactionContext.resourceTracker.AddRamUsage(account, delta)
}

func (a *ActionContext) GetCode(codeHash ids.ID) (*contract.Code, error) {
	return a.state.GetCode(codeHash)
}
