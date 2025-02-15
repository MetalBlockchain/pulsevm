package engine

import "github.com/MetalBlockchain/pulsevm/chain/action"

type ActionContext struct {
	transactionContext *TransactionContext
	action             *action.Action
}

func NewActionContext(
	transactionContext *TransactionContext,
	action *action.Action,
) *ActionContext {
	return &ActionContext{
		transactionContext: transactionContext,
		action:             action,
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
