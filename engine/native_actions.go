package engine

import (
	"github.com/MetalBlockchain/pulsevm/chain/name"
)

type nativeActionHandler func(*ActionContext) error

var (
	SystemContractName           = name.NewNameFromString("pulse")
	SystemContractActionHandlers = make(map[name.Name]nativeActionHandler)
)

func init() {
	SystemContractActionHandlers[name.NewNameFromString("newaccount")] = handleNewAccount
}

func handleNewAccount(actionContext *ActionContext) error {
	/*var actionData NewAccount
	if _, err := actionContext.transactionContext.codec.Unmarshal(actionContext.action.Data, &actionData); err != nil {
		return errors.New("failed to decode action data")
	}*/

	return nil
}
