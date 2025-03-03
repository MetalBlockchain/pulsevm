package engine

import (
	"errors"
	"fmt"

	"github.com/MetalBlockchain/pulsevm/chain/action"
	"github.com/MetalBlockchain/pulsevm/chain/name"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/MetalBlockchain/pulsevm/state"
)

var (
	errNoAuthorizer = errors.New("transaction has no authorizers")
)

type TransactionContext struct {
	transaction      *txs.BaseTx
	signatures       [][]byte
	resourceTracker  *ResourceTracker
	authorityChecker *AuthorityChecker
	state            state.Chain
}

func NewTransactionContext(tx *txs.BaseTx, signatures [][]byte, state state.Chain) (*TransactionContext, error) {
	authorityChecker, err := NewAuthorityChecker(tx.Bytes(), signatures, state)
	if err != nil {
		return nil, err
	}

	return &TransactionContext{
		transaction:      tx,
		signatures:       signatures,
		resourceTracker:  NewResourceTracker(),
		authorityChecker: authorityChecker,
		state:            state,
	}, nil
}

// This function goes through all of the transaction's specified permissions and checks them against the provided keys
func (tc *TransactionContext) CheckAuthorization() error {
	for _, action := range tc.transaction.Actions {
		for _, level := range action.Authorization {
			if err := tc.authorityChecker.SatisfiesPermissionLevel(level); err != nil {
				return fmt.Errorf("authorization failed: %w", err)
			}
		}
	}

	return nil
}

func (tc *TransactionContext) Execute() error {
	if err := tc.CheckAuthorization(); err != nil {
		return err
	}

	firstAuthorizer, err := tc.FirstAuthorizer()
	if err != nil {
		return err
	}

	// First authorizer is billed for NET usage
	tc.resourceTracker.AddNetUsage(firstAuthorizer, len(tc.transaction.Bytes()))

	for index, action := range tc.transaction.Actions {
		if err := tc.ExecuteAction(action, index); err != nil {
			return err
		}
	}

	return nil
}

func (tc *TransactionContext) ExecuteAction(action action.Action, ordinal int) error {
	actionContext := NewActionContext(tc, &action, tc.state)

	return actionContext.Execute()
}

func (tc *TransactionContext) FirstAuthorizer() (name.Name, error) {
	for _, action := range tc.transaction.Actions {
		for _, auth := range action.Authorization {
			return auth.Actor, nil
		}
	}

	return 0, errNoAuthorizer
}

func (tc *TransactionContext) FindNativeActionHandler(account name.Name, action name.Name) nativeActionHandler {
	if account == SystemContractName {
		if handler, ok := SystemContractActionHandlers[action]; ok {
			return handler
		}
	}

	return nil
}
