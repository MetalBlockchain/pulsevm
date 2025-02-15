package engine

import (
	"errors"

	"github.com/MetalBlockchain/metalgo/codec"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/pulsevm/chain/action"
	"github.com/MetalBlockchain/pulsevm/chain/name"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
)

var (
	ErrNoAuthorizer = errors.New("transaction has no authorizers")
)

type TransactionContext struct {
	transaction      *txs.BaseTx
	resourceTracker  *ResourceTracker
	codec            codec.Manager
	authorityChecker *AuthorityChecker
}

func NewTransactionContext(transaction *txs.BaseTx, codec codec.Manager) (*TransactionContext, error) {
	return &TransactionContext{
		transaction:      transaction,
		resourceTracker:  NewResourceTracker(),
		codec:            codec,
		authorityChecker: NewAuthorityChecker(make([]secp256k1.PublicKey, 0)),
	}, nil
}

// This function goes through all of the transaction's specified permissions and checks them against the provided keys
func (tc *TransactionContext) CheckAuthorization() error {
	for _, action := range tc.transaction.Actions {
		for _, level := range action.Authorization {
			if err := tc.authorityChecker.SatisfiesPermissionLevel(level); err != nil {
				return err
			}
		}
	}

	return nil
}

func (tc *TransactionContext) Execute() error {
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
	actionContext := NewActionContext(tc, &action)

	return actionContext.Execute()
}

func (tc *TransactionContext) FirstAuthorizer() (name.Name, error) {
	for _, action := range tc.transaction.Actions {
		for _, auth := range action.Authorization {
			return auth.Actor, nil
		}
	}

	return 0, ErrNoAuthorizer
}

func (tc *TransactionContext) FindNativeActionHandler(account name.Name, action name.Name) nativeActionHandler {
	if account == SystemContractName {
		if handler, ok := SystemContractActionHandlers[action]; ok {
			return handler
		}
	}

	return nil
}
