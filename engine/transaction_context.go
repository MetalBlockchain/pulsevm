package engine

import "github.com/MetalBlockchain/pulsevm/chain/txs"

type TransactionContext struct {
	transaction     *txs.BaseTx
	resourceTracker *ResourceTracker
}

func NewTransactionContext(transaction *txs.BaseTx) (*TransactionContext, error) {
	return &TransactionContext{
		transaction:     transaction,
		resourceTracker: NewResourceTracker(),
	}, nil
}

func (tc *TransactionContext) Execute() error {
	// First authorizer is billed for NET usage
	//tc.resourceTracker.AddNetUsage("", len(tc.transaction.Bytes()))
	return nil
}
