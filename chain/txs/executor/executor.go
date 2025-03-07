package executor

import (
	"github.com/MetalBlockchain/metalgo/codec"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/MetalBlockchain/pulsevm/engine"
	"github.com/MetalBlockchain/pulsevm/state"
)

var (
	_ txs.Visitor = (*Executor)(nil)
)

type Executor struct {
	Codec codec.Manager
	State state.Chain // state will be modified
	Tx    *txs.Tx
}

func (e *Executor) BaseTx(tx *txs.BaseTx) error {
	txContext, err := engine.NewTransactionContext(tx, e.Tx.Signatures, e.State)
	if err != nil {
		return err
	}

	return txContext.Execute()
}
