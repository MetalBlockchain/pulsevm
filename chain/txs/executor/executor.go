package executor

import (
	"github.com/MetalBlockchain/metalgo/snow"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/MetalBlockchain/pulsevm/engine"
	"github.com/MetalBlockchain/pulsevm/state"
)

var (
	_ txs.Visitor = (*Executor)(nil)
)

type Executor struct {
	State state.Chain // state will be modified
	Tx    *txs.Tx
	Ctx   *snow.Context
}

func (e *Executor) BaseTx(tx *txs.BaseTx) error {
	txContext, err := engine.NewTransactionContext(tx, e.Tx.Signatures, e.State, e.Ctx.ChainID)
	if err != nil {
		return err
	}

	return txContext.Execute()
}
