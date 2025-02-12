package executor

import (
	"fmt"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/set"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/MetalBlockchain/pulsevm/state"
)

var (
	_ txs.Visitor = (*standardTxExecutor)(nil)
)

// StandardTx executes the standard transaction [tx].
//
// [state] is modified to represent the state of the chain after the execution
// of [tx].
//
// Returns:
//   - The IDs of any import UTXOs consumed.
//   - A, potentially nil, function that should be called when this transaction
//     is accepted.
func StandardTx(
	backend *Backend,
	tx *txs.Tx,
	state state.Diff,
) (set.Set[ids.ID], func(), error) {
	standardExecutor := standardTxExecutor{
		backend: backend,
		tx:      tx,
		state:   state,
	}
	if err := tx.Unsigned.Visit(&standardExecutor); err != nil {
		txID := tx.ID()
		return nil, nil, fmt.Errorf("standard tx %s failed execution: %w", txID, err)
	}
	return standardExecutor.inputs, standardExecutor.onAccept, nil
}

type standardTxExecutor struct {
	// inputs, to be filled before visitor methods are called
	backend *Backend
	state   state.Diff // state is expected to be modified
	tx      *txs.Tx

	// outputs of visitor execution
	onAccept func() // may be nil
	inputs   set.Set[ids.ID]
}

func (s *standardTxExecutor) BaseTransaction(*txs.BaseTx) error {
	panic("unimplemented")
}

func (s *standardTxExecutor) CreateAccountTx(*txs.CreateAccountTx) error {
	return nil
}

func (s *standardTxExecutor) CreateAssetTx(*txs.CreateAssetTx) error {
	panic("unimplemented")
}
