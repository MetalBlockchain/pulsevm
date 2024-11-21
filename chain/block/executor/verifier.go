package executor

import (
	"errors"

	"github.com/MetalBlockchain/metalgo/utils/set"
	"github.com/MetalBlockchain/pulsevm/chain/block"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/MetalBlockchain/pulsevm/chain/txs/executor"
	"github.com/MetalBlockchain/pulsevm/state"
)

var (
	_ block.Visitor = (*verifier)(nil)

	errStandardBlockWithoutChanges = errors.New("StandardBlock performs no state changes")
)

type verifier struct {
	*backend
	txExecutorBackend *executor.Backend
	pChainHeight      uint64
}

func (v *verifier) StandardBlock(b *block.StandardBlock) error {
	parentID := b.Parent()
	onAcceptState, err := state.NewDiff(parentID, v.backend)
	if err != nil {
		return err
	}

	// If this block doesn't perform any changes, then it should never have been
	// issued.
	if len(b.Transactions) == 0 {
		return errStandardBlockWithoutChanges
	}

	return v.standardBlock(
		b,
		b.Transactions,
		onAcceptState,
	)
}

// standardBlock populates the state of this block if [nil] is returned
func (v *verifier) standardBlock(
	b block.Block,
	txs []*txs.Tx,
	onAcceptState state.Diff,
) error {
	inputs, onAcceptFunc, err := v.processStandardTxs(
		txs,
		onAcceptState,
		b.Parent(),
	)
	if err != nil {
		return err
	}

	v.Mempool.Remove(txs...)

	blkID := b.ID()
	v.blkIDToState[blkID] = &blockState{
		statelessBlock: b,

		onAcceptState: onAcceptState,
		onAcceptFunc:  onAcceptFunc,

		timestamp:       onAcceptState.GetTimestamp(),
		inputs:          inputs,
		verifiedHeights: set.Of(v.pChainHeight),
	}
	return nil
}
