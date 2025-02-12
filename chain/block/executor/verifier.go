package executor

import (
	"errors"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/set"
	"github.com/MetalBlockchain/pulsevm/chain/block"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/MetalBlockchain/pulsevm/chain/txs/executor"
	"github.com/MetalBlockchain/pulsevm/state"
	"github.com/MetalBlockchain/pulsevm/status"
)

var (
	_ block.Visitor = (*verifier)(nil)

	errConflictingBlockTxs         = errors.New("block contains conflicting transactions")
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

func (v *verifier) processStandardTxs(txs []*txs.Tx, diff state.Diff, parentID ids.ID) (
	set.Set[ids.ID],
	func(),
	error,
) {
	var (
		onAcceptFunc func()
		inputs       set.Set[ids.ID]
		funcs        = make([]func(), 0, len(txs))
	)
	for _, tx := range txs {
		txInputs, onAccept, err := executor.StandardTx(
			v.txExecutorBackend,
			tx,
			diff,
		)
		if err != nil {
			txID := tx.ID()
			v.MarkDropped(txID, err) // cache tx as dropped
			return nil, nil, err
		}
		// ensure it doesn't overlap with current input batch
		if inputs.Overlaps(txInputs) {
			return nil, nil, errConflictingBlockTxs
		}
		// Add UTXOs to batch
		inputs.Union(txInputs)

		diff.AddTx(tx, status.Committed)
		if onAccept != nil {
			funcs = append(funcs, onAccept)
		}
	}

	if numFuncs := len(funcs); numFuncs == 1 {
		onAcceptFunc = funcs[0]
	} else if numFuncs > 1 {
		onAcceptFunc = func() {
			for _, f := range funcs {
				f()
			}
		}
	}

	return inputs, onAcceptFunc, nil
}
