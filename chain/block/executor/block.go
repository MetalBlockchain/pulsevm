package executor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/MetalBlockchain/metalgo/chains/atomic"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow/consensus/snowman"
	"github.com/MetalBlockchain/pulsevm/chain/block"
	"github.com/MetalBlockchain/pulsevm/chain/txs/executor"
	"github.com/MetalBlockchain/pulsevm/state"
	"go.uber.org/zap"
)

var (
	_ snowman.Block = (*Block)(nil)

	errIncorrectHeight             = errors.New("block has incorrect height")
	errTimestampBeyondSyncBound    = errors.New("proposed timestamp is too far in the future relative to local time")
	errChildBlockEarlierThanParent = errors.New("proposed timestamp before current chain time")
	errBlockNotFound               = errors.New("block not found")
)

const SyncBound = 10 * time.Second

type Block struct {
	block.Block
	manager *manager
}

func (b *Block) Verify(context.Context) error {
	blkID := b.ID()
	if _, ok := b.manager.blkIDToState[blkID]; ok {
		// This block has already been verified.
		return nil
	}

	// Only allow timestamp to reasonably far forward
	newChainTime := b.Timestamp()
	now := b.manager.clk.Time()
	maxNewChainTime := now.Add(SyncBound)
	if newChainTime.After(maxNewChainTime) {
		return fmt.Errorf(
			"%w, proposed time (%s), local time (%s)",
			errTimestampBeyondSyncBound,
			newChainTime,
			now,
		)
	}

	txs := b.Txs()
	if len(txs) == 0 {
		return errors.New("block has no transactions")
	}

	// Verify that the parent exists.
	parentID := b.Parent()
	parent, err := b.manager.GetStatelessBlock(parentID)
	if err != nil {
		return err
	}

	// Verify that currentBlkHeight = parentBlkHeight + 1.
	expectedHeight := parent.Height() + 1
	height := b.Height()
	if expectedHeight != height {
		return fmt.Errorf(
			"%w: expected height %d, got %d",
			errIncorrectHeight,
			expectedHeight,
			height,
		)
	}

	stateDiff, err := state.NewDiff(parentID, b.manager)
	if err != nil {
		return err
	}

	parentChainTime := stateDiff.GetTimestamp()
	// The proposed timestamp must not be before the parent's timestamp.
	if newChainTime.Before(parentChainTime) {
		return fmt.Errorf(
			"%w: proposed timestamp (%s), chain time (%s)",
			errChildBlockEarlierThanParent,
			newChainTime,
			parentChainTime,
		)
	}

	stateDiff.SetTimestamp(newChainTime)

	blockState := &blockState{
		statelessBlock: b.Block,
		onAcceptState:  stateDiff,
		atomicRequests: make(map[ids.ID]*atomic.Requests),
	}

	for _, tx := range txs {
		// Apply the txs state changes to the state.
		//
		// Note: This must be done inside the same loop as semantic verification
		// to ensure that semantic verification correctly accounts for
		// transactions that occurred earlier in the block.
		executor := &executor.Executor{
			State: stateDiff,
			Tx:    tx,
			Ctx:   b.manager.backend.Ctx,
		}

		if err := tx.Unsigned.Visit(executor); err != nil {
			txID := tx.ID()
			b.manager.mempool.MarkDropped(txID, err)
			return err
		}

		// Now that the tx would be marked as accepted, we should add it to the
		// state for the next transaction in the block.
		stateDiff.AddTx(tx)
	}

	// Now that the block has been executed, we can add the block data to the
	// state diff.
	stateDiff.SetLastAccepted(blkID)
	stateDiff.AddBlock(b.Block)

	b.manager.blkIDToState[blkID] = blockState
	b.manager.mempool.Remove(txs...)

	return nil
}

func (b *Block) Accept(context.Context) error {
	blkID := b.ID()
	defer b.manager.free(blkID)

	txs := b.Txs()
	for _, tx := range txs {
		if err := b.manager.onAccept(tx); err != nil {
			return fmt.Errorf(
				"failed to mark tx %q as accepted: %w",
				blkID,
				err,
			)
		}
	}

	b.manager.lastAccepted = blkID
	b.manager.mempool.Remove(txs...)

	blkState, ok := b.manager.blkIDToState[blkID]
	if !ok {
		return fmt.Errorf("%w: %s", errBlockNotFound, blkID)
	}

	// Update the state to reflect the changes made in [onAcceptState].
	blkState.onAcceptState.Apply(b.manager.state)

	defer b.manager.state.Abort()
	batch, err := b.manager.state.CommitBatch()
	if err != nil {
		return fmt.Errorf(
			"failed to stage state diff for block %s: %w",
			blkID,
			err,
		)
	}

	// Note that this method writes [batch] to the database.
	if err := b.manager.backend.Ctx.SharedMemory.Apply(blkState.atomicRequests, batch); err != nil {
		return fmt.Errorf("failed to apply state diff to shared memory: %w", err)
	}

	b.manager.backend.Ctx.Log.Info(
		"accepted block",
		zap.Stringer("blkID", blkID),
		zap.Uint64("height", b.Height()),
		zap.Stringer("parentID", b.Parent()),
	)

	return nil
}

func (b *Block) Reject(context.Context) error {
	blkID := b.ID()
	defer b.manager.free(blkID)

	b.manager.backend.Ctx.Log.Info(
		"rejecting block",
		zap.Stringer("blkID", blkID),
		zap.Uint64("height", b.Height()),
		zap.Stringer("parentID", b.Parent()),
	)

	for _, tx := range b.Txs() {
		if err := b.manager.VerifyTx(tx); err != nil {
			b.manager.backend.Ctx.Log.Debug("dropping invalidated tx",
				zap.Stringer("txID", tx.ID()),
				zap.Stringer("blkID", blkID),
				zap.Error(err),
			)
			continue
		}
		if err := b.manager.mempool.Add(tx); err != nil {
			b.manager.backend.Ctx.Log.Debug("dropping valid tx",
				zap.Stringer("txID", tx.ID()),
				zap.Stringer("blkID", blkID),
				zap.Error(err),
			)
		}
	}

	// If we added transactions to the mempool, we should be willing to build a
	// block.
	b.manager.mempool.RequestBuildBlock()

	return nil
}
