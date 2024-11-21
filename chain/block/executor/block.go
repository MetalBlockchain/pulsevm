package executor

import (
	"context"
	"time"

	"github.com/MetalBlockchain/metalgo/snow/consensus/snowman"
	smblock "github.com/MetalBlockchain/metalgo/snow/engine/snowman/block"
	"github.com/MetalBlockchain/pulsevm/chain/block"
)

var (
	_ snowman.Block = (*Block)(nil)
)

type Block struct {
	block.Block
	manager *manager
}

func (b *Block) VerifyWithContext(ctx context.Context, blockContext *smblock.Context) error {
	blkID := b.ID()
	blkState, previouslyExecuted := b.manager.blkIDToState[blkID]

	// If the block was previously executed, we don't need to execute it again,
	// we can just mark that the warp messages are valid at this height.
	if previouslyExecuted {
		blkState.verifiedHeights.Add(blockContext.PChainHeight)
		return nil
	}

	// Since this is the first time we are verifying this block, we must execute
	// the state transitions to generate the state diffs.
	return b.Visit(&verifier{
		backend:           b.manager.backend,
		txExecutorBackend: b.manager.txExecutorBackend,
		pChainHeight:      blockContext.PChainHeight,
	})
}

func (b *Block) Verify(ctx context.Context) error {
	return b.VerifyWithContext(
		ctx,
		&smblock.Context{
			PChainHeight: 0,
		},
	)
}

func (b *Block) Accept(context.Context) error {
	if err := b.Visit(b.manager.acceptor); err != nil {
		return err
	}

	return nil
}

func (b *Block) Reject(context.Context) error {
	return b.Visit(b.manager.rejector)
}

func (b *Block) Timestamp() time.Time {
	return b.manager.getTimestamp(b.ID())
}
