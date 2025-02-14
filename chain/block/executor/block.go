package executor

import (
	"context"

	"github.com/MetalBlockchain/metalgo/snow/consensus/snowman"
	"github.com/MetalBlockchain/pulsevm/chain/block"
)

var (
	_ snowman.Block = (*Block)(nil)
)

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

	return nil
}

func (b *Block) Accept(context.Context) error {
	return nil
}

func (b *Block) Reject(context.Context) error {
	return nil
}
