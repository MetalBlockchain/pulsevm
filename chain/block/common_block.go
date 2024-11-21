package block

import (
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/hashing"
)

type CommonBlock struct {
	// parent's ID
	PrntID ids.ID `serialize:"true" json:"parentID"`

	// This block's height. The genesis block is at height 0.
	Hght uint64 `serialize:"true" json:"height"`

	BlockID ids.ID `json:"id"`
	bytes   []byte
}

func (b *CommonBlock) initialize(bytes []byte) {
	b.BlockID = hashing.ComputeHash256Array(bytes)
	b.bytes = bytes
}

func (b *CommonBlock) ID() ids.ID {
	return b.BlockID
}

func (b *CommonBlock) Parent() ids.ID {
	return b.PrntID
}

func (b *CommonBlock) Bytes() []byte {
	return b.bytes
}

func (b *CommonBlock) Height() uint64 {
	return b.Hght
}
