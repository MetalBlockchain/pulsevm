package block

import (
	"fmt"
	"time"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
)

var (
	_ Block = (*StandardBlock)(nil)
)

type StandardBlock struct {
	CommonBlock  `serialize:"true"`
	Time         uint64    `serialize:"true" json:"time"`
	Transactions []*txs.Tx `serialize:"true" json:"txs"`
}

func (b *StandardBlock) Timestamp() time.Time {
	return time.Unix(int64(b.Time), 0)
}

func (b *StandardBlock) initialize(bytes []byte) error {
	b.CommonBlock.initialize(bytes)
	for _, tx := range b.Transactions {
		if err := tx.Initialize(txs.Codec); err != nil {
			return fmt.Errorf("failed to initialize tx: %w", err)
		}
	}
	return nil
}

func (b *StandardBlock) InitCtx(ctx *snow.Context) {
	for _, tx := range b.Transactions {
		tx.Unsigned.InitCtx(ctx)
	}
}

func (b *StandardBlock) Txs() []*txs.Tx {
	return b.Transactions
}

func (b *StandardBlock) Visit(v Visitor) error {
	return v.StandardBlock(b)
}

func NewStandardBlock(
	timestamp time.Time,
	parentID ids.ID,
	height uint64,
	txs []*txs.Tx,
) (*StandardBlock, error) {
	blk := &StandardBlock{
		Time: uint64(timestamp.Unix()),
		CommonBlock: CommonBlock{
			PrntID: parentID,
			Hght:   height,
		},
		Transactions: txs,
	}
	return blk, initialize(blk, &blk.CommonBlock)
}
