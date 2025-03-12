package block

import (
	"fmt"
	"time"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/hashing"
	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/common"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
)

var (
	_ Block               = (*StandardBlock)(nil)
	_ common.Serializable = (*StandardBlock)(nil)
)

type StandardBlock struct {
	BlockID      ids.ID    `json:"id"`
	PrntID       ids.ID    `serialize:"true" json:"parentID"`
	Hght         uint64    `serialize:"true" json:"height"`
	Time         uint64    `serialize:"true" json:"time"`
	Root         ids.ID    `serialize:"true" json:"merkleRoot"`
	Transactions []*txs.Tx `serialize:"true" json:"txs"`

	bytes []byte
}

func (b *StandardBlock) Marshal(p *wrappers.Packer) ([]byte, error) {
	p.PackFixedBytes(b.PrntID[:])
	p.PackLong(b.Hght)
	p.PackLong(b.Time)
	p.PackFixedBytes(b.Root[:])
	p.PackInt(uint32(len(b.Transactions)))
	for _, tx := range b.Transactions {
		_, err := tx.Marshal(p)
		if err != nil {
			return nil, err
		}
	}
	return p.Bytes, p.Err
}

func (b *StandardBlock) Unmarshal(p *wrappers.Packer) error {
	b.PrntID = ids.ID(p.UnpackFixedBytes(ids.IDLen))
	b.Hght = p.UnpackLong()
	b.Time = p.UnpackLong()
	b.Root = ids.ID(p.UnpackFixedBytes(ids.IDLen))
	numTxs := p.UnpackInt()
	b.Transactions = make([]*txs.Tx, numTxs)
	for i := range int(numTxs) {
		var tx txs.Tx
		if err := tx.Unmarshal(p); err != nil {
			return err
		}
		b.Transactions[i] = &tx
	}
	return p.Err
}

func (b *StandardBlock) initialize(bytes []byte) error {
	b.BlockID = hashing.ComputeHash256Array(bytes)
	b.bytes = bytes
	for _, tx := range b.Transactions {
		if err := tx.Initialize(); err != nil {
			return fmt.Errorf("failed to initialize tx: %w", err)
		}
	}
	return nil
}

func (b *StandardBlock) ID() ids.ID {
	return b.BlockID
}

func (b *StandardBlock) Parent() ids.ID {
	return b.PrntID
}

func (b *StandardBlock) Height() uint64 {
	return b.Hght
}

func (b *StandardBlock) Timestamp() time.Time {
	return time.Unix(int64(b.Time), 0)
}

func (b *StandardBlock) MerkleRoot() ids.ID {
	return b.Root
}

func (b *StandardBlock) Txs() []*txs.Tx {
	return b.Transactions
}

func (b *StandardBlock) Bytes() []byte {
	return b.bytes
}

func NewStandardBlock(
	parentID ids.ID,
	height uint64,
	timestamp time.Time,
	txs []*txs.Tx,
) (*StandardBlock, error) {
	blk := &StandardBlock{
		PrntID:       parentID,
		Hght:         height,
		Time:         uint64(timestamp.Unix()),
		Transactions: txs,
	}

	// We serialize this block as a pointer so that it can be deserialized into
	// a Block

	var blkIntf Block = blk
	bytes, err := blkIntf.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal block: %w", err)
	}

	blk.BlockID = hashing.ComputeHash256Array(bytes)
	blk.bytes = bytes
	return blk, nil
}
