package block

import (
	"time"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/pulsevm/chain/common"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
)

type Block interface {
	common.Serializable
	ID() ids.ID
	Parent() ids.ID
	Height() uint64
	Timestamp() time.Time
	MerkleRoot() ids.ID
	Bytes() []byte
	Txs() []*txs.Tx

	// note: initialize does not assume that block transactions
	// are initialized, and initializes them itself if they aren't.
	initialize(bytes []byte) error
}
