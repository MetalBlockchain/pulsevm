package txs

import (
	"errors"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow"
	"github.com/MetalBlockchain/pulsevm/chain/action"
)

var (
	_ UnsignedTx = (*BaseTx)(nil)

	ErrNilTx = errors.New("tx is nil")
)

type BaseTx struct {
	NetworkID    uint32          `serialize:"true" json:"networkID"`    // ID of the network this chain lives on
	BlockchainID ids.ID          `serialize:"true" json:"blockchainID"` // ID of the chain on which this transaction exists (prevents replay attacks)
	Actions      []action.Action `serialize:"true" json:"actions"`      // Actions this transaction will execute

	// true iff this transaction has already passed syntactic verification
	SyntacticallyVerified bool `json:"-"`

	unsignedBytes []byte // Unsigned byte representation of this data
}

func (tx *BaseTx) SetBytes(unsignedBytes []byte) {
	tx.unsignedBytes = unsignedBytes
}

func (tx *BaseTx) Bytes() []byte {
	return tx.unsignedBytes
}

// SyntacticVerify returns nil iff this tx is well formed
func (tx *BaseTx) SyntacticVerify(ctx *snow.Context) error {
	switch {
	case tx == nil:
		return ErrNilTx
	case tx.SyntacticallyVerified: // already passed syntactic verification
		return nil
	}
	return nil
}

func (tx *BaseTx) Visit(visitor Visitor) error {
	return visitor.BaseTx(tx)
}

func (tx *BaseTx) InitCtx(ctx *snow.Context) {

}
