package txs

import (
	"errors"

	"github.com/MetalBlockchain/metalgo/snow"
	"github.com/MetalBlockchain/metalgo/vms/components/avax"
	"github.com/MetalBlockchain/metalgo/vms/secp256k1fx"
)

var (
	_ UnsignedTx = (*BaseTx)(nil)

	ErrNilTx = errors.New("tx is nil")
)

// BaseTx contains fields common to many transaction types. It should be
// embedded in transaction implementations.
type BaseTx struct {
	avax.BaseTx `serialize:"true"`

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
	for _, in := range tx.BaseTx.Ins {
		in.FxID = secp256k1fx.ID
	}
	for _, out := range tx.BaseTx.Outs {
		out.FxID = secp256k1fx.ID
		out.InitCtx(ctx)
	}
}
