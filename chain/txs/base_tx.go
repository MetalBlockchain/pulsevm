package txs

import (
	"errors"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/action"
)

var (
	_ UnsignedTx = (*BaseTx)(nil)

	ErrNilTx = errors.New("tx is nil")
)

type BaseTx struct {
	BlockchainID ids.ID          `serialize:"true" json:"blockchainID"` // ID of the chain on which this transaction exists (prevents replay attacks)
	Actions      []action.Action `serialize:"true" json:"actions"`      // Actions this transaction will execute

	// true iff this transaction has already passed syntactic verification
	SyntacticallyVerified bool `json:"-"`

	unsignedBytes []byte // Unsigned byte representation of this data
}

func (tx *BaseTx) Marshal(p *wrappers.Packer) ([]byte, error) {
	p.PackFixedBytes(tx.BlockchainID[:])
	p.PackInt(uint32(len(tx.Actions)))
	for _, action := range tx.Actions {
		if _, err := action.Marshal(p); err != nil {
			return nil, err
		}
	}
	return p.Bytes, p.Err
}

// Unmarshal implements UnsignedTx.
func (tx *BaseTx) Unmarshal(p *wrappers.Packer) error {
	tx.BlockchainID = ids.ID(p.UnpackFixedBytes(ids.IDLen))
	numActions := p.UnpackInt()
	tx.Actions = make([]action.Action, numActions)
	for i := range int(numActions) {
		var action action.Action
		if err := action.Unmarshal(p); err != nil {
			return err
		}
		tx.Actions[i] = action
	}
	return p.Err
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
