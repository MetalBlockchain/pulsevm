package txs

import "github.com/MetalBlockchain/metalgo/snow"

type UnsignedTx interface {
	snow.ContextInitializable
	SetBytes(unsignedBytes []byte)
	Bytes() []byte
	// Attempts to verify this transaction without any provided state.
	SyntacticVerify(ctx *snow.Context) error
	// Visit calls [visitor] with this transaction's concrete type
	Visit(visitor Visitor) error
}
