package block

import (
	"github.com/MetalBlockchain/metalgo/codec"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
)

const CodecVersion = txs.CodecVersion

var (
	Codec codec.Manager
)

func init() {
	Codec = codec.NewDefaultManager()
}
