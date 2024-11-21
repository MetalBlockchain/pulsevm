package txs

import (
	"github.com/MetalBlockchain/metalgo/codec"
)

const CodecVersion = 0

var (
	Codec codec.Manager
)

func init() {
	Codec = codec.NewDefaultManager()
}
