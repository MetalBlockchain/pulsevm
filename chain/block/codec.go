package block

import "github.com/MetalBlockchain/metalgo/codec"

var (
	Codec codec.Manager
)

func init() {
	Codec = codec.NewDefaultManager()
}
