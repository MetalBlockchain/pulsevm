package block

import (
	"github.com/MetalBlockchain/metalgo/codec"
	"github.com/MetalBlockchain/metalgo/codec/linearcodec"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
)

const CodecVersion = txs.CodecVersion

var (
	Codec codec.Manager
)

func init() {
	c := linearcodec.NewDefault()

	errs := wrappers.Errs{}
	errs.Add(
		c.RegisterType(&StandardBlock{}),
	)

	Codec = codec.NewDefaultManager()
	errs.Add(Codec.RegisterCodec(CodecVersion, c))

	if errs.Errored() {
		panic(errs.Err)
	}
}
