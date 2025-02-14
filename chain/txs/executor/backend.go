package executor

import (
	"github.com/MetalBlockchain/metalgo/codec"
	"github.com/MetalBlockchain/metalgo/snow"
)

type Backend struct {
	Ctx          *snow.Context
	Codec        codec.Manager
	Bootstrapped bool
}
