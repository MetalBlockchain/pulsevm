package executor

import (
	"github.com/MetalBlockchain/metalgo/codec"
	"github.com/MetalBlockchain/metalgo/snow"
	"github.com/MetalBlockchain/metalgo/utils"
	"github.com/MetalBlockchain/metalgo/utils/timer/mockable"
)

type Backend struct {
	Ctx          *snow.Context
	Clk          *mockable.Clock
	Bootstrapped *utils.Atomic[bool]
	Codec        codec.Manager
}
