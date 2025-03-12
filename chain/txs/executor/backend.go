package executor

import (
	"github.com/MetalBlockchain/metalgo/snow"
)

type Backend struct {
	Ctx          *snow.Context
	Bootstrapped bool
}
