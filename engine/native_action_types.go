package engine

import (
	"github.com/MetalBlockchain/pulsevm/chain/authority"
	"github.com/MetalBlockchain/pulsevm/chain/name"
)

type NewAccount struct {
	Creator name.Name           `serialize:"true"`
	Name    name.Name           `serialize:"true"`
	Owner   authority.Authority `serialize:"true"`
	Active  authority.Authority `serialize:"true"`
}
