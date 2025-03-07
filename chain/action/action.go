package action

import (
	"github.com/MetalBlockchain/metalgo/vms/types"
	"github.com/MetalBlockchain/pulsevm/chain/authority"
	"github.com/MetalBlockchain/pulsevm/chain/name"
)

type Action struct {
	Account       name.Name                   `serialize:"true" json:"account"`
	Name          name.Name                   `serialize:"true" json:"name"`
	Data          types.JSONByteSlice         `serialize:"true" json:"data"`
	Authorization []authority.PermissionLevel `serialize:"true" json:"authorization"`
}
