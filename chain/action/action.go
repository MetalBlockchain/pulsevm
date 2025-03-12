package action

import (
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/metalgo/vms/types"
	"github.com/MetalBlockchain/pulsevm/chain/authority"
	"github.com/MetalBlockchain/pulsevm/chain/common"
	"github.com/MetalBlockchain/pulsevm/chain/name"
)

var _ common.Serializable = (*Action)(nil)

type Action struct {
	Account       name.Name                   `serialize:"true" json:"account"`
	Name          name.Name                   `serialize:"true" json:"name"`
	Data          types.JSONByteSlice         `serialize:"true" json:"data"`
	Authorization []authority.PermissionLevel `serialize:"true" json:"authorization"`
}

func (a *Action) Marshal(p *wrappers.Packer) ([]byte, error) {
	p.PackLong(uint64(a.Account))
	p.PackLong(uint64(a.Name))
	p.PackBytes(a.Data)
	p.PackInt(uint32(len(a.Authorization)))
	for _, auth := range a.Authorization {
		if _, err := auth.Marshal(p); err != nil {
			return nil, err
		}
	}
	return p.Bytes, p.Err
}

func (a *Action) Unmarshal(p *wrappers.Packer) error {
	a.Account = name.Name(p.UnpackLong())
	a.Name = name.Name(p.UnpackLong())
	a.Data = p.UnpackBytes()
	numAuth := p.UnpackInt()
	a.Authorization = make([]authority.PermissionLevel, numAuth)
	for i := range int(numAuth) {
		var auth authority.PermissionLevel
		if err := auth.Unmarshal(p); err != nil {
			return err
		}
		a.Authorization[i] = auth
	}
	return p.Err
}
