package account

import (
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/metalgo/vms/types"
	"github.com/MetalBlockchain/pulsevm/chain/common"
	"github.com/MetalBlockchain/pulsevm/chain/name"
)

var _ common.Serializable = (*Account)(nil)

const AccountBillableSize = 61

type Account struct {
	Name         name.Name           `serialize:"true"`
	Created      common.Timestamp    `serialize:"true"`
	Priviliged   bool                `serialize:"true"`
	CodeHash     ids.ID              `serialize:"true"`
	CodeSequence uint32              `serialize:"true"`
	Abi          types.JSONByteSlice `serialize:"true"`
	AbiSequence  uint32              `serialize:"true"`
}

func (a *Account) Marshal(p *wrappers.Packer) ([]byte, error) {
	p.PackLong(uint64(a.Name))
	p.PackInt(uint32(a.Created))
	p.PackBool(a.Priviliged)
	p.PackFixedBytes(a.CodeHash[:])
	p.PackInt(a.CodeSequence)
	p.PackBytes(a.Abi)
	p.PackInt(a.AbiSequence)
	return p.Bytes, p.Err
}

func (a *Account) Unmarshal(p *wrappers.Packer) error {
	a.Name = name.Name(p.UnpackLong())
	a.Created = common.Timestamp(p.UnpackInt())
	a.Priviliged = p.UnpackBool()
	a.CodeHash = ids.ID(p.UnpackFixedBytes(ids.IDLen))
	a.CodeSequence = p.UnpackInt()
	a.Abi = p.UnpackBytes()
	a.AbiSequence = p.UnpackInt()
	return p.Err
}
