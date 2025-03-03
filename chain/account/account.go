package account

import (
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/common"
	"github.com/MetalBlockchain/pulsevm/chain/name"
)

var _ common.Serializable = (*Account)(nil)

const AccountBillableSize = 53

type Account struct {
	Name         name.Name        `serialize:"true"`
	Created      common.Timestamp `serialize:"true"`
	Priviliged   bool             `serialize:"true"`
	CodeHash     ids.ID           `serialize:"true"`
	CodeSequence uint32           `serialize:"true"`
}

func (a *Account) Marshal() ([]byte, error) {
	p := wrappers.Packer{
		MaxSize: 256 * units.KiB,
		Bytes:   make([]byte, 0, 128),
	}
	p.PackLong(uint64(a.Name))
	p.PackInt(uint32(a.Created))
	p.PackBool(a.Priviliged)
	p.PackBytes(a.CodeHash[:])
	p.PackInt(a.CodeSequence)
	return p.Bytes, p.Err
}

func (a *Account) Unmarshal(data []byte) error {
	p := wrappers.Packer{
		MaxSize: 256 * units.KiB,
		Bytes:   data,
	}
	a.Name = name.Name(p.UnpackLong())
	a.Created = common.Timestamp(p.UnpackInt())
	a.Priviliged = p.UnpackBool()
	a.CodeHash = ids.ID(p.UnpackBytes())
	a.CodeSequence = p.UnpackInt()
	return p.Err
}
