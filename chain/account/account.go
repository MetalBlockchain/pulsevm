package account

import (
	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/common"
	"github.com/MetalBlockchain/pulsevm/chain/name"
)

var _ common.Serializable = (*Account)(nil)

const AccountBillableSize = 13

type Account struct {
	Name       name.Name        `serialize:"true"`
	Created    common.Timestamp `serialize:"true"`
	Priviliged bool             `serialize:"true"`
}

func (a *Account) Marshal() ([]byte, error) {
	p := wrappers.Packer{
		MaxSize: 256 * units.KiB,
		Bytes:   make([]byte, 0, 128),
	}
	p.PackLong(uint64(a.Name))
	p.PackInt(uint32(a.Created))
	p.PackBool(a.Priviliged)
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
	return p.Err
}
