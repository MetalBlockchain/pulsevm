package contract

import (
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/metalgo/vms/types"
	"github.com/MetalBlockchain/pulsevm/chain/common"
)

var _ common.Serializable = (*Code)(nil)

type Code struct {
	Hash     ids.ID              `serialize:"true" json:"hash"`
	Code     types.JSONByteSlice `serialize:"true" json:"code"`
	RefCount uint32              `serialize:"true" json:"ref_count"`
}

func (c *Code) Marshal() ([]byte, error) {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   make([]byte, 0, 128),
	}
	pk.PackBytes(c.Hash[:])
	pk.PackBytes(c.Code)
	pk.PackInt(c.RefCount)
	return pk.Bytes, pk.Err
}

func (c *Code) Unmarshal(data []byte) error {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   data,
	}
	c.Hash = ids.ID(pk.UnpackBytes())
	c.Code = pk.UnpackBytes()
	c.RefCount = pk.UnpackInt()
	return pk.Err
}
