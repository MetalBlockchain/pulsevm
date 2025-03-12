package contract

import (
	"github.com/MetalBlockchain/metalgo/ids"
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

func (c *Code) Marshal(pk *wrappers.Packer) ([]byte, error) {
	pk.PackFixedBytes(c.Hash[:])
	pk.PackBytes(c.Code)
	pk.PackInt(c.RefCount)
	return pk.Bytes, pk.Err
}

func (c *Code) Unmarshal(pk *wrappers.Packer) error {
	c.Hash = ids.ID(pk.UnpackFixedBytes(ids.IDLen))
	c.Code = pk.UnpackBytes()
	c.RefCount = pk.UnpackInt()
	return pk.Err
}
