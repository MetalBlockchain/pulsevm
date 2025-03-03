package engine

import (
	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/metalgo/vms/types"
	"github.com/MetalBlockchain/pulsevm/chain/authority"
	"github.com/MetalBlockchain/pulsevm/chain/common"
	"github.com/MetalBlockchain/pulsevm/chain/name"
)

var (
	_ common.Serializable = (*NewAccount)(nil)
	_ common.Serializable = (*SetCode)(nil)
	_ common.Serializable = (*SetAbi)(nil)
)

type NewAccount struct {
	Creator name.Name           `serialize:"true"`
	Name    name.Name           `serialize:"true"`
	Owner   authority.Authority `serialize:"true"`
	Active  authority.Authority `serialize:"true"`
}

func (n *NewAccount) Marshal() ([]byte, error) {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   make([]byte, 0, 128),
	}
	pk.PackLong(uint64(n.Creator))
	pk.PackLong(uint64(n.Name))
	ownerBytes, err := n.Owner.Marshal()
	if err != nil {
		return nil, err
	}
	pk.PackBytes(ownerBytes)
	activeBytes, err := n.Active.Marshal()
	if err != nil {
		return nil, err
	}
	pk.PackBytes(activeBytes)
	return pk.Bytes, pk.Err
}

func (n *NewAccount) Unmarshal(data []byte) error {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   data,
	}
	n.Creator = name.Name(pk.UnpackLong())
	n.Name = name.Name(pk.UnpackLong())
	ownerBytes := pk.UnpackBytes()
	if err := n.Owner.Unmarshal(ownerBytes); err != nil {
		return err
	}
	activeBytes := pk.UnpackBytes()
	if err := n.Active.Unmarshal(activeBytes); err != nil {
		return err
	}
	return pk.Err
}

type SetCode struct {
	Account name.Name           `serialize:"true"`
	Code    types.JSONByteSlice `serialize:"true"`
}

func (s *SetCode) Marshal() ([]byte, error) {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   make([]byte, 0, 128),
	}
	pk.PackLong(uint64(s.Account))
	pk.PackBytes(s.Code)
	return pk.Bytes, pk.Err
}

func (s *SetCode) Unmarshal(data []byte) error {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   data,
	}
	s.Account = name.Name(pk.UnpackLong())
	s.Code = pk.UnpackBytes()
	return pk.Err
}

type SetAbi struct {
	Account name.Name           `serialize:"true"`
	Abi     types.JSONByteSlice `serialize:"true"`
}

func (s *SetAbi) Marshal() ([]byte, error) {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   make([]byte, 0, 128),
	}
	pk.PackLong(uint64(s.Account))
	pk.PackBytes(s.Abi)
	return pk.Bytes, pk.Err
}

func (s *SetAbi) Unmarshal(data []byte) error {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   data,
	}
	s.Account = name.Name(pk.UnpackLong())
	s.Abi = pk.UnpackBytes()
	return pk.Err
}
