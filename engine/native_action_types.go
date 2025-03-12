package engine

import (
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

func (n *NewAccount) Marshal(pk *wrappers.Packer) ([]byte, error) {
	pk.PackLong(uint64(n.Creator))
	pk.PackLong(uint64(n.Name))
	_, err := n.Owner.Marshal(pk)
	if err != nil {
		return nil, err
	}
	_, err = n.Active.Marshal(pk)
	if err != nil {
		return nil, err
	}
	return pk.Bytes, pk.Err
}

func (n *NewAccount) Unmarshal(pk *wrappers.Packer) error {
	n.Creator = name.Name(pk.UnpackLong())
	n.Name = name.Name(pk.UnpackLong())
	if err := n.Owner.Unmarshal(pk); err != nil {
		return err
	}
	if err := n.Active.Unmarshal(pk); err != nil {
		return err
	}
	return pk.Err
}

type SetCode struct {
	Account name.Name           `serialize:"true"`
	Code    types.JSONByteSlice `serialize:"true"`
}

func (s *SetCode) Marshal(pk *wrappers.Packer) ([]byte, error) {
	pk.PackLong(uint64(s.Account))
	pk.PackBytes(s.Code)
	return pk.Bytes, pk.Err
}

func (s *SetCode) Unmarshal(pk *wrappers.Packer) error {
	s.Account = name.Name(pk.UnpackLong())
	s.Code = pk.UnpackBytes()
	return pk.Err
}

type SetAbi struct {
	Account name.Name           `serialize:"true"`
	Abi     types.JSONByteSlice `serialize:"true"`
}

func (s *SetAbi) Marshal(pk *wrappers.Packer) ([]byte, error) {
	pk.PackLong(uint64(s.Account))
	pk.PackBytes(s.Abi)
	return pk.Bytes, pk.Err
}

func (s *SetAbi) Unmarshal(pk *wrappers.Packer) error {
	s.Account = name.Name(pk.UnpackLong())
	s.Abi = pk.UnpackBytes()
	return pk.Err
}
