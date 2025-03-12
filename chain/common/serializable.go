package common

import "github.com/MetalBlockchain/metalgo/utils/wrappers"

type Serializable interface {
	Marshal(*wrappers.Packer) ([]byte, error)
	Unmarshal(*wrappers.Packer) error
}
