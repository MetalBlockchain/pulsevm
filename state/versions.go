package state

import "github.com/MetalBlockchain/metalgo/ids"

type Versions interface {
	// GetState returns the state of the chain after [blkID] has been accepted.
	// If the state is not known, `false` will be returned.
	GetState(blkID ids.ID) (Chain, bool)
}
