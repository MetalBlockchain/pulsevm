package account

import (
	"testing"

	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/name"
	"github.com/stretchr/testify/assert"
)

func TestAccountBillableSize(t *testing.T) {
	account := &Account{
		Name:       name.NewNameFromString("pulse"),
		Priviliged: false,
	}
	size, err := account.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
	assert.NoError(t, err)
	assert.Equal(t, AccountBillableSize, len(size))
}
