package account

import (
	"testing"

	"github.com/MetalBlockchain/pulsevm/chain/name"
	"github.com/stretchr/testify/assert"
)

func TestAccountBillableSize(t *testing.T) {
	account := &Account{
		Name:       name.NewNameFromString("pulse"),
		Priviliged: false,
	}
	size, err := account.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, AccountBillableSize, len(size))
}
