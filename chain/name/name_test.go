package name

import (
	"encoding/hex"
	"testing"

	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/stretchr/testify/assert"
)

func TestXxx(t *testing.T) {
	n := NewNameFromString("eosio")
	packer := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   make([]byte, 0, 128),
	}
	packer.PackLong(uint64(n))
	assert.NoError(t, packer.Err)
	encoded := hex.EncodeToString(packer.Bytes)
	assert.Equal(t, "5530ea0000000000", encoded)
}
