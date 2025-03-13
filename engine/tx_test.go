package engine

import (
	"encoding/hex"
	"testing"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/cb58"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/action"
	"github.com/MetalBlockchain/pulsevm/chain/authority"
	"github.com/MetalBlockchain/pulsevm/chain/name"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/stretchr/testify/assert"
)

func TestXxx(t *testing.T) {
	key, err := cb58.Decode("frqNAoTevNse58hUoJMDzPXDbfNicjCGjNz5VDgqqHJbhBBG9")
	assert.NoError(t, err)
	privateKey, err := secp256k1.ToPrivateKey(key[:])
	newAccount := &NewAccount{
		Creator: name.NewNameFromString("pulse"),
		Name:    name.NewNameFromString("glenn"),
		Owner: authority.Authority{
			Threshold: 1,
			Keys: []authority.KeyWeight{
				authority.KeyWeight{
					Key:    *privateKey.PublicKey(),
					Weight: 1,
				},
			},
		},
		Active: authority.Authority{
			Threshold: 1,
			Keys: []authority.KeyWeight{
				authority.KeyWeight{
					Key:    *privateKey.PublicKey(),
					Weight: 1,
				},
			},
		},
	}
	newAccountBytes, err := newAccount.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
	assert.NoError(t, err)
	tx := txs.Tx{
		Unsigned: &txs.BaseTx{
			BlockchainID: ids.Empty,
			Actions: []action.Action{
				action.Action{
					Account: name.NewNameFromString("pulse"),
					Name:    name.NewNameFromString("newaccount"),
					Data:    newAccountBytes,
					Authorization: []authority.PermissionLevel{
						authority.PermissionLevel{
							Actor:      name.NewNameFromString("pulse"),
							Permission: name.NewNameFromString("active"),
						},
					},
				},
			},
		},
		Signatures: make([][]byte, 0),
	}
	err = tx.Initialize()
	assert.NoError(t, err)
	err = tx.Sign(privateKey)
	assert.NoError(t, err)
	bytes, err := tx.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
	assert.NoError(t, err)
	assert.Equal(t, "000", hex.EncodeToString(bytes))
}
