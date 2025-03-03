package engine

import (
	"testing"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/pulsevm/chain/action"
	"github.com/MetalBlockchain/pulsevm/chain/authority"
	"github.com/MetalBlockchain/pulsevm/chain/name"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/MetalBlockchain/pulsevm/state/statemock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

var (
	testPrivateKeyBytes = []byte{
		0xd3, 0xd1, 0x37, 0x7d, 0x21, 0x97, 0x91, 0xb5,
		0x4b, 0xcb, 0xce, 0x7a, 0xb1, 0x48, 0x87, 0x12,
		0x35, 0x85, 0xa2, 0xa1, 0x81, 0xbc, 0x8a, 0x6d,
		0x88, 0x20, 0x58, 0x0f, 0x01, 0x8e, 0x80, 0x7f,
	}
)

func TestKeyLevelWeight(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	parser, err := txs.NewParser()
	assert.NoError(t, err)
	tx := txs.Tx{
		Unsigned: &txs.BaseTx{
			NetworkID:    1,
			BlockchainID: ids.Empty,
			Actions: []action.Action{
				action.Action{
					Account: name.NewNameFromString("pulse"),
					Name:    name.NewNameFromString("newaccount"),
					Authorization: []authority.PermissionLevel{
						authority.PermissionLevel{Actor: name.NewNameFromString("pulse"), Permission: name.NewNameFromString("active")},
					},
					Data: nil,
				},
			},
		},
	}
	err = tx.Initialize(parser.Codec())
	assert.NoError(t, err)
	key, err := secp256k1.ToPrivateKey(testPrivateKeyBytes)
	assert.NoError(t, err)
	err = tx.Sign(key)
	assert.NoError(t, err)

	// Setup mock
	state := statemock.NewMockState(ctrl)
	state.EXPECT().GetPermission(name.NewNameFromString("pulse"), name.NewNameFromString("active")).Return(&authority.Permission{
		ID:     ids.Empty,
		Parent: ids.Empty,
		Owner:  name.NewNameFromString("pulse"),
		Name:   name.NewNameFromString("active"),
		Auth: authority.Authority{
			Threshold: 1,
			Keys: []authority.KeyWeight{
				authority.KeyWeight{
					Key:    *key.PublicKey(),
					Weight: 1,
				},
			},
		},
	}, nil)

	ac, err := NewAuthorityChecker(tx.Unsigned.Bytes(), tx.Signatures, state)
	assert.NoError(t, err)
	err = ac.SatisfiesPermissionLevel(authority.PermissionLevel{Actor: name.NewNameFromString("pulse"), Permission: name.NewNameFromString("active")})
	assert.NoError(t, err)
}

func TestAccountLevelWeight(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	parser, err := txs.NewParser()
	assert.NoError(t, err)
	tx := txs.Tx{
		Unsigned: &txs.BaseTx{
			NetworkID:    1,
			BlockchainID: ids.Empty,
			Actions: []action.Action{
				action.Action{
					Account: name.NewNameFromString("pulse"),
					Name:    name.NewNameFromString("newaccount"),
					Authorization: []authority.PermissionLevel{
						authority.PermissionLevel{Actor: name.NewNameFromString("pulse"), Permission: name.NewNameFromString("secondary")},
					},
					Data: nil,
				},
			},
		},
	}
	err = tx.Initialize(parser.Codec())
	assert.NoError(t, err)
	key, err := secp256k1.ToPrivateKey(testPrivateKeyBytes)
	assert.NoError(t, err)
	err = tx.Sign(key)
	assert.NoError(t, err)

	// Setup mock
	state := statemock.NewMockState(ctrl)
	state.EXPECT().GetPermission(name.NewNameFromString("pulse"), name.NewNameFromString("secondary")).Return(&authority.Permission{
		ID:     ids.Empty,
		Parent: ids.Empty,
		Owner:  name.NewNameFromString("pulse"),
		Name:   name.NewNameFromString("secondary"),
		Auth: authority.Authority{
			Threshold: 1,
			Accounts: []authority.PermissionLevelWeight{
				authority.PermissionLevelWeight{
					Permission: authority.PermissionLevel{Actor: name.NewNameFromString("pulse"), Permission: name.NewNameFromString("active")},
					Weight:     1,
				},
			},
		},
	}, nil)
	state.EXPECT().GetPermission(name.NewNameFromString("pulse"), name.NewNameFromString("active")).Return(&authority.Permission{
		ID:     ids.Empty,
		Parent: ids.Empty,
		Owner:  name.NewNameFromString("pulse"),
		Name:   name.NewNameFromString("active"),
		Auth: authority.Authority{
			Threshold: 1,
			Keys: []authority.KeyWeight{
				authority.KeyWeight{
					Key:    *key.PublicKey(),
					Weight: 1,
				},
			},
		},
	}, nil)

	ac, err := NewAuthorityChecker(tx.Unsigned.Bytes(), tx.Signatures, state)
	assert.NoError(t, err)
	err = ac.SatisfiesPermissionLevel(authority.PermissionLevel{Actor: name.NewNameFromString("pulse"), Permission: name.NewNameFromString("secondary")})
	assert.NoError(t, err)
}
