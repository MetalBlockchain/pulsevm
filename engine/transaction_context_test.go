package engine

import (
	"testing"

	"github.com/MetalBlockchain/metalgo/database"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/account"
	"github.com/MetalBlockchain/pulsevm/chain/action"
	"github.com/MetalBlockchain/pulsevm/chain/authority"
	"github.com/MetalBlockchain/pulsevm/chain/name"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/MetalBlockchain/pulsevm/state/statemock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestNewAccount(t *testing.T) {
	key, err := secp256k1.ToPrivateKey(testPrivateKeyBytes)
	assert.NoError(t, err)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	newAccount := &NewAccount{
		Creator: name.NewNameFromString("pulse"),
		Name:    name.NewNameFromString("glenn"),
		Owner: authority.Authority{
			Threshold: 1,
			Keys: []authority.KeyWeight{
				authority.KeyWeight{
					Key:    *key.PublicKey(),
					Weight: 1,
				},
			},
		},
		Active: authority.Authority{
			Threshold: 1,
			Keys: []authority.KeyWeight{
				authority.KeyWeight{
					Key:    *key.PublicKey(),
					Weight: 1,
				},
			},
		},
	}
	newAccountBytes, err := newAccount.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
	assert.NoError(t, err)
	baseTx := &txs.BaseTx{
		BlockchainID: ids.Empty,
		Actions: []action.Action{
			action.Action{
				Account: name.NewNameFromString("pulse"),
				Name:    name.NewNameFromString("newaccount"),
				Authorization: []authority.PermissionLevel{
					authority.PermissionLevel{Actor: name.NewNameFromString("pulse"), Permission: name.NewNameFromString("active")},
				},
				Data: newAccountBytes,
			},
		},
	}
	tx := txs.Tx{
		Unsigned: baseTx,
	}
	err = tx.Initialize()
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
	state.EXPECT().GetAccount(name.NewNameFromString("pulse")).Return(&account.Account{
		Name:       name.NewNameFromString("pulse"),
		Priviliged: true,
	}, nil)
	state.EXPECT().GetAccount(name.NewNameFromString("glenn")).Return(nil, database.ErrNotFound)
	state.EXPECT().ModifyAccount(gomock.Any())
	state.EXPECT().AddPermission(gomock.Any()).Times(2)

	// Test
	tc, err := NewTransactionContext(baseTx, tx.Signatures, state)
	assert.NoError(t, err)
	err = tc.Execute()
	assert.NoError(t, err)
}

func TestSetCode(t *testing.T) {
	key, err := secp256k1.ToPrivateKey(testPrivateKeyBytes)
	assert.NoError(t, err)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	setCode := &SetCode{
		Account: name.NewNameFromString("pulse"),
		Code:    []byte{0x01, 0x02, 0x03},
	}
	setCodeBytes, err := setCode.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
	assert.NoError(t, err)
	codeHash, err := ids.FromString("2a2xz3zWjg7iZeqbqJFtjhpBjVeBDY6UQKS9zHJ7Bnz9PNPoj")
	assert.NoError(t, err)
	baseTx := &txs.BaseTx{
		BlockchainID: ids.Empty,
		Actions: []action.Action{
			action.Action{
				Account: name.NewNameFromString("pulse"),
				Name:    name.NewNameFromString("setcode"),
				Authorization: []authority.PermissionLevel{
					authority.PermissionLevel{Actor: name.NewNameFromString("pulse"), Permission: name.NewNameFromString("active")},
				},
				Data: setCodeBytes,
			},
		},
	}
	tx := txs.Tx{
		Unsigned: baseTx,
	}
	err = tx.Initialize()
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
	state.EXPECT().GetAccount(name.NewNameFromString("pulse")).Return(&account.Account{
		Name:       name.NewNameFromString("pulse"),
		Priviliged: true,
		CodeHash:   ids.Empty,
	}, nil)
	state.EXPECT().GetCode(codeHash).Return(nil, database.ErrNotFound)
	state.EXPECT().ModifyCode(gomock.Any())
	state.EXPECT().ModifyAccount(gomock.Any())

	// Test
	tc, err := NewTransactionContext(baseTx, tx.Signatures, state)
	assert.NoError(t, err)
	err = tc.Execute()
	assert.NoError(t, err)
}

func TestSetAbi(t *testing.T) {
	key, err := secp256k1.ToPrivateKey(testPrivateKeyBytes)
	assert.NoError(t, err)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	setAbi := &SetAbi{
		Account: name.NewNameFromString("pulse"),
		Abi:     []byte{0x01, 0x02, 0x03},
	}
	setAbiBytes, err := setAbi.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
	assert.NoError(t, err)
	baseTx := &txs.BaseTx{
		BlockchainID: ids.Empty,
		Actions: []action.Action{
			action.Action{
				Account: name.NewNameFromString("pulse"),
				Name:    name.NewNameFromString("setabi"),
				Authorization: []authority.PermissionLevel{
					authority.PermissionLevel{Actor: name.NewNameFromString("pulse"), Permission: name.NewNameFromString("active")},
				},
				Data: setAbiBytes,
			},
		},
	}
	tx := txs.Tx{
		Unsigned: baseTx,
	}
	err = tx.Initialize()
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
	state.EXPECT().GetAccount(name.NewNameFromString("pulse")).Return(&account.Account{
		Name:       name.NewNameFromString("pulse"),
		Priviliged: true,
		CodeHash:   ids.Empty,
	}, nil)
	state.EXPECT().ModifyAccount(gomock.Any())

	// Test
	tc, err := NewTransactionContext(baseTx, tx.Signatures, state)
	assert.NoError(t, err)
	err = tc.Execute()
	assert.NoError(t, err)
}
