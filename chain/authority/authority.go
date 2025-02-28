package authority

import (
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/hashing"
	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/common"
	"github.com/MetalBlockchain/pulsevm/chain/name"
)

var (
	_ common.Serializable = (*Permission)(nil)
	_ common.Serializable = (*Authority)(nil)
	_ common.Serializable = (*KeyWeight)(nil)
	_ common.Serializable = (*PermissionLevelWeight)(nil)
	_ common.Serializable = (*PermissionLevel)(nil)
)

type KeyWeight struct {
	Key    secp256k1.PublicKey `serialize:"true" json:"key"`
	Weight uint16              `serialize:"true" json:"weight"`
}

// Marshal implements common.Serializable.
func (k *KeyWeight) Marshal() ([]byte, error) {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   make([]byte, 0, 128),
	}
	pk.PackBytes(k.Key.Bytes())
	pk.PackShort(k.Weight)
	return pk.Bytes, pk.Err
}

// Unmarshal implements common.Serializable.
func (k *KeyWeight) Unmarshal(data []byte) error {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   data,
	}
	key, err := secp256k1.ToPublicKey(pk.UnpackBytes())
	if err != nil {
		return err
	}
	k.Key = *key
	k.Weight = pk.UnpackShort()
	return pk.Err
}

type PermissionLevel struct {
	Actor      name.Name `serialize:"true" json:"actor"`
	Permission name.Name `serialize:"true" json:"permission"`
}

// Marshal implements common.Serializable.
func (p *PermissionLevel) Marshal() ([]byte, error) {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   make([]byte, 0, 128),
	}
	pk.PackLong(uint64(p.Actor))
	pk.PackLong(uint64(p.Permission))
	return pk.Bytes, pk.Err
}

// Unmarshal implements common.Serializable.
func (p *PermissionLevel) Unmarshal(data []byte) error {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   data,
	}
	p.Actor = name.Name(pk.UnpackLong())
	p.Permission = name.Name(pk.UnpackLong())
	return pk.Err
}

type PermissionLevelWeight struct {
	Permission PermissionLevel `serialize:"true" json:"permission"`
	Weight     uint16          `serialize:"true" json:"weight"`
}

// Marshal implements common.Serializable.
func (p *PermissionLevelWeight) Marshal() ([]byte, error) {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   make([]byte, 0, 128),
	}
	permissionBytes, err := p.Permission.Marshal()
	if err != nil {
		return nil, err
	}
	pk.PackBytes(permissionBytes)
	pk.PackShort(p.Weight)
	return pk.Bytes, pk.Err
}

// Unmarshal implements common.Serializable.
func (p *PermissionLevelWeight) Unmarshal(data []byte) error {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   data,
	}
	var permissionLevel PermissionLevel
	if err := permissionLevel.Unmarshal(pk.UnpackBytes()); err != nil {
		return err
	}
	p.Weight = pk.UnpackShort()
	return pk.Err
}

type Authority struct {
	Threshold uint32                  `serialize:"true" json:"threshold"`
	Keys      []KeyWeight             `serialize:"true" json:"keys"`
	Accounts  []PermissionLevelWeight `serialize:"true" json:"accounts"`
}

// Marshal implements common.Serializable.
func (a *Authority) Marshal() ([]byte, error) {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   make([]byte, 0, 128),
	}
	pk.PackInt(a.Threshold)
	pk.PackInt(uint32(len(a.Keys))) // length of keys
	for _, key := range a.Keys {
		keyBytes, err := key.Marshal()
		if err != nil {
			return nil, err
		}
		pk.PackBytes(keyBytes)
	}
	pk.PackInt(uint32(len(a.Accounts))) // length of accounts
	for _, account := range a.Accounts {
		accountBytes, err := account.Marshal()
		if err != nil {
			return nil, err
		}
		pk.PackBytes(accountBytes)
	}
	return pk.Bytes, pk.Err
}

// Unmarshal implements common.Serializable.
func (a *Authority) Unmarshal(data []byte) error {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   data,
	}
	a.Threshold = pk.UnpackInt()
	keyLength := pk.UnpackInt()
	a.Keys = make([]KeyWeight, keyLength)
	for i := 0; i < int(keyLength); i++ {
		var keyWeight KeyWeight
		if err := keyWeight.Unmarshal(pk.UnpackBytes()); err != nil {
			return err
		}
		a.Keys[i] = keyWeight
	}
	accountLength := pk.UnpackInt()
	a.Accounts = make([]PermissionLevelWeight, accountLength)
	for i := 0; i < int(accountLength); i++ {
		var permissionLevelWeight PermissionLevelWeight
		if err := permissionLevelWeight.Unmarshal(pk.UnpackBytes()); err != nil {
			return err
		}
		a.Accounts[i] = permissionLevelWeight
	}
	return pk.Err
}

type Permission struct {
	ID          ids.ID           `serialize:"true"`
	Parent      ids.ID           `serialize:"true"`
	Owner       name.Name        `serialize:"true"`
	Name        name.Name        `serialize:"true"`
	LastUpdated common.Timestamp `serialize:"true"`
	LastUsed    common.Timestamp `serialize:"true"`
	Auth        Authority        `serialize:"true"`
}

func (p *Permission) Marshal() ([]byte, error) {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   make([]byte, 0, 128),
	}
	pk.PackBytes(p.ID[:])     // 32 bytes
	pk.PackBytes(p.Parent[:]) // 32 bytes
	pk.PackLong(uint64(p.Owner))
	pk.PackLong(uint64(p.Name))
	pk.PackInt(uint32(p.LastUpdated))
	pk.PackInt(uint32(p.LastUsed))
	authBytes, err := p.Auth.Marshal()
	if err != nil {
		return nil, err
	}
	pk.PackBytes(authBytes)
	return pk.Bytes, pk.Err
}

func (p *Permission) Unmarshal(data []byte) error {
	pk := wrappers.Packer{
		MaxSize: 128 * units.KiB,
		Bytes:   data,
	}
	p.ID = ids.ID(pk.UnpackBytes())
	p.Parent = ids.ID(pk.UnpackBytes())
	p.Owner = name.Name(pk.UnpackLong())
	p.Name = name.Name(pk.UnpackLong())
	p.LastUpdated = common.Timestamp(pk.UnpackInt())
	p.LastUsed = common.Timestamp(pk.UnpackInt())
	if err := p.Auth.Unmarshal(pk.UnpackBytes()); err != nil {
		return err
	}
	return pk.Err
}

func NewPermission(parent ids.ID, owner name.Name, name name.Name, auth *Authority) (*Permission, error) {
	id, err := GetPermissionID(owner, name)
	if err != nil {
		return nil, err
	}

	return &Permission{
		ID:          id,
		Parent:      parent,
		Owner:       owner,
		Name:        name,
		LastUpdated: 0,
		LastUsed:    0,
		Auth:        *auth,
	}, nil
}

func GetPermissionID(owner name.Name, name name.Name) (ids.ID, error) {
	// ID is calculated as SHA256(owner + name)
	id, err := ids.ToID(hashing.ComputeHash256(append(owner.Bytes(), name.Bytes()...)))
	if err != nil {
		return ids.Empty, err
	}
	return id, nil
}
