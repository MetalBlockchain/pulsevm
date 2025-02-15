package engine

import (
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/set"
	"github.com/MetalBlockchain/pulsevm/chain/authority"
)

type AuthorityChecker struct {
	ProvidedKeys []secp256k1.PublicKey
	UsedKeys     set.Set[*secp256k1.PublicKey]
}

func NewAuthorityChecker(providedKeys []secp256k1.PublicKey) *AuthorityChecker {
	return &AuthorityChecker{
		ProvidedKeys: providedKeys,
		UsedKeys:     set.NewSet[*secp256k1.PublicKey](0),
	}
}

func (a *AuthorityChecker) SatisfiesPermissionLevel(level authority.PermissionLevel) error {

	return nil
}
