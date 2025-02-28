package engine

import (
	"fmt"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/set"
	"github.com/MetalBlockchain/pulsevm/chain/authority"
	"github.com/MetalBlockchain/pulsevm/state"
)

type AuthorityChecker struct {
	Signatures           [][]byte
	ProvidedKeys         set.Set[ids.ShortID]
	UsedKeys             set.Set[ids.ShortID]
	SatisfiedAuthorities set.Set[authority.PermissionLevel]
	State                state.Chain
}

func NewAuthorityChecker(txBytes []byte, signatures [][]byte, state state.Chain) (*AuthorityChecker, error) {
	var cache secp256k1.RecoverCache
	providedKeys := set.NewSet[ids.ShortID](0)

	for _, signature := range signatures {
		key, err := cache.RecoverPublicKey(txBytes, signature[:])
		if err != nil {
			return nil, fmt.Errorf("failed to recover public key: %w", err)
		}
		providedKeys.Add(key.Address())
	}

	return &AuthorityChecker{
		Signatures:           signatures,
		ProvidedKeys:         providedKeys,
		UsedKeys:             set.NewSet[ids.ShortID](0),
		SatisfiedAuthorities: set.NewSet[authority.PermissionLevel](0),
		State:                state,
	}, nil
}

func (a *AuthorityChecker) SatisfiesPermissionLevel(level authority.PermissionLevel) error {
	return a.satisfiesPermissionLevel(level, 0)
}

func (a *AuthorityChecker) satisfiesPermissionLevel(level authority.PermissionLevel, recursionDepth int) error {
	if recursionDepth > 10 {
		return fmt.Errorf("recursion depth exceeded")
	}
	if a.SatisfiedAuthorities.Contains(level) {
		return nil
	}
	perm, err := a.State.GetPermission(level.Actor, level.Permission)
	if err != nil {
		return fmt.Errorf("permission not found: %s@%s", level.Actor, level.Permission)
	}

	// weight we have been able to claim so far
	var weight uint16

	for _, key := range perm.Auth.Keys {
		if a.ProvidedKeys.Contains(key.Key.Address()) {
			a.UsedKeys.Add(key.Key.Address())
			weight += key.Weight
		}
	}

	if weight >= uint16(perm.Auth.Threshold) {
		a.SatisfiedAuthorities.Add(level)
		return nil
	}

	for _, account := range perm.Auth.Accounts {
		if err := a.satisfiesPermissionLevel(account.Permission, recursionDepth+1); err == nil {
			weight += account.Weight
		}
	}

	if weight >= uint16(perm.Auth.Threshold) {
		a.SatisfiedAuthorities.Add(level)
		return nil
	}

	return fmt.Errorf("permission level not satisfied: %s@%s", level.Actor, level.Permission)
}
