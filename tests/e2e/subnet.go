// Package e2e provides fixtures for booting a PulseVM chain on an ephemeral
// tmpnet network and exercising it end to end.
package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/tests/fixture/tmpnet"
)

const (
	// SubnetName is the tmpnet-local handle for the subnet hosting the PulseVM
	// chain. It is not the SubnetID, which is only known once the network is
	// running.
	SubnetName = "pulsevm"

	// VMID is the ID metalgo resolves the plugin binary by: the plugin must be
	// installed at <plugin-dir>/<VMID>. It is "pulsevm" as ASCII, zero-padded
	// to 32 bytes -- the same derivation scripts/install.sh hardcodes.
	VMID = "rXcAFxZvio99epp6TzEwYfexCfPAbJuBTMsjUUoiT7PkVykNs"
)

// RepoRoot returns the path to the repository root, derived from this file's
// location so that tests can be run from any working directory.
func RepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// This package lives at <root>/tests/e2e.
	return filepath.Abs(filepath.Join(wd, "..", ".."))
}

// GenesisBytes reads the chain genesis shipped in the repository. PulseVM's
// genesis is Antelope-shaped JSON and is passed through to the VM verbatim;
// metalgo never parses it.
func GenesisBytes() ([]byte, error) {
	root, err := RepoRoot()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root, "genesis.json")
	genesis, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading genesis at %s: %w", path, err)
	}
	return genesis, nil
}

// ChainConfig reads the producer configuration shipped in the repository.
//
// PulseVM requires a non-empty chain config: Controller::initialize parses it
// before touching genesis, and an empty value fails with "failed to parse node
// config JSON: EOF while parsing a value at line 1 column 0". The config it
// expects is a single object -- producer_name, producer_key and an optional
// db_size -- but chain_config.json stores a map of node name to that object,
// which is the shape metal-network-runner consumes.
//
// tmpnet applies one chain config to every node, so a single entry is
// extracted. That is faithful to the repository's intent: all five entries in
// chain_config.json declare the same producer identity.
func ChainConfig() (string, error) {
	root, err := RepoRoot()
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "chain_config.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading chain config at %s: %w", path, err)
	}

	var perNode map[string]json.RawMessage
	if err := json.Unmarshal(raw, &perNode); err != nil {
		return "", fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(perNode) == 0 {
		return "", fmt.Errorf("%s declares no node configurations", path)
	}

	// Sort so the selection is deterministic across runs.
	names := make([]string, 0, len(perNode))
	for name := range perNode {
		names = append(names, name)
	}
	sort.Strings(names)

	return string(perNode[names[0]]), nil
}

// NewSubnet returns the tmpnet definition of a subnet running a single PulseVM
// chain, validated by the provided nodes.
func NewSubnet(nodes ...*tmpnet.Node) (*tmpnet.Subnet, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("a subnet must be validated by at least one node")
	}

	vmID, err := ids.FromString(VMID)
	if err != nil {
		return nil, fmt.Errorf("parsing VM ID %q: %w", VMID, err)
	}

	genesis, err := GenesisBytes()
	if err != nil {
		return nil, err
	}

	chainConfig, err := ChainConfig()
	if err != nil {
		return nil, err
	}

	return &tmpnet.Subnet{
		Name: SubnetName,
		Config: tmpnet.ConfigMap{
			// Reduced from the 1s default so tx acceptance is not dominated by
			// the proposer delay. PulseVM checks its mempool every 500ms.
			"proposerMinBlockDelay": 0,
		},
		Chains: []*tmpnet.Chain{
			{
				VMID:    vmID,
				Genesis: genesis,
				Config:  chainConfig,
				// VersionArgs is deliberately empty: the pulsevm binary has no
				// CLI surface -- main() reads AVALANCHE_VM_RUNTIME_ENGINE_ADDR
				// and panics if it is unset -- so tmpnet's rpcchainvm version
				// pre-check cannot be used yet. See TestPluginProtocolVersion,
				// which asserts the compatibility this would otherwise verify.
				VersionArgs: nil,
			},
		},
		ValidatorIDs: tmpnet.NodesToIDs(nodes...),
	}, nil
}
