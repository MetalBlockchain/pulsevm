package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/MetalBlockchain/metalgo/api/info"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/tests"
	"github.com/MetalBlockchain/metalgo/tests/fixture/tmpnet"
	"github.com/stretchr/testify/require"
)

const (
	// nodeCount is the validator set size. Five matches the topology the
	// repository README documents for metal-network-runner, so behaviour
	// observed here is comparable to a manual boot.
	nodeCount = 5

	// defaultBootstrapTimeout covers node start, subnet creation, the node
	// restart required to track the new subnet, and the chain reporting
	// healthy. Override with PULSEVM_BOOTSTRAP_TIMEOUT (a Go duration) when
	// running against a debug build, whose controller initialization is
	// substantially slower than a release build's.
	defaultBootstrapTimeout = 5 * time.Minute

	// BootstrapTimeoutEnvName overrides defaultBootstrapTimeout.
	BootstrapTimeoutEnvName = "PULSEVM_BOOTSTRAP_TIMEOUT"

	teardownTimeout = 2 * time.Minute
)

// bootstrapTimeout returns the network start timeout, honouring an override.
func bootstrapTimeout(t *testing.T) time.Duration {
	t.Helper()
	raw := os.Getenv(BootstrapTimeoutEnvName)
	if raw == "" {
		return defaultBootstrapTimeout
	}
	d, err := time.ParseDuration(raw)
	require.NoError(t, err, "invalid %s=%q", BootstrapTimeoutEnvName, raw)
	return d
}

// StartNetwork boots an ephemeral network running a PulseVM chain and
// registers its teardown with the test. It returns the running network.
//
// Every test that needs a chain goes through here, so the lifecycle is
// identical whether one test runs or the whole suite does.
func StartNetwork(t *testing.T) *tmpnet.Network {
	t.Helper()
	require := require.New(t)

	metalGoPath, err := MetalGoPath()
	require.NoError(err)

	pluginDir, err := PluginDir()
	require.NoError(err)

	pluginPath, err := CheckPluginInstalled()
	require.NoError(err)
	t.Logf("using PulseVM plugin at %s", pluginPath)

	nodes := tmpnet.NewNodesOrPanic(nodeCount)

	subnet, err := NewSubnet(nodes...)
	require.NoError(err)

	network := &tmpnet.Network{
		Owner:        "pulsevm-e2e",
		DefaultFlags: tmpnet.DefaultE2EFlags(),
		DefaultRuntimeConfig: tmpnet.NodeRuntimeConfig{
			Process: &tmpnet.ProcessRuntimeConfig{
				AvalancheGoPath: metalGoPath,
				PluginDir:       pluginDir,
			},
		},
		Nodes:   nodes,
		Subnets: []*tmpnet.Subnet{subnet},
	}

	log := tests.NewDefaultLogger("pulsevm-e2e")

	ctx, cancel := context.WithTimeout(context.Background(), bootstrapTimeout(t))
	defer cancel()

	// Registered before the error check so that a partially started network is
	// still torn down -- otherwise a failure mid-bootstrap leaks node processes.
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), teardownTimeout)
		defer stopCancel()
		if err := network.Stop(stopCtx); err != nil {
			t.Errorf("failed to stop network: %v", err)
			return
		}
		t.Logf("stopped network at %s", network.Dir)
	})

	require.NoError(tmpnet.BootstrapNewNetwork(ctx, log, network, ""))

	// The network directory holds per-node logs, flags and databases. Emitting
	// it makes a failed CI run debuggable from the collected artifact.
	t.Logf("network dir: %s", network.Dir)

	return network
}

// TestNetworkLifecycle is the prototype required by phase 3 step 2: a tmpnet
// network running the PulseVM plugin with the repository's genesis, brought up
// and torn down entirely inside a test.
func TestNetworkLifecycle(t *testing.T) {
	require := require.New(t)

	network := StartNetwork(t)

	uris := network.GetNodeURIs()
	require.Len(uris, nodeCount, "expected every node to report a URI")
	for _, uri := range uris {
		t.Logf("node %s at %s", uri.NodeID, uri.URI)
	}

	subnet := network.GetSubnet(SubnetName)
	require.NotNil(subnet, "subnet %q missing from network", SubnetName)
	require.NotEqual(ids.Empty, subnet.SubnetID, "subnet was not created")
	require.Len(subnet.Chains, 1)

	chain := subnet.Chains[0]
	require.NotEqual(ids.Empty, chain.ChainID, "chain was not created")
	t.Logf("PulseVM chain %s on subnet %s", chain.ChainID, subnet.SubnetID)

	// Every node in the validator set must have bootstrapped the chain, not
	// just the one that issued the create-chain transaction.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, node := range network.Nodes {
		client := info.NewClient(node.GetAccessibleURI())
		bootstrapped, err := client.IsBootstrapped(ctx, chain.ChainID.String())
		require.NoError(err)
		require.True(bootstrapped, "chain not bootstrapped on node %s", node.NodeID)
	}
}
