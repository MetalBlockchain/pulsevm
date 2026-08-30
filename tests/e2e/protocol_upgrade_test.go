package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/MetalBlockchain/metalgo/chains"
	"github.com/MetalBlockchain/metalgo/config"
	"github.com/MetalBlockchain/metalgo/tests/fixture/tmpnet"
	"github.com/stretchr/testify/require"
)

// installChainUpgrade adds upgrade bytes to the chain-config-content MetalGo
// passes to every VM Initialize request, then restarts the real node processes.
// tmpnet v1.13.5 models the ordinary chain config but not its sibling upgrade
// blob, so the test fills that field in after chain creation gives us its ID.
func installChainUpgrade(
	ctx context.Context,
	network *tmpnet.Network,
	chainID string,
	upgrade []byte,
) error {
	encoded, err := network.GetChainConfigContent()
	if err != nil {
		return fmt.Errorf("building tmpnet chain config content: %w", err)
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decoding tmpnet chain config content: %w", err)
	}

	chainConfigs := map[string]chains.ChainConfig{}
	if err := json.Unmarshal(raw, &chainConfigs); err != nil {
		return fmt.Errorf("parsing tmpnet chain config content: %w", err)
	}
	chainConfig, ok := chainConfigs[chainID]
	if !ok {
		return fmt.Errorf("chain config content has no entry for %s", chainID)
	}
	chainConfig.Upgrade = upgrade
	chainConfigs[chainID] = chainConfig

	raw, err = json.Marshal(chainConfigs)
	if err != nil {
		return fmt.Errorf("encoding chain config content with upgrade: %w", err)
	}
	encoded = base64.StdEncoding.EncodeToString(raw)
	for _, node := range network.Nodes {
		// Explicit node flags override the value tmpnet derives from Chain.Config
		// when it composes the command line for the restarted MetalGo process.
		node.Flags[config.ChainConfigContentKey] = encoded
	}

	if err := network.Restart(ctx); err != nil {
		return fmt.Errorf("restarting network with protocol upgrade: %w", err)
	}
	return nil
}

func chainRPCURI(network *tmpnet.Network, nodeIndex int, chainID string) string {
	return network.Nodes[nodeIndex].GetAccessibleURI() + "/ext/bc/" + chainID + "/rpc"
}

func protocolScheduleHash(version, height uint32) string {
	canonical := make([]byte, 0, 20)
	canonical = append(canonical, []byte("PVMUPG01")...)
	canonical = binary.LittleEndian.AppendUint32(canonical, 1)
	canonical = binary.LittleEndian.AppendUint32(canonical, version)
	canonical = binary.LittleEndian.AppendUint32(canonical, height)
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}

// TestProtocolUpgradeScheduleFromMetalGo covers the complete transport and
// enforcement path:
//
//	upgrade bytes in MetalGo's chain config
//	  -> rpcchainvm InitializeRequest
//	  -> PulseVM schedule parsing
//	  -> successful production at H-1
//	  -> fail-closed transaction admission targeting H on an unsupported binary.
func TestProtocolUpgradeScheduleFromMetalGo(t *testing.T) {
	require := require.New(t)

	boot, err := BootBinaryPath()
	require.NoError(err)
	key, err := ProducerKey()
	require.NoError(err)
	root, err := RepoRoot()
	require.NoError(err)
	tokenWasm := filepath.Join(root, "reference_contracts", "pulse_token.wasm")
	tokenABI := filepath.Join(root, "reference_contracts", "pulse_token.abi")
	require.FileExists(tokenWasm)
	require.FileExists(tokenABI)

	network := StartNetwork(t)
	subnet := network.GetSubnet(SubnetName)
	require.NotNil(subnet)
	require.Len(subnet.Chains, 1)
	chainID := subnet.Chains[0].ChainID.String()

	queryCtx, queryCancel := context.WithTimeout(context.Background(), time.Minute)
	initial, err := GetInfo(queryCtx, chainRPCURI(network, 0, chainID))
	queryCancel()
	require.NoError(err)
	require.EqualValues(1, initial.ProtocolVersion)
	require.GreaterOrEqual(initial.SupportedProtocolVersion, initial.ProtocolVersion)
	require.NotEqual(^uint32(0), initial.SupportedProtocolVersion, "cannot construct the next unsupported protocol version")

	activationHeight := initial.HeadBlockNum + 2
	unsupportedVersion := initial.SupportedProtocolVersion + 1
	upgrade, err := json.Marshal(map[string]any{
		"protocol_upgrades": []map[string]uint32{
			{
				"protocol_version":  unsupportedVersion,
				"activation_height": activationHeight,
			},
		},
	})
	require.NoError(err)
	expectedScheduleHash := protocolScheduleHash(unsupportedVersion, activationHeight)
	t.Logf(
		"installing unsupported v%d activation at height %d over accepted head %d (compiled maximum v%d)",
		unsupportedVersion,
		activationHeight,
		initial.HeadBlockNum,
		initial.SupportedProtocolVersion,
	)

	restartCtx, restartCancel := context.WithTimeout(context.Background(), bootstrapTimeout(t))
	err = installChainUpgrade(restartCtx, network, chainID, upgrade)
	restartCancel()
	require.NoError(err)

	// A future unsupported entry is valid before activation. Every real MetalGo
	// node must reinitialize the plugin, remain healthy, and still report the
	// same active and compiled versions at the accepted head.
	for i := range network.Nodes {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		info, err := GetInfo(ctx, chainRPCURI(network, i, chainID))
		cancel()
		require.NoError(err, "getInfo from node %d after restart", i)
		require.Equal(initial.HeadBlockNum, info.HeadBlockNum, "node %d head moved during restart", i)
		require.Equal(initial.ProtocolVersion, info.ProtocolVersion, "node %d active version", i)
		require.Equal(initial.SupportedProtocolVersion, info.SupportedProtocolVersion, "node %d supported version", i)
		require.Equal(expectedScheduleHash, info.ProtocolUpgradeScheduleHash, "node %d loaded schedule", i)
		require.NotNil(info.NextProtocolUpgrade, "node %d next upgrade", i)
		require.Equal(unsupportedVersion, info.NextProtocolUpgrade.ProtocolVersion, "node %d next version", i)
		require.Equal(activationHeight, info.NextProtocolUpgrade.ActivationHeight, "node %d activation height", i)
	}

	// The boot fixture submits one transaction at a time. Its first transaction
	// must become block H-1. Admission of the next transaction targets H and is
	// rejected before gossip because this binary deliberately does not support
	// that next version.
	uri := chainRPCURI(network, 0, chainID)
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 90*time.Second)
	cmd := exec.CommandContext(bootCtx, boot,
		"--url", uri,
		"--private-key", key,
		"--token-wasm", tokenWasm,
		"--token-abi", tokenABI,
	)
	output, bootErr := cmd.CombinedOutput()
	bootCtxErr := bootCtx.Err()
	bootCancel()
	require.Error(bootErr, "binary unexpectedly produced the unsupported activation block")
	require.NotEqual(context.DeadlineExceeded, bootCtxErr, "boot driver exceeded its outer timeout: %s", output)
	require.Contains(string(output), fmt.Sprintf(
		"protocol version %d is unsupported by this binary",
		unsupportedVersion,
	), "unexpected boot failure: %s", output)

	final := make([]ChainInfo, len(network.Nodes))
	for i := range network.Nodes {
		nodeIndex := i
		require.Eventually(func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			info, err := GetInfo(ctx, chainRPCURI(network, nodeIndex, chainID))
			if err != nil {
				return false
			}
			final[nodeIndex] = info
			return info.HeadBlockNum == activationHeight-1
		}, 30*time.Second, 250*time.Millisecond, "node %d did not accept H-1 and stop before H", nodeIndex)
		require.Equal(initial.ProtocolVersion, final[nodeIndex].ProtocolVersion, "node %d active version", nodeIndex)
		require.Equal(initial.SupportedProtocolVersion, final[nodeIndex].SupportedProtocolVersion, "node %d supported version", nodeIndex)
		require.Equal(expectedScheduleHash, final[nodeIndex].ProtocolUpgradeScheduleHash, "node %d loaded schedule", nodeIndex)
	}

	t.Logf(
		"verified MetalGo upgrade delivery: accepted head stopped at %d; activation %d rejected on admission",
		final[0].HeadBlockNum,
		activationHeight,
	)
}
