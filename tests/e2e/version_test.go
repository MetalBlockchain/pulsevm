package e2e

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPluginProtocolVersion asserts that the rpcchainvm protocol version
// PulseVM implements matches the one the metalgo binary speaks.
//
// A mismatch is the single most likely cause of a PulseVM chain failing to
// come up after a metalgo bump, and it manifests as a plugin handshake failure
// with no useful diagnostic. tmpnet can normally pre-check this via
// Chain.VersionArgs, but that requires the VM binary to report its version on
// stdout, which PulseVM does not yet support -- so this test stands in for it.
//
// It is deliberately cheap and has no dependency on a running network, so it
// fails fast ahead of the lifecycle tests.
func TestPluginProtocolVersion(t *testing.T) {
	require := require.New(t)

	metalGoPath, err := MetalGoPath()
	require.NoError(err)

	output, err := exec.Command(metalGoPath, "--version").CombinedOutput()
	require.NoError(err, "failed to read metalgo version: %s", output)

	match := metalGoRPCChainVMRE.FindSubmatch(output)
	require.NotNil(match, "no rpcchainvm version in metalgo --version output: %s", output)
	metalGoVersion := string(match[1])

	pulseVMVersion, err := PulseVMPluginVersion()
	require.NoError(err)

	require.Equal(
		metalGoVersion,
		pulseVMVersion,
		"rpcchainvm protocol mismatch: metalgo speaks %s, PulseVM implements %s. "+
			"The plugin will fail to handshake. Update PLUGIN_VERSION in "+
			"crates/pulsevm_core/src/chain/config/mod.rs to match, or pin an older metalgo.",
		metalGoVersion,
		pulseVMVersion,
	)

	t.Logf("rpcchainvm protocol version %s (metalgo and PulseVM agree)", metalGoVersion)
}
