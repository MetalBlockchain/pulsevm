package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

const (
	// MetalGoPathEnvName matches the variable tmpnet itself reads, so a single
	// export configures both this fixture and tmpnetctl.
	MetalGoPathEnvName = "METALGO_PATH"

	// PluginDirEnvName overrides the default plugin directory (<repo>/build,
	// as documented in the repository README).
	PluginDirEnvName = "PULSEVM_PLUGIN_DIR"
)

// MetalGoPath returns the path to the metalgo binary the nodes will execute.
func MetalGoPath() (string, error) {
	path := os.Getenv(MetalGoPathEnvName)
	if path == "" {
		return "", fmt.Errorf("%s must be set to the path of a metalgo binary", MetalGoPathEnvName)
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("%s=%s is not usable: %w", MetalGoPathEnvName, path, err)
	}
	return path, nil
}

// PluginDir returns the directory metalgo will search for VM plugins. The
// PulseVM binary must be present in it named by its VM ID -- metalgo resolves
// plugins by filename, not by any metadata inside the binary.
func PluginDir() (string, error) {
	if dir := os.Getenv(PluginDirEnvName); dir != "" {
		return dir, nil
	}
	root, err := RepoRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "build"), nil
}

// CheckPluginInstalled verifies the PulseVM plugin is where metalgo will look
// for it, and returns its path. A missing plugin otherwise surfaces as an
// opaque chain-creation failure well after network start.
func CheckPluginInstalled() (string, error) {
	dir, err := PluginDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, VMID)
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf(
			"PulseVM plugin not found at %s: %w\n"+
				"build it with `cargo build --release -p pulsevm` and copy the binary to that path, "+
				"or set %s to a directory that contains it",
			path, err, PluginDirEnvName,
		)
	}
	if info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("PulseVM plugin at %s is not executable", path)
	}
	return path, nil
}

var (
	// e.g. "metalgo/1.13.5 [database=v1.4.5, rpcchainvm=43, commit=..., go=1.26.5]"
	metalGoRPCChainVMRE = regexp.MustCompile(`rpcchainvm=(\d+)`)

	// crates/pulsevm_core/src/chain/config/mod.rs: pub const PLUGIN_VERSION: u32 = 43;
	pulseVMPluginVersionRE = regexp.MustCompile(`PLUGIN_VERSION\s*:\s*u32\s*=\s*(\d+)`)
)

// PulseVMPluginVersion reads the rpcchainvm protocol version PulseVM declares.
//
// It is parsed from source rather than queried from the binary because the
// plugin has no CLI surface: main() reads AVALANCHE_VM_RUNTIME_ENGINE_ADDR and
// panics when it is absent. If PulseVM ever grows a `--version-json` flag, this
// should be replaced by tmpnet's built-in check via Chain.VersionArgs.
func PulseVMPluginVersion() (string, error) {
	root, err := RepoRoot()
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "crates", "pulsevm_core", "src", "chain", "config", "mod.rs")
	source, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	match := pulseVMPluginVersionRE.FindSubmatch(source)
	if match == nil {
		return "", fmt.Errorf("no PLUGIN_VERSION constant found in %s", path)
	}
	return string(match[1]), nil
}
