package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// bootBinary is the fixture that drives the chain's boot sequence. It lives in
// the Cargo workspace because transaction signing and Antelope serialization
// already exist there; reimplementing them in Go would put correctness risk in
// the test harness itself.
const bootBinary = "pulsevm-e2e-boot"
const admissionSoakBinary = "pulsevm-e2e-admission-soak"

// bootStep is one entry of the helper's JSON report.
type bootStep struct {
	Step     string   `json:"step"`
	Account  string   `json:"account"`
	From     string   `json:"from"`
	To       string   `json:"to"`
	Quantity string   `json:"quantity"`
	Tx       string   `json:"tx"`
	Proposed []string `json:"proposed"`
}

type bootReport struct {
	ChainID       string     `json:"chain_id"`
	TokenContract string     `json:"token_contract"`
	Steps         []bootStep `json:"steps"`
}

// BootBinaryPath locates the compiled fixture, preferring a release build.
func BootBinaryPath() (string, error) {
	return fixtureBinaryPath(bootBinary)
}

// AdmissionSoakBinaryPath locates the fixture that stresses concurrent
// transaction admission against a real tmpnet.
func AdmissionSoakBinaryPath() (string, error) {
	return fixtureBinaryPath(admissionSoakBinary)
}

func fixtureBinaryPath(binary string) (string, error) {
	root, err := RepoRoot()
	if err != nil {
		return "", err
	}
	for _, profile := range []string{"release", "debug"} {
		path := filepath.Join(root, "target", profile, binary)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", errFixtureBinaryMissing(root, binary)
}

func errFixtureBinaryMissing(root, binary string) error {
	return &bootBinaryError{root: root, binary: binary}
}

type bootBinaryError struct {
	root   string
	binary string
}

func (e *bootBinaryError) Error() string {
	return e.binary + " fixture not built: run `cargo build -p pulsevm_e2e_boot` in " + e.root
}

// ProducerKey returns the private key declared in chain_config.json. The chain
// is booted with this key as its genesis authority, so it is what the boot
// sequence must sign with.
func ProducerKey() (string, error) {
	root, err := RepoRoot()
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(filepath.Join(root, "chain_config.json"))
	if err != nil {
		return "", err
	}
	var perNode map[string]struct {
		ProducerKey string `json:"producer_key"`
	}
	if err := json.Unmarshal(raw, &perNode); err != nil {
		return "", err
	}
	for _, cfg := range perNode {
		if cfg.ProducerKey != "" {
			return cfg.ProducerKey, nil
		}
	}
	return "", errNoProducerKey
}

var errNoProducerKey = errors.New("chain_config.json declares no producer_key")

// TestBootSequenceAndTransfer runs the chain's boot sequence end to end:
// accounts are created, the token contract is deployed, a token is created and
// issued, and a transfer is pushed between two ordinary accounts.
func TestBootSequenceAndTransfer(t *testing.T) {
	require := require.New(t)

	boot, err := BootBinaryPath()
	require.NoError(err)

	key, err := ProducerKey()
	require.NoError(err)

	root, err := RepoRoot()
	require.NoError(err)
	tokenWasm := filepath.Join(root, "reference_contracts", "pulse_token.wasm")
	require.FileExists(tokenWasm)
	tokenABI := filepath.Join(root, "reference_contracts", "pulse_token.abi")
	require.FileExists(tokenABI)

	network := StartNetwork(t)
	subnet := network.GetSubnet(SubnetName)
	require.NotNil(subnet)
	chainID := subnet.Chains[0].ChainID.String()

	// Any validator serves the chain's API; the first is as good as any. The
	// "/rpc" suffix is the handler prefix PulseVM registers in create_handlers.
	uri := network.Nodes[0].GetAccessibleURI() + "/ext/bc/" + chainID + "/rpc"
	t.Logf("driving boot sequence against %s", uri)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, boot,
		"--url", uri,
		"--private-key", key,
		"--token-wasm", tokenWasm,
		"--token-abi", tokenABI,
	)
	var stderr []byte
	stdout, err := cmd.Output()
	if exitErr, ok := err.(*exec.ExitError); ok {
		stderr = exitErr.Stderr
	}
	require.NoError(err, "boot sequence failed:\n%s", stderr)

	var report bootReport
	require.NoError(json.Unmarshal(stdout, &report), "unparseable boot report: %s", stdout)

	byStep := map[string]bootStep{}
	for _, step := range report.Steps {
		byStep[step.Step] = step
		t.Logf("%-12s tx=%s", step.Step, step.Tx)
	}

	for _, expected := range []string{"newaccount", "setcode", "setabi", "create", "issue", "fund", "transfer"} {
		step, ok := byStep[expected]
		require.True(ok, "boot sequence did not report a %q step", expected)
		require.NotEmpty(step.Tx, "%q step produced no transaction id", expected)
	}

	transfer := byStep["transfer"]
	require.Equal("alice", transfer.From)
	require.Equal("bob", transfer.To)
	require.Equal("250.0000 PULSE", transfer.Quantity)

	// Accepted transactions are not the same as applied state, so assert the
	// balances the chain actually holds. 1000 issued to the contract, 500 sent
	// to alice, 250 of that on to bob.
	for _, want := range []struct {
		account string
		balance string
	}{
		{report.TokenContract, "500.0000 PULSE"},
		{"alice", "250.0000 PULSE"},
		{"bob", "250.0000 PULSE"},
	} {
		balance, err := CurrencyBalance(ctx, uri, report.TokenContract, want.account, "PULSE")
		require.NoError(err, "querying balance of %s", want.account)
		require.Equal(want.balance, balance, "balance of %s", want.account)
		t.Logf("%-12s %s", want.account, balance)
	}

	// Producer election, end to end. The boot fixture deployed a privileged
	// setprods forwarder onto pulse and proposed a schedule that adds producerb.
	// The chain enforces the change on the accepting block, so getProducers must
	// report the new set once it activates.
	setprods, ok := byStep["setprods"]
	require.True(ok, "boot sequence did not report a setprods step")
	require.NotEmpty(setprods.Tx, "setprods step produced no transaction id")
	require.Equal([]string{"pulse", "producerb"}, setprods.Proposed)

	// The fixture submits two harmless transactions after setprods: one forces a
	// later header to carry the pending schedule and the other forces its
	// activation after that header is accepted. Poll because RPC visibility can
	// still lag acceptance briefly.
	var producers ActiveProducers
	require.Eventually(func() bool {
		p, err := Producers(ctx, uri)
		if err != nil {
			t.Logf("getProducers: %v", err)
			return false
		}
		producers = p
		return p.ScheduleVersion >= 1
	}, 30*time.Second, 500*time.Millisecond, "producer schedule never activated")

	require.EqualValues(1, producers.ScheduleVersion)
	require.Equal([]string{"pulse", "producerb"}, producers.ActiveProducers)
	t.Logf("active producers v%d: %v", producers.ScheduleVersion, producers.ActiveProducers)
}
