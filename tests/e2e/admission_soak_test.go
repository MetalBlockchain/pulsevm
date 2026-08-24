package e2e

import (
	"context"
	"encoding/json"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// admissionSoakReport is emitted by the Rust fixture after all admitted
// transactions have become accounts on-chain. The latency values describe the
// HTTP admission calls themselves, rather than waiting for block inclusion.
type admissionSoakReport struct {
	Submitted      int `json:"submitted"`
	Included       int `json:"included"`
	P50AdmissionMS int `json:"p50_admission_ms"`
	P95AdmissionMS int `json:"p95_admission_ms"`
	MaxAdmissionMS int `json:"max_admission_ms"`
}

// TestMempoolAdmissionSoak drives concurrent signed HTTP ingress at one node
// while the five-node network is producing and verifying blocks. It catches
// the failure modes unit tests cannot: RPC transport behavior, process
// scheduling, gossip, and a producer/validator accepting every admitted
// transaction under a sustained burst.
func TestMempoolAdmissionSoak(t *testing.T) {
	require := require.New(t)

	soak, err := AdmissionSoakBinaryPath()
	require.NoError(err)
	key, err := ProducerKey()
	require.NoError(err)

	network := StartNetwork(t)
	subnet := network.GetSubnet(SubnetName)
	require.NotNil(subnet)
	chainID := subnet.Chains[0].ChainID.String()
	uri := network.Nodes[0].GetAccessibleURI() + "/ext/bc/" + chainID + "/rpc"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, soak,
		"--url", uri,
		"--private-key", key,
		"--transactions", "128",
		"--concurrency", "32",
	).CombinedOutput()
	require.NoError(err, "admission soak failed:\n%s", output)

	var report admissionSoakReport
	require.NoError(json.Unmarshal(output, &report), "unparseable admission soak report: %s", output)
	require.Equal(128, report.Submitted)
	require.Equal(report.Submitted, report.Included, "every admitted transaction must be applied")
	// This is intentionally a liveness guard rather than a machine-specific
	// performance target. It catches a regression back to multi-second queuing
	// behind production while avoiding flaky CI on slow runners. The exact p95
	// is logged for comparison in PRs and production-load reports.
	require.Less(report.MaxAdmissionMS, 5000, "admission stalled behind block execution")
	t.Logf("admission latency p50=%dms p95=%dms max=%dms for %d transactions", report.P50AdmissionMS, report.P95AdmissionMS, report.MaxAdmissionMS, report.Submitted)
}
