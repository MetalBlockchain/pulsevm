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
	Submitted        int      `json:"submitted"`
	Included         int      `json:"included"`
	IncludedStatuses int      `json:"included_statuses"`
	StartBlockNum    uint32   `json:"start_block_num"`
	TransactionIDs   []string `json:"transaction_ids"`
	P50AdmissionMS   int      `json:"p50_admission_ms"`
	P95AdmissionMS   int      `json:"p95_admission_ms"`
	MaxAdmissionMS   int      `json:"max_admission_ms"`
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
	soakStarted := time.Now()
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
	require.Equal(report.Submitted, report.IncludedStatuses, "every admitted transaction must reach included RPC status")
	require.Len(report.TransactionIDs, report.Submitted)

	// Account state on the submitter alone cannot show that every validator
	// accepted the same receipts. Walk each node's accepted blocks from the
	// pre-soak head and require every submitted transaction hash to appear.
	expected := make(map[string]struct{}, len(report.TransactionIDs))
	for _, id := range report.TransactionIDs {
		expected[id] = struct{}{}
	}
	deadline := soakStarted.Add(time.Minute)
	for _, node := range network.Nodes {
		baseURI := node.GetAccessibleURI() + "/ext/bc/" + chainID
		infoURI := baseURI + "/rpc"
		blockURI := baseURI + "/v1/chain/get_block"
		nextBlock := report.StartBlockNum + 1
		seen := make(map[string]struct{}, len(expected))
		for len(seen) < len(expected) {
			info, err := GetInfo(ctx, infoURI)
			require.NoError(err, "getting chain info from node %s", node.NodeID)
			for nextBlock <= info.HeadBlockNum {
				ids, err := BlockTransactionIDs(ctx, blockURI, nextBlock)
				require.NoError(err, "reading block %d from node %s", nextBlock, node.NodeID)
				for _, id := range ids {
					if _, wanted := expected[id]; wanted {
						seen[id] = struct{}{}
					}
				}
				nextBlock++
			}
			if len(seen) == len(expected) {
				break
			}
			require.True(time.Now().Before(deadline),
				"node %s accepted only %d of %d submitted transaction hashes",
				node.NodeID, len(seen), len(expected))
			time.Sleep(100 * time.Millisecond)
		}
		t.Logf("node %s accepted all %d submitted transaction hashes in %s",
			node.NodeID, len(seen), time.Since(soakStarted).Round(time.Millisecond))
	}

	// This is intentionally a liveness guard rather than a machine-specific
	// performance target. It catches a regression back to multi-second queuing
	// behind production while avoiding flaky CI on slow runners. The exact p95
	// is logged for comparison in PRs and production-load reports.
	require.Less(report.MaxAdmissionMS, 5000, "admission stalled behind block execution")
	t.Logf("admission latency p50=%dms p95=%dms max=%dms for %d transactions", report.P50AdmissionMS, report.P95AdmissionMS, report.MaxAdmissionMS, report.Submitted)
}
