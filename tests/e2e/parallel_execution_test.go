package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const parallelPairCount = 8

var parallelCommitPattern = regexp.MustCompile(
	`parallel (?:producer )?execution block=[0-9]+.*committed=([0-9]+) fallbacks=([0-9]+)`,
)

// TestParallelBlockExecution proves that a real multi-validator network both
// produces and independently validates a block through the optimistic path.
// The workload uses disjoint authorizers and token table scopes so every
// transaction is eligible to commit without a serial fallback.
func TestParallelBlockExecution(t *testing.T) {
	require := require.New(t)

	// Request a stable upper bound and make eight candidates cross the parallel
	// threshold. The controller still safely caps workers to host parallelism.
	t.Setenv("PULSEVM_PARALLEL_EXECUTION_WORKERS", "4")
	t.Setenv("PULSEVM_PARALLEL_EXECUTION_TASKS_PER_WORKER", "1")
	t.Setenv("PULSEVM_PARALLEL_EXECUTION_MEMORY_MB", "1024")

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
	chainID := subnet.Chains[0].ChainID.String()
	uri := chainRPCURI(network, 0, chainID)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, boot,
		"--url", uri,
		"--private-key", key,
		"--token-wasm", tokenWasm,
		"--token-abi", tokenABI,
		"--parallel-pairs", strconv.Itoa(parallelPairCount),
	)
	stdout, err := cmd.Output()
	if exitErr, ok := err.(*exec.ExitError); ok {
		t.Fatalf("parallel boot workload failed: %v\n%s", err, exitErr.Stderr)
	}
	require.NoError(err)

	var report bootReport
	require.NoError(json.Unmarshal(stdout, &report), "unparseable boot report: %s", stdout)
	parallelTransfers := make([]bootStep, 0, parallelPairCount)
	for _, step := range report.Steps {
		if step.Step == "parallel_transfer" {
			parallelTransfers = append(parallelTransfers, step)
		}
	}
	require.Len(parallelTransfers, parallelPairCount)
	for _, transfer := range parallelTransfers {
		require.NotEmpty(transfer.Tx)
		require.Equal("1.0000 PULSE", transfer.Quantity)
	}

	// Observe the resulting state from every validator. This is stronger than
	// transaction admission: it catches execution divergence or a node that
	// rejected the producer's parallel block.
	require.Eventually(func() bool {
		var commonHead uint32
		for nodeIndex := range network.Nodes {
			nodeURI := chainRPCURI(network, nodeIndex, chainID)
			info, err := GetInfo(ctx, nodeURI)
			if err != nil {
				t.Logf("node %d getInfo: %v", nodeIndex, err)
				return false
			}
			if nodeIndex == 0 {
				commonHead = info.HeadBlockNum
			} else if info.HeadBlockNum != commonHead {
				return false
			}
			for _, transfer := range parallelTransfers {
				receiverBalance, err := CurrencyBalance(
					ctx,
					nodeURI,
					report.TokenContract,
					transfer.To,
					"PULSE",
				)
				if err != nil || receiverBalance != transfer.Quantity {
					return false
				}
				senderBalance, err := CurrencyBalance(
					ctx,
					nodeURI,
					report.TokenContract,
					transfer.From,
					"PULSE",
				)
				if err != nil || senderBalance != "9.0000 PULSE" {
					return false
				}
			}
		}
		t.Logf("all %d validators converged at block %d", len(network.Nodes), commonHead)
		return true
	}, 30*time.Second, 250*time.Millisecond, "validators did not converge on parallel transfer state")

	// Logs are the externally observable proof that success came from
	// speculation and journal commit, rather than a correct serial fallback.
	for _, node := range network.Nodes {
		logPath := filepath.Join(network.Dir, node.NodeID.String(), "logs", chainID+".log")
		var committed uint64
		require.Eventually(func() bool {
			var err error
			committed, err = fullParallelCommit(logPath, parallelPairCount)
			if err != nil {
				t.Logf("reading %s: %v", logPath, err)
				return false
			}
			return committed == parallelPairCount
		}, 15*time.Second, 200*time.Millisecond, "node %s recorded no clean %d-transaction optimistic commit", node.NodeID, parallelPairCount)
		t.Logf("node %s committed all %d transactions optimistically with zero fallbacks", node.NodeID, committed)
	}
}

func fullParallelCommit(logPath string, want uint64) (uint64, error) {
	contents, err := os.ReadFile(logPath)
	if err != nil {
		return 0, err
	}

	for _, match := range parallelCommitPattern.FindAllSubmatch(contents, -1) {
		committed, err := strconv.ParseUint(string(match[1]), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parsing committed count %q: %w", match[1], err)
		}
		fallbacks, err := strconv.ParseUint(string(match[2]), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parsing fallback count %q: %w", match[2], err)
		}
		if committed == want && fallbacks == 0 {
			return committed, nil
		}
	}
	return 0, nil
}
