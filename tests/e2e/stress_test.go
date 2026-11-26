package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Environment knobs. Defaults give several thousand transactions over a few
// minutes; raise them to push harder.
const (
	stressUsersEnv    = "PULSEVM_STRESS_USERS"    // funded, independently keyed accounts
	stressScaleEnv    = "PULSEVM_STRESS_SCALE"    // multiplier on every wave's transaction count
	stressSaturateEnv = "PULSEVM_STRESS_SATURATE" // extra transactions aimed at one node's mempool (limit is 10000)
	stressSeedEnv     = "PULSEVM_STRESS_SEED"     // reproduces a run's exact traffic
)

const stressTokenAccount = "pulse.token"

type u64 uint64

// UnmarshalJSON accepts both numbers and quoted numbers: nodeos-style ABI JSON
// renders 64-bit integers either way.
func (u *u64) UnmarshalJSON(b []byte) error {
	v, err := strconv.ParseUint(strings.Trim(string(b), `"`), 10, 64)
	if err != nil {
		return fmt.Errorf("not a uint64: %s", b)
	}
	*u = u64(v)
	return nil
}

type latencySummary struct {
	P50 int `json:"p50"`
	P95 int `json:"p95"`
	Max int `json:"max"`
}

type stressWave struct {
	Name                string                    `json:"name"`
	Submitted           int                       `json:"submitted"`
	StartBlock          uint32                    `json:"start_block"`
	EndBlock            uint32                    `json:"end_block"`
	BlocksWithIncluded  int                       `json:"blocks_with_included"`
	MaxIncludedPerBlock int                       `json:"max_included_per_block"`
	SubmitSecs          float64                   `json:"submit_secs"`
	WallSecs            float64                   `json:"wall_secs"`
	SubmitRPS           float64                   `json:"submit_rps"`
	Included            int                       `json:"included"`
	RejectedAtAdmission int                       `json:"rejected_at_admission"`
	FailedInExecution   int                       `json:"failed_in_execution"`
	DroppedUnknown      int                       `json:"dropped_unknown"`
	ResubmitAdmitted    int                       `json:"resubmit_admitted"`
	ResubmitRejected    int                       `json:"resubmit_rejected"`
	AdmissionRetries    int                       `json:"admission_retries"`
	AdmitMS             latencySummary            `json:"admit_ms"`
	InclusionMS         latencySummary            `json:"inclusion_ms"`
	Kinds               map[string]map[string]int `json:"kinds"`
	RejectionReasons    map[string]int            `json:"rejection_reasons"`
	RetryReasons        map[string]int            `json:"retry_reasons"`
	Failures            int                       `json:"failures"`
}

type stressFeed struct {
	Price u64 `json:"price"`
	Seq   u64 `json:"seq"`
}

type stressAggregate struct {
	Sum   u64 `json:"sum"`
	Count u64 `json:"count"`
	Avg   u64 `json:"avg"`
}

type stressModel struct {
	Token    string                       `json:"token"`
	Symbols  []string                     `json:"symbols"`
	Balances map[string]map[string]string `json:"balances"`
	Supply   map[string]string            `json:"supply"`
	AMM      struct {
		Account        string   `json:"account"`
		InitA          u64      `json:"init_a"`
		InitB          u64      `json:"init_b"`
		FaucetEachSide u64      `json:"faucet_each_side"`
		Swaps          u64      `json:"swaps"`
		Traders        []string `json:"traders"`
	} `json:"amm"`
	Oracle struct {
		Account    string                           `json:"account"`
		Updates    u64                              `json:"updates"`
		Pairs      []string                         `json:"pairs"`
		Feeds      map[string]map[string]stressFeed `json:"feeds"`
		Aggregates map[string]stressAggregate       `json:"aggregates"`
	} `json:"oracle"`
}

type stressReport struct {
	ChainID      string       `json:"chain_id"`
	Seed         uint64       `json:"seed"`
	Users        int          `json:"users"`
	Nodes        int          `json:"nodes"`
	StartBlock   uint32       `json:"start_block"`
	EndBlock     uint32       `json:"end_block"`
	ElapsedSecs  float64      `json:"elapsed_secs"`
	AbortedAfter *string      `json:"aborted_after"`
	Waves        []stressWave `json:"waves"`
	GoodIDs      []string     `json:"good_ids"`
	BadIDs       []string     `json:"bad_ids"`
	FailureCount int          `json:"failure_count"`
	Failures     []string     `json:"failures"`
	Model        stressModel  `json:"model"`
}

// ---- concurrent RPC readers --------------------------------------------------

// readerStats tallies the read-only RPC traffic that runs alongside the write
// load. The write path being fast is no use if reads stall or error under it.
type readerStats struct {
	calls  atomic.Int64
	errors atomic.Int64
	mu     sync.Mutex
	maxLat time.Duration
	first  []string
}

func (r *readerStats) record(op string, took time.Duration, err error) {
	r.calls.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	if took > r.maxLat {
		r.maxLat = took
	}
	if err != nil {
		r.errors.Add(1)
		if len(r.first) < 10 {
			r.first = append(r.first, fmt.Sprintf("%s: %v", op, err))
		}
	}
}

// runReaders hammers every node's read API until ctx is done. Targets are the
// contract accounts and token, which exist before any traffic starts.
func runReaders(ctx context.Context, wg *sync.WaitGroup, chainBases []string, token string, stats *readerStats, workers int) {
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; ctx.Err() == nil; i++ {
				base := chainBases[i%len(chainBases)]
				rpc := base + "/rpc"
				op := i % 6
				var name string
				var err error
				call, cancel := context.WithTimeout(ctx, 20*time.Second)
				started := time.Now()
				switch op {
				case 0:
					name = "getInfo"
					_, err = GetInfo(call, rpc)
				case 1:
					name = "getAccount"
					var out json.RawMessage
					err = RPCCall(call, rpc, "pulsevm.getAccount", map[string]any{"account_name": "oracle"}, &out)
				case 2:
					name = "getCurrencyBalance"
					_, err = CurrencyBalance(call, rpc, token, token, "PULSE")
				case 3:
					name = "getTableRows"
					var out json.RawMessage
					err = RPCCall(call, rpc, "pulsevm.getTableRows", map[string]any{
						"json": true, "code": "amm", "scope": "amm", "table": "pool", "limit": 5, "key_type": "i64",
					}, &out)
				case 4:
					name = "get_block"
					var info ChainInfo
					if info, err = GetInfo(call, rpc); err == nil {
						_, err = BlockTransactionIDs(call, base+"/v1/chain/get_block", info.HeadBlockNum)
					}
				default:
					name = "getCurrencyStats"
					var out json.RawMessage
					err = RPCCall(call, rpc, "pulsevm.getCurrencyStats", map[string]any{"code": token, "symbol": "PULSE"}, &out)
				}
				cancel()
				if ctx.Err() != nil {
					return // the run ended mid-call; not a chain failure
				}
				stats.record(name, time.Since(started), err)
				time.Sleep(15 * time.Millisecond)
			}
		}(w)
	}
}

// ---- state readback ----------------------------------------------------------

type tableResponse struct {
	Rows    []json.RawMessage `json:"rows"`
	More    bool              `json:"more"`
	NextKey json.RawMessage   `json:"next_key"`
}

// allRows reads a whole table, following pagination.
func allRows(ctx context.Context, rpc, code, scope, table string, showPayer bool) ([]json.RawMessage, error) {
	var rows []json.RawMessage
	next := ""
	for page := 0; page < 1000; page++ {
		params := map[string]any{
			"json": true, "code": code, "scope": scope, "table": table,
			"limit": 500, "key_type": "i64", "show_payer": showPayer,
		}
		if next != "" {
			params["lower_bound"] = next
		}
		var resp tableResponse
		if err := RPCCall(ctx, rpc, "pulsevm.getTableRows", params, &resp); err != nil {
			return nil, err
		}
		rows = append(rows, resp.Rows...)
		if !resp.More {
			return rows, nil
		}
		next = strings.Trim(string(resp.NextKey), `"`)
		if next == "" {
			return nil, fmt.Errorf("%s/%s: more rows reported without a next_key", code, table)
		}
	}
	return nil, fmt.Errorf("%s/%s: pagination did not terminate", code, table)
}

// parallel runs fn for every index with bounded concurrency and returns the
// first few errors.
func parallel(n, workers int, fn func(i int) error) []error {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
		next atomic.Int64
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= n {
					return
				}
				if err := fn(i); err != nil {
					mu.Lock()
					if len(errs) < 10 {
						errs = append(errs, err)
					}
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return errs
}

// verifyState compares one node's chain state with the fixture's model.
func verifyState(ctx context.Context, t *testing.T, label, rpc string, m stressModel) {
	t.Helper()
	require := require.New(t)

	// Token balances, exactly, for every account that ever held anything.
	accounts := make([]string, 0, len(m.Balances))
	for account := range m.Balances {
		accounts = append(accounts, account)
	}
	sort.Strings(accounts)
	errs := parallel(len(accounts), 24, func(i int) error {
		for _, symbol := range m.Symbols {
			want := m.Balances[accounts[i]][symbol]
			got, err := CurrencyBalance(ctx, rpc, m.Token, accounts[i], symbol)
			if err != nil {
				return fmt.Errorf("balance of %s: %w", accounts[i], err)
			}
			// An account that never held a symbol has no row, which reads back as
			// an empty string; the model writes that as a zero balance.
			if got == "" && strings.HasPrefix(want, "0.0000 ") {
				continue
			}
			if got != want {
				return fmt.Errorf("%s holds %q, want %q", accounts[i], got, want)
			}
		}
		return nil
	})
	require.Empty(errs, "%s: token balances diverge from the model (%d accounts checked)", label, len(accounts))

	for _, symbol := range m.Symbols {
		var raw json.RawMessage
		require.NoError(RPCCall(ctx, rpc, "pulsevm.getCurrencyStats", map[string]any{"code": m.Token, "symbol": symbol}, &raw), label)
		var stats map[string]struct {
			Supply string `json:"supply"`
		}
		require.NoError(json.Unmarshal(raw, &stats), label)
		// Non-fatal so one RPC discrepancy does not hide the AMM and oracle
		// checks below; the raw response is included to make it diagnosable.
		assert.Equal(t, m.Supply[symbol], stats[symbol].Supply, "%s: %s supply (raw getCurrencyStats response: %s)", label, symbol, raw)

		// The same row through the generic table API, which needs the token's
		// ABI to declare the table under the name the contract really uses.
		var rows tableResponse
		if assert.NoError(t, RPCCall(ctx, rpc, "pulsevm.getTableRows", map[string]any{
			"json": true, "code": m.Token, "scope": symbol, "table": "stats", "limit": 5, "key_type": "i64",
		}, &rows), "%s: stats table for %s", label, symbol) {
			assert.Len(t, rows.Rows, 1, "%s: one stats row for %s", label, symbol)
		}
	}

	verifyAMM(ctx, t, label, rpc, m)
	verifyOracle(ctx, t, label, rpc, m)
}

func verifyAMM(ctx context.Context, t *testing.T, label, rpc string, m stressModel) {
	t.Helper()
	require := require.New(t)

	poolRows, err := allRows(ctx, rpc, m.AMM.Account, m.AMM.Account, "pool", false)
	require.NoError(err, label)
	require.Len(poolRows, 1, "%s: expected exactly one pool row", label)
	var pool struct {
		ReserveA u64 `json:"reserve_a"`
		ReserveB u64 `json:"reserve_b"`
		Swaps    u64 `json:"swaps"`
	}
	require.NoError(json.Unmarshal(poolRows[0], &pool))

	balRows, err := allRows(ctx, rpc, m.AMM.Account, m.AMM.Account, "bal", false)
	require.NoError(err, label)
	require.Len(balRows, len(m.AMM.Traders), "%s: one balance row per funded trader", label)
	var sumA, sumB uint64
	for _, raw := range balRows {
		var row struct {
			A u64 `json:"a"`
			B u64 `json:"b"`
		}
		require.NoError(json.Unmarshal(raw, &row))
		sumA += uint64(row.A)
		sumB += uint64(row.B)
	}

	// Every swap that executed was counted exactly once, none ran twice and
	// none were lost, however the five nodes interleaved them.
	require.Equal(m.AMM.Swaps, pool.Swaps, "%s: swap count", label)

	// Value is conserved: reserves plus all balances equal what was put in.
	// A duplicated or half-applied swap would break this.
	require.Equal(uint64(m.AMM.InitA)+uint64(m.AMM.FaucetEachSide), uint64(pool.ReserveA)+sumA, "%s: side A not conserved", label)
	require.Equal(uint64(m.AMM.InitB)+uint64(m.AMM.FaucetEachSide), uint64(pool.ReserveB)+sumB, "%s: side B not conserved", label)

	// Rounding favours the pool, so the constant-product invariant can only grow.
	k0 := new(big.Int).Mul(new(big.Int).SetUint64(uint64(m.AMM.InitA)), new(big.Int).SetUint64(uint64(m.AMM.InitB)))
	k1 := new(big.Int).Mul(new(big.Int).SetUint64(uint64(pool.ReserveA)), new(big.Int).SetUint64(uint64(pool.ReserveB)))
	require.GreaterOrEqual(k1.Cmp(k0), 0, "%s: pool invariant k shrank (%s < %s)", label, k1, k0)
}

func verifyOracle(ctx context.Context, t *testing.T, label, rpc string, m stressModel) {
	t.Helper()
	require := require.New(t)
	oracle := m.Oracle.Account

	statRows, err := allRows(ctx, rpc, oracle, oracle, "stats", false)
	require.NoError(err, label)
	require.Len(statRows, 1, "%s: expected one stats row", label)
	var stat struct {
		Updates u64 `json:"updates"`
	}
	require.NoError(json.Unmarshal(statRows[0], &stat))
	require.Equal(m.Oracle.Updates, stat.Updates, "%s: every setprice must bump the hot counter exactly once", label)

	for _, pair := range m.Oracle.Pairs {
		rows, err := allRows(ctx, rpc, oracle, pair, "feeds", true)
		require.NoError(err, "%s: feeds for %s", label, pair)
		got := map[string]stressFeed{}
		for _, raw := range rows {
			var row struct {
				Data  stressFeed `json:"data"`
				Payer string     `json:"payer"`
			}
			require.NoError(json.Unmarshal(raw, &row))
			got[row.Payer] = row.Data
		}
		require.Equal(m.Oracle.Feeds[pair], got, "%s: feeds for %s (newest seq must win whatever the arrival order)", label, pair)

		aggs, err := allRows(ctx, rpc, oracle, pair, "agg", false)
		require.NoError(err, label)
		want, hasAgg := m.Oracle.Aggregates[pair]
		require.True(hasAgg, "model has no aggregate for %s", pair)
		require.Len(aggs, 1, "%s: aggregate row for %s", label, pair)
		var agg stressAggregate
		require.NoError(json.Unmarshal(aggs[0], &agg))
		require.Equal(want, agg, "%s: final aggregate for %s", label, pair)
	}
}

// ---- block walk --------------------------------------------------------------

// walkBlocks returns each block's transaction IDs in order for blocks
// (from, to], waiting for the node to reach `to` first.
func walkBlocks(ctx context.Context, base string, from, to uint32) ([][]string, error) {
	deadline := time.Now().Add(90 * time.Second)
	for {
		info, err := GetInfo(ctx, base+"/rpc")
		if err != nil {
			return nil, err
		}
		if info.HeadBlockNum >= to {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("head stuck at %d, want %d", info.HeadBlockNum, to)
		}
		time.Sleep(200 * time.Millisecond)
	}
	blocks := make([][]string, 0, to-from)
	for n := from + 1; n <= to; n++ {
		ids, err := BlockTransactionIDs(ctx, base+"/v1/chain/get_block", n)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", n, err)
		}
		blocks = append(blocks, ids)
	}
	return blocks, nil
}

func envInt(t *testing.T, name string, fallback int) int {
	t.Helper()
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	require.NoError(t, err, "invalid %s=%q", name, raw)
	return v
}

// TestMixedWorkloadStress drives thousands of transactions of many kinds,
// from hundreds of independently keyed accounts, at all five nodes at once,
// and then proves the network handled them correctly:
//
//   - every valid transaction is in exactly one block, identically on every node;
//   - no invalid transaction (bad signature, expired, overdrawn, wrong authority,
//     failed assertion, oversize memo, unknown contract) is in any block, and a
//     failing action rolls back the rest of its transaction;
//   - token balances, AMM invariants and oracle state read back over RPC equal a
//     model computed from the traffic, on every node;
//   - read RPCs stay healthy under the write load.
//
// See crates/pulsevm_e2e_boot/src/stress for the workload definition.
func TestMixedWorkloadStress(t *testing.T) {
	require := require.New(t)

	stress, err := StressBinaryPath()
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
	var bases []string
	for _, node := range network.Nodes {
		bases = append(bases, node.GetAccessibleURI()+"/ext/bc/"+chainID)
	}

	args := []string{
		"--private-key", key,
		"--token-wasm", tokenWasm,
		"--token-abi", tokenABI,
		"--users", strconv.Itoa(envInt(t, stressUsersEnv, 300)),
		"--saturate", strconv.Itoa(envInt(t, stressSaturateEnv, 0)),
	}
	for _, base := range bases {
		args = append(args, "--url", base+"/rpc")
	}
	if scale := os.Getenv(stressScaleEnv); scale != "" {
		args = append(args, "--scale", scale)
	}
	if seed := os.Getenv(stressSeedEnv); seed != "" {
		args = append(args, "--seed", seed)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, stress, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	stderr, err := cmd.StderrPipe()
	require.NoError(err)

	readCtx, stopReaders := context.WithCancel(ctx)
	defer stopReaders()
	var readers sync.WaitGroup
	reads := &readerStats{}
	var startReaders sync.Once

	require.NoError(cmd.Start())
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(stderr)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			t.Log(line)
			if line == "STRESS_READY" {
				startReaders.Do(func() { runReaders(readCtx, &readers, bases, stressTokenAccount, reads, 8) })
			}
		}
	}()
	runErr := cmd.Wait()
	<-scanDone
	stopReaders()
	readers.Wait()
	require.NoError(runErr, "stress fixture failed; stdout so far:\n%s", stdout.String())

	var report stressReport
	require.NoError(json.Unmarshal(stdout.Bytes(), &report), "unparseable stress report")

	total := 0
	for _, w := range report.Waves {
		total += w.Submitted
		t.Logf("wave %-17s %5d tx  blocks %d..%d (%d with txs, max %d/block)  submit %.0f/s  admit p95 %dms max %dms  inclusion p50 %dms p95 %dms  retries %d  rejected %d  exec-failed %d  dropped %d  replays %d admitted/%d rejected",
			w.Name, w.Submitted, w.StartBlock, w.EndBlock, w.BlocksWithIncluded, w.MaxIncludedPerBlock,
			w.SubmitRPS, w.AdmitMS.P95, w.AdmitMS.Max, w.InclusionMS.P50, w.InclusionMS.P95,
			w.AdmissionRetries, w.RejectedAtAdmission, w.FailedInExecution, w.DroppedUnknown,
			w.ResubmitAdmitted, w.ResubmitRejected)
		if len(w.RejectionReasons) > 0 {
			t.Logf("  rejection reasons: %v", w.RejectionReasons)
		}
		if len(w.RetryReasons) > 0 {
			t.Logf("  admission retry reasons: %v", w.RetryReasons)
		}
		kinds := make([]string, 0, len(w.Kinds))
		for k := range w.Kinds {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			t.Logf("    %-22s %v", k, w.Kinds[k])
		}
	}
	t.Logf("%d transactions (%d valid, %d invalid) from %d accounts over blocks %d..%d in %.0fs; seed %d (rerun with %s=%d)",
		total, len(report.GoodIDs), len(report.BadIDs), report.Users, report.StartBlock, report.EndBlock,
		report.ElapsedSecs, report.Seed, stressSeedEnv, report.Seed)

	// 1. The fixture's own per-transaction observations.
	require.Nil(report.AbortedAfter, "a setup wave failed and later waves were skipped")
	require.Zero(report.FailureCount, "fixture observed %d failures, first ones:\n%s",
		report.FailureCount, strings.Join(report.Failures, "\n"))

	// 2. Every node holds the same blocks, with every valid transaction exactly
	// once and no invalid one.
	perNode := make([][][]string, len(bases))
	errs := parallel(len(bases), len(bases), func(i int) error {
		blocks, err := walkBlocks(ctx, bases[i], report.StartBlock, report.EndBlock)
		perNode[i] = blocks
		return err
	})
	require.Empty(errs, "walking blocks")
	for i := 1; i < len(perNode); i++ {
		require.Equal(perNode[0], perNode[i], "node %d disagrees with node 0 about block contents", i)
	}

	good := make(map[string]struct{}, len(report.GoodIDs))
	for _, id := range report.GoodIDs {
		good[id] = struct{}{}
	}
	bad := make(map[string]struct{}, len(report.BadIDs))
	for _, id := range report.BadIDs {
		bad[id] = struct{}{}
	}
	seen := map[string]int{}
	var unexpected []string
	blocksWithTxs, maxPerBlock := 0, 0
	for _, ids := range perNode[0] {
		if len(ids) > 0 {
			blocksWithTxs++
		}
		maxPerBlock = max(maxPerBlock, len(ids))
		for _, id := range ids {
			seen[id]++
			if _, ok := good[id]; !ok {
				if _, isBad := bad[id]; isBad {
					t.Errorf("invalid transaction %s was included in a block", id)
				} else {
					unexpected = append(unexpected, id)
				}
			}
		}
	}
	var missing, duplicated []string
	for id := range good {
		switch seen[id] {
		case 0:
			missing = append(missing, id)
		case 1:
		default:
			duplicated = append(duplicated, id)
		}
	}
	require.Empty(missing, "%d valid transactions never reached a block", len(missing))
	require.Empty(duplicated, "%d transactions were included more than once", len(duplicated))
	require.Empty(unexpected, "%d transactions in blocks that the fixture never submitted as valid", len(unexpected))
	t.Logf("every node holds the same %d blocks; %d carry transactions (max %d in one block); all %d valid transactions appear exactly once",
		len(perNode[0]), blocksWithTxs, maxPerBlock, len(good))
	require.GreaterOrEqual(blocksWithTxs, 5, "load should span several blocks")

	// 3. State on every node equals the model.
	for i, base := range bases {
		verifyState(ctx, t, fmt.Sprintf("node %d", i), base+"/rpc", report.Model)
	}
	if !t.Failed() {
		t.Logf("token balances (%d accounts), supply, AMM and oracle state match the model on all %d nodes",
			len(report.Model.Balances), len(bases))
	}

	// 4. Reads stayed healthy throughout.
	t.Logf("concurrent RPC readers: %d calls, %d errors, slowest %s",
		reads.calls.Load(), reads.errors.Load(), reads.maxLat.Round(time.Millisecond))
	require.Zero(reads.errors.Load(), "read RPCs failed during the write load: %v", reads.first)
	require.Greater(reads.calls.Load(), int64(100), "readers made too few calls to mean anything")
	require.Less(reads.maxLat, 15*time.Second, "a read RPC stalled behind block production")
}
