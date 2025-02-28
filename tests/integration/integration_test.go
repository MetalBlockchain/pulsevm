package e2e

import (
	"context"
	_ "embed"
	"encoding/hex"
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/MetalBlockchain/metalgo/config"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/tests"
	"github.com/MetalBlockchain/metalgo/tests/fixture/tmpnet"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/formatting"
	"github.com/MetalBlockchain/pulsevm/api"
	"github.com/MetalBlockchain/pulsevm/chain/action"
	"github.com/MetalBlockchain/pulsevm/chain/authority"
	"github.com/MetalBlockchain/pulsevm/chain/constants"
	"github.com/MetalBlockchain/pulsevm/chain/name"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/MetalBlockchain/pulsevm/client"
	"github.com/MetalBlockchain/pulsevm/engine"
	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestIntegration(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "pulsevm integration test suites")
}

var (
	requestTimeout time.Duration
	vms            int
	metalGoPath    string
	pluginPath     string
	network        *tmpnet.Network
	chainID        ids.ID

	//go:embed genesis.json
	genesisBytes []byte
)

func init() {
	flag.DurationVar(
		&requestTimeout,
		"request-timeout",
		120*time.Second,
		"timeout for transaction issuance and confirmation",
	)
	flag.IntVar(
		&vms,
		"vms",
		3,
		"number of VMs to create",
	)
	flag.StringVar(
		&metalGoPath,
		"metalgo-path",
		"",
		"path to the metalgo binary",
	)
	flag.StringVar(
		&pluginPath,
		"plugin-path",
		"",
		"path to the plugin binary",
	)
}

var _ = ginkgo.BeforeSuite(func() {
	nodes := tmpnet.NewNodesOrPanic(5)
	network = &tmpnet.Network{ // Configure non-default values for the new network
		DefaultFlags: tmpnet.FlagsMap{
			config.LogLevelKey: "INFO", // Change one of the network's defaults
		},
		Nodes: nodes, // Number of initial validating nodes
		Subnets: []*tmpnet.Subnet{ // Subnets to create on the new network once it is running
			{
				Name: "pulsevm", // User-defined name used to reference subnet in code and on disk
				Chains: []*tmpnet.Chain{
					{
						VMID:    constants.PulseVMID,
						Genesis: genesisBytes,
					},
				},
				ValidatorIDs: tmpnet.NodesToIDs(nodes...), // The IDs of nodes that validate the subnet
			},
		},
	}

	// Extreme upper bound, should never take this long
	networkStartTimeout := 2 * time.Minute

	ctx, _ := context.WithTimeout(context.Background(), networkStartTimeout)
	err := tmpnet.BootstrapNewNetwork( // Bootstrap the network
		ctx,                        // Context used to limit duration of waiting for network health
		tests.NewDefaultLogger(""), // Writer to report progress of initialization
		network,
		"./tmpnet",  // Empty string uses the default network path (~/tmpnet/networks)
		metalGoPath, // The path to the binary that nodes will execute
		pluginPath,  // The path nodes will use for plugin binaries (suggested value ~/.avalanchego/plugins)
	)
	gomega.Ω(err).Should(gomega.BeNil())

	for _, subnet := range network.Subnets {
		for _, chain := range subnet.Chains {
			if chain.VMID.Compare(constants.PulseVMID) == 0 {
				chainID = chain.ChainID
			}
		}
	}
	gomega.Ω(chainID).Should(gomega.Not(gomega.Equal(ids.Empty)))
})

var _ = ginkgo.AfterSuite(func() {
	err := network.Stop(context.TODO())
	gomega.Ω(err).Should(gomega.BeNil())
})

var _ = ginkgo.Describe("[Ping]", func() {
	ginkgo.It("can ping", func() {
		for _, uri := range network.GetNodeURIs() {
			cli := client.New(getEndpointURI(uri.URI, chainID), requestTimeout)
			ok, err := cli.Ping(context.Background())
			gomega.Ω(ok).Should(gomega.BeTrue())
			gomega.Ω(err).Should(gomega.BeNil())
		}
	})
})

var _ = ginkgo.Describe("[Transaction]", func() {
	keyBytes, _ := hex.DecodeString("d3d137d219791b54bcbce7ab148871223585a2a181bc8a6d8820580f018e807f")
	key, err := secp256k1.ToPrivateKey(keyBytes)
	fmt.Printf("key.PublicKey().Address(): %v\n", key.PublicKey().Address())
	gomega.Ω(err).Should(gomega.BeNil())
	newAccount := engine.NewAccount{
		Creator: name.NewNameFromString("glenn"),
		Name:    name.NewNameFromString("marshall"),
		Owner: authority.Authority{
			Threshold: 1,
			Keys: []authority.KeyWeight{
				authority.KeyWeight{
					Key:    *key.PublicKey(),
					Weight: 1,
				},
			},
		},
		Active: authority.Authority{
			Threshold: 1,
			Keys: []authority.KeyWeight{
				authority.KeyWeight{
					Key:    *key.PublicKey(),
					Weight: 1,
				},
			},
		},
	}
	parser, err := txs.NewParser()
	gomega.Ω(err).Should(gomega.BeNil())
	actionDataBytes, err := parser.Codec().Marshal(txs.CodecVersion, newAccount)
	gomega.Ω(err).Should(gomega.BeNil())
	tx := txs.Tx{
		Unsigned: &txs.BaseTx{
			NetworkID:    1,
			BlockchainID: ids.Empty,
			Actions: []action.Action{
				action.Action{
					Account: name.NewNameFromString("pulse"),
					Name:    name.NewNameFromString("newaccount"),
					Authorization: []authority.PermissionLevel{
						authority.PermissionLevel{Actor: name.NewNameFromString("pulse"), Permission: name.NewNameFromString("active")},
					},
					Data: actionDataBytes,
				},
			},
		},
	}
	err = tx.Initialize(parser.Codec())
	gomega.Ω(err).Should(gomega.BeNil())
	err = tx.Sign(*key)
	gomega.Ω(err).Should(gomega.BeNil())
	txHex, err := formatting.Encode(formatting.Hex, tx.Bytes())
	fmt.Println(txHex)
	gomega.Ω(err).Should(gomega.BeNil())
	ginkgo.It("can issue a transaction", func() {
		for _, uri := range network.GetNodeURIs() {
			cli := client.New(getEndpointURI(uri.URI, chainID), requestTimeout)
			txID, err := cli.IssueTx(context.Background(), api.FormattedTx{
				Encoding: formatting.Hex,
				Tx:       txHex,
			})
			gomega.Ω(err).Should(gomega.BeNil())
			gomega.Ω(txID.String()).Should(gomega.Equal("2mkJGAU9LBA4W4ovY7RyjZe2A5paQHNHuEp87NAHUXJRg4Gwne"))
		}
	})
})

func getEndpointURI(nodeURI string, chainID ids.ID) string {
	return nodeURI + "/ext/bc/" + chainID.String()
}
