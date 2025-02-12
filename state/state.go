package state

import (
	"errors"
	"fmt"
	"time"

	"github.com/MetalBlockchain/metalgo/cache"
	"github.com/MetalBlockchain/metalgo/cache/metercacher"
	"github.com/MetalBlockchain/metalgo/database"
	"github.com/MetalBlockchain/metalgo/database/prefixdb"
	"github.com/MetalBlockchain/metalgo/database/versiondb"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow/choices"
	"github.com/MetalBlockchain/metalgo/utils/constants"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/block"
	"github.com/MetalBlockchain/pulsevm/chain/config"
	"github.com/MetalBlockchain/pulsevm/chain/genesis"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/MetalBlockchain/pulsevm/status"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	_ State = (*state)(nil)

	ErrMissingParentState = errors.New("missing parent state")

	SingletonPrefix = []byte("singleton")
	BlockIDPrefix   = []byte("blockID")
	BlockPrefix     = []byte("block")
	TxPrefix        = []byte("tx")

	InitializedKey  = []byte("initialized")
	TimestampKey    = []byte("timestamp")
	LastAcceptedKey = []byte("last accepted")
)

type State interface {
	Chain

	GetLastAccepted() ids.ID
	SetLastAccepted(blkID ids.ID)

	// Invariant: [block] is an accepted block.
	AddStatelessBlock(block block.Block)
	GetStatelessBlock(blockID ids.ID) (block.Block, error)
	GetBlockIDAtHeight(height uint64) (ids.ID, error)

	// Commit changes to the base database.
	Commit() error

	Close() error
}

type txBytesAndStatus struct {
	Tx     []byte        `serialize:"true"`
	Status status.Status `serialize:"true"`
}

type txAndStatus struct {
	tx     *txs.Tx
	status status.Status
}

type state struct {
	baseDB *versiondb.Database

	// [lastAccepted] is the most recently accepted block.
	lastAccepted, persistedLastAccepted ids.ID

	currentHeight uint64

	addedBlocks map[ids.ID]block.Block            // map of blockID -> Block
	blockCache  cache.Cacher[ids.ID, block.Block] // cache of blockID -> Block; if the entry is nil, it is not in the database
	blockDB     database.Database

	addedBlockIDs map[uint64]ids.ID            // map of height -> blockID
	blockIDCache  cache.Cacher[uint64, ids.ID] // cache of height -> blockID; if the entry is ids.Empty, it is not in the database
	blockIDDB     database.Database

	addedTxs map[ids.ID]*txAndStatus            // map of txID -> {*txs.Tx, Status}
	txCache  cache.Cacher[ids.ID, *txAndStatus] // txID -> {*txs.Tx, Status}; if the entry is nil, it is not in the database
	txDB     database.Database

	singletonDB database.Database

	timestamp, persistedTimestamp time.Time
}

func blockSize(_ ids.ID, blk block.Block) int {
	if blk == nil {
		return ids.IDLen + constants.PointerOverhead
	}
	return ids.IDLen + len(blk.Bytes()) + constants.PointerOverhead
}

func txAndStatusSize(_ ids.ID, t *txAndStatus) int {
	if t == nil {
		return ids.IDLen + constants.PointerOverhead
	}
	return ids.IDLen + len(t.tx.Bytes()) + wrappers.IntLen + 2*constants.PointerOverhead
}

func New(
	db database.Database,
	genesisBytes []byte,
	metricsReg prometheus.Registerer,
	execCfg *config.Config,
) (State, error) {
	blockIDCache, err := metercacher.New[uint64, ids.ID](
		"block_id_cache",
		metricsReg,
		&cache.LRU[uint64, ids.ID]{Size: execCfg.BlockIDCacheSize},
	)
	if err != nil {
		return nil, err
	}

	blockCache, err := metercacher.New[ids.ID, block.Block](
		"block_cache",
		metricsReg,
		cache.NewSizedLRU[ids.ID, block.Block](execCfg.BlockCacheSize, blockSize),
	)
	if err != nil {
		return nil, err
	}

	txCache, err := metercacher.New(
		"tx_cache",
		metricsReg,
		cache.NewSizedLRU[ids.ID, *txAndStatus](execCfg.TxCacheSize, txAndStatusSize),
	)
	if err != nil {
		return nil, err
	}

	baseDB := versiondb.New(db)

	s := &state{
		baseDB: baseDB,

		addedBlockIDs: make(map[uint64]ids.ID),
		blockIDCache:  blockIDCache,
		blockIDDB:     prefixdb.New(BlockIDPrefix, baseDB),

		addedBlocks: make(map[ids.ID]block.Block),
		blockCache:  blockCache,
		blockDB:     prefixdb.New(BlockPrefix, baseDB),

		addedTxs: make(map[ids.ID]*txAndStatus),
		txDB:     prefixdb.New(TxPrefix, baseDB),
		txCache:  txCache,

		singletonDB: prefixdb.New(SingletonPrefix, baseDB),
	}

	if err := s.sync(genesisBytes); err != nil {
		return nil, errors.Join(
			err,
			s.Close(),
		)
	}

	return s, nil
}

func (s *state) sync(genesis []byte) error {
	wasInitialized, err := isInitialized(s.singletonDB)
	if err != nil {
		return fmt.Errorf(
			"failed to check if the database is initialized: %w",
			err,
		)
	}

	if !wasInitialized {
		if err := s.init(genesis); err != nil {
			return fmt.Errorf(
				"failed to initialize the database: %w",
				err,
			)
		}
	}

	if err := s.load(); err != nil {
		return fmt.Errorf(
			"failed to load the database state: %w",
			err,
		)
	}

	return nil
}

func (s *state) init(genesisBytes []byte) error {
	genesis, err := genesis.Parse(genesisBytes)
	if err != nil {
		return err
	}

	genesisBlock, err := block.NewStandardBlock(genesis.Timestamp, ids.Empty, 0, nil)
	if err != nil {
		return err
	}

	if err := s.syncGenesis(genesisBlock, genesis); err != nil {
		return err
	}

	if err := markInitialized(s.singletonDB); err != nil {
		return err
	}

	return s.Commit()
}

func (s *state) syncGenesis(genesisBlk block.Block, genesis *genesis.Genesis) error {
	genesisBlkID := genesisBlk.ID()
	s.SetLastAccepted(genesisBlkID)
	s.SetTimestamp(genesis.Timestamp)
	s.AddStatelessBlock(genesisBlk)

	return s.write(0)
}

// Load pulls data previously stored on disk that is expected to be in memory.
func (s *state) load() error {
	return errors.Join(
		s.loadMetadata(),
	)
}

func (s *state) loadMetadata() error {
	timestamp, err := database.GetTimestamp(s.singletonDB, TimestampKey)
	if err != nil {
		return err
	}
	s.persistedTimestamp = timestamp
	s.SetTimestamp(timestamp)

	lastAccepted, err := database.GetID(s.singletonDB, LastAcceptedKey)
	if err != nil {
		return err
	}
	s.persistedLastAccepted = lastAccepted
	s.lastAccepted = lastAccepted

	return nil
}

func markInitialized(db database.KeyValueWriter) error {
	return db.Put(InitializedKey, nil)
}

func isInitialized(db database.KeyValueReader) (bool, error) {
	return db.Has(InitializedKey)
}

func (s *state) GetTimestamp() time.Time {
	return s.timestamp
}

func (s *state) SetTimestamp(tm time.Time) {
	s.timestamp = tm
}

func (s *state) GetLastAccepted() ids.ID {
	return s.lastAccepted
}

func (s *state) SetLastAccepted(lastAccepted ids.ID) {
	s.lastAccepted = lastAccepted
}

func (s *state) AddStatelessBlock(block block.Block) {
	blkID := block.ID()
	s.addedBlockIDs[block.Height()] = blkID
	s.addedBlocks[blkID] = block
}

func (s *state) GetStatelessBlock(blockID ids.ID) (block.Block, error) {
	if blk, exists := s.addedBlocks[blockID]; exists {
		return blk, nil
	}
	if blk, cached := s.blockCache.Get(blockID); cached {
		if blk == nil {
			return nil, database.ErrNotFound
		}

		return blk, nil
	}

	blkBytes, err := s.blockDB.Get(blockID[:])
	if err == database.ErrNotFound {
		s.blockCache.Put(blockID, nil)
		return nil, database.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	blk, _, err := parseStoredBlock(blkBytes)
	if err != nil {
		return nil, err
	}

	s.blockCache.Put(blockID, blk)
	return blk, nil
}

func (s *state) GetBlockIDAtHeight(height uint64) (ids.ID, error) {
	if blkID, exists := s.addedBlockIDs[height]; exists {
		return blkID, nil
	}
	if blkID, cached := s.blockIDCache.Get(height); cached {
		if blkID == ids.Empty {
			return ids.Empty, database.ErrNotFound
		}

		return blkID, nil
	}

	heightKey := database.PackUInt64(height)

	blkID, err := database.GetID(s.blockIDDB, heightKey)
	if err == database.ErrNotFound {
		s.blockIDCache.Put(height, ids.Empty)
		return ids.Empty, database.ErrNotFound
	}
	if err != nil {
		return ids.Empty, err
	}

	s.blockIDCache.Put(height, blkID)
	return blkID, nil
}

type stateBlk struct {
	Bytes  []byte         `serialize:"true"`
	Status choices.Status `serialize:"true"`
}

// Returns the block and whether it is a [stateBlk].
// Invariant: blkBytes is safe to parse with blocks.GenesisCodec
//
// TODO: Remove after v1.12.x is activated
func parseStoredBlock(blkBytes []byte) (block.Block, bool, error) {
	// Attempt to parse as blocks.Block
	blk, err := block.Parse(block.Codec, blkBytes)
	if err == nil {
		return blk, false, nil
	}

	// Fallback to [stateBlk]
	blkState := stateBlk{}
	if _, err := block.Codec.Unmarshal(blkBytes, &blkState); err != nil {
		return nil, false, err
	}

	blk, err = block.Parse(block.Codec, blkState.Bytes)
	return blk, true, err
}

func (s *state) GetTx(txID ids.ID) (*txs.Tx, status.Status, error) {
	if tx, exists := s.addedTxs[txID]; exists {
		return tx.tx, tx.status, nil
	}
	if tx, cached := s.txCache.Get(txID); cached {
		if tx == nil {
			return nil, status.Unknown, database.ErrNotFound
		}
		return tx.tx, tx.status, nil
	}
	txBytes, err := s.txDB.Get(txID[:])
	if err == database.ErrNotFound {
		s.txCache.Put(txID, nil)
		return nil, status.Unknown, database.ErrNotFound
	} else if err != nil {
		return nil, status.Unknown, err
	}

	stx := txBytesAndStatus{}
	if _, err := txs.Codec.Unmarshal(txBytes, &stx); err != nil {
		return nil, status.Unknown, err
	}

	tx, err := txs.Parse(txs.Codec, stx.Tx)
	if err != nil {
		return nil, status.Unknown, err
	}

	ptx := &txAndStatus{
		tx:     tx,
		status: stx.Status,
	}

	s.txCache.Put(txID, ptx)
	return ptx.tx, ptx.status, nil
}

func (s *state) AddTx(tx *txs.Tx, status status.Status) {
	s.addedTxs[tx.ID()] = &txAndStatus{
		tx:     tx,
		status: status,
	}
}

func (s *state) Abort() {
	s.baseDB.Abort()
}

func (s *state) Commit() error {
	defer s.Abort()
	batch, err := s.CommitBatch()
	if err != nil {
		return err
	}
	return batch.Write()
}

func (s *state) CommitBatch() (database.Batch, error) {
	if err := s.write(s.currentHeight); err != nil {
		return nil, err
	}
	return s.baseDB.CommitBatch()
}

func (s *state) Close() error {
	return errors.Join(
		s.txDB.Close(),
		s.blockDB.Close(),
		s.blockIDDB.Close(),
	)
}

func (s *state) write(height uint64) error {
	return errors.Join(
		s.writeBlocks(),
		s.writeTXs(),
		s.writeMetadata(height),
	)
}

func (s *state) writeBlocks() error {
	for blkID, blk := range s.addedBlocks {
		blkID := blkID
		blkBytes := blk.Bytes()
		blkHeight := blk.Height()
		heightKey := database.PackUInt64(blkHeight)

		delete(s.addedBlockIDs, blkHeight)
		s.blockIDCache.Put(blkHeight, blkID)
		if err := database.PutID(s.blockIDDB, heightKey, blkID); err != nil {
			return fmt.Errorf("failed to add blockID: %w", err)
		}

		delete(s.addedBlocks, blkID)
		// Note: Evict is used rather than Put here because blk may end up
		// referencing additional data (because of shared byte slices) that
		// would not be properly accounted for in the cache sizing.
		s.blockCache.Evict(blkID)
		if err := s.blockDB.Put(blkID[:], blkBytes); err != nil {
			return fmt.Errorf("failed to write block %s: %w", blkID, err)
		}
	}
	return nil
}

func (s *state) writeTXs() error {
	for txID, txStatus := range s.addedTxs {
		txID := txID

		stx := txBytesAndStatus{
			Tx:     txStatus.tx.Bytes(),
			Status: txStatus.status,
		}

		txBytes, err := txs.Codec.Marshal(txs.CodecVersion, &stx)
		if err != nil {
			return fmt.Errorf("failed to serialize tx: %w", err)
		}

		delete(s.addedTxs, txID)
		// Note: Evict is used rather than Put here because stx may end up
		// referencing additional data (because of shared byte slices) that
		// would not be properly accounted for in the cache sizing.
		s.txCache.Evict(txID)
		if err := s.txDB.Put(txID[:], txBytes); err != nil {
			return fmt.Errorf("failed to add tx: %w", err)
		}
	}
	return nil
}

func (s *state) writeMetadata(height uint64) error {
	if !s.persistedTimestamp.Equal(s.timestamp) {
		if err := database.PutTimestamp(s.singletonDB, TimestampKey, s.timestamp); err != nil {
			return fmt.Errorf("failed to write timestamp: %w", err)
		}
		s.persistedTimestamp = s.timestamp
	}

	if s.persistedLastAccepted != s.lastAccepted {
		if err := database.PutID(s.singletonDB, LastAcceptedKey, s.lastAccepted); err != nil {
			return fmt.Errorf("failed to write last accepted: %w", err)
		}
		s.persistedLastAccepted = s.lastAccepted
	}

	return nil
}
