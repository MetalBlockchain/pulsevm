package state

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/MetalBlockchain/metalgo/cache"
	"github.com/MetalBlockchain/metalgo/cache/metercacher"
	"github.com/MetalBlockchain/metalgo/database"
	"github.com/MetalBlockchain/metalgo/database/prefixdb"
	"github.com/MetalBlockchain/metalgo/database/versiondb"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/account"
	"github.com/MetalBlockchain/pulsevm/chain/authority"
	"github.com/MetalBlockchain/pulsevm/chain/block"
	"github.com/MetalBlockchain/pulsevm/chain/config"
	"github.com/MetalBlockchain/pulsevm/chain/contract"
	"github.com/MetalBlockchain/pulsevm/chain/name"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/MetalBlockchain/pulsevm/status"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	txCacheSize      = 8192
	blockIDCacheSize = 8192
	blockCacheSize   = 2048
	accountCacheSize = 8192
)

var (
	_ State = (*state)(nil)

	ErrMissingParentState = errors.New("missing parent state")

	SingletonPrefix  = []byte("singleton")
	BlockIDPrefix    = []byte("blockID")
	BlockPrefix      = []byte("block")
	TxPrefix         = []byte("tx")
	AccountPrefix    = []byte("account")
	PermissionPrefix = []byte("permission")
	CodePrefix       = []byte("code")

	isInitializedKey = []byte{0x00}
	timestampKey     = []byte{0x01}
	lastAcceptedKey  = []byte{0x02}
)

type ReadOnlyChain interface {
	GetTx(txID ids.ID) (*txs.Tx, error)
	GetBlockIDAtHeight(height uint64) (ids.ID, error)
	GetBlock(blkID ids.ID) (block.Block, error)
	GetLastAccepted() ids.ID
	GetTimestamp() time.Time
	GetAccount(name name.Name) (*account.Account, error)
	GetPermission(owner name.Name, name name.Name) (*authority.Permission, error)
	GetCode(codeHash ids.ID) (*contract.Code, error)
}

type Chain interface {
	ReadOnlyChain

	AddTx(tx *txs.Tx)
	AddBlock(block block.Block)
	ModifyAccount(account *account.Account)
	AddPermission(permission *authority.Permission)
	SetLastAccepted(blkID ids.ID)
	SetTimestamp(t time.Time)
	ModifyCode(code *contract.Code)
}

type State interface {
	Chain

	Initialize(genesisTimestamp time.Time) error
	IsInitialized() (bool, error)
	SetInitialized() error

	// Discard uncommitted changes to the database.
	Abort()

	// Commit changes to the base database.
	Commit() error

	// Returns a batch of unwritten changes that, when written, will commit all
	// pending changes to the base database.
	CommitBatch() (database.Batch, error)

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
	parser block.Parser
	db     *versiondb.Database

	// [lastAccepted] is the most recently accepted block.
	lastAccepted, persistedLastAccepted ids.ID

	currentHeight uint64

	addedBlocks map[ids.ID]block.Block            // map of blockID -> Block
	blockCache  cache.Cacher[ids.ID, block.Block] // cache of blockID -> Block; if the entry is nil, it is not in the database
	blockDB     database.Database

	addedBlockIDs map[uint64]ids.ID            // map of height -> blockID
	blockIDCache  cache.Cacher[uint64, ids.ID] // cache of height -> blockID; if the entry is ids.Empty, it is not in the database
	blockIDDB     database.Database

	addedTxs map[ids.ID]*txs.Tx            // map of txID -> *txs.Tx
	txCache  cache.Cacher[ids.ID, *txs.Tx] // cache of txID -> *txs.Tx. If the entry is nil, it is not in the database
	txDB     database.Database

	modifiedAccounts map[name.Name]*account.Account
	accountCache     cache.Cacher[name.Name, *account.Account]
	accountDB        database.Database

	modifiedPermissions map[ids.ID]*authority.Permission
	permissionCache     cache.Cacher[ids.ID, *authority.Permission]
	permissionDB        database.Database

	modifiedCodes map[ids.ID]*contract.Code
	codeCache     cache.Cacher[ids.ID, *contract.Code]
	codeDB        database.Database

	singletonDB database.Database

	timestamp, persistedTimestamp time.Time
}

func New(
	db *versiondb.Database,
	parser block.Parser,
	genesisBytes []byte,
	metrics prometheus.Registerer,
	execCfg *config.Config,
) (State, error) {
	blockIDCache, err := metercacher.New[uint64, ids.ID](
		"block_id_cache",
		metrics,
		&cache.LRU[uint64, ids.ID]{Size: blockIDCacheSize},
	)
	if err != nil {
		return nil, err
	}

	blockCache, err := metercacher.New[ids.ID, block.Block](
		"block_cache",
		metrics,
		&cache.LRU[ids.ID, block.Block]{Size: blockCacheSize},
	)
	if err != nil {
		return nil, err
	}

	txCache, err := metercacher.New[ids.ID, *txs.Tx](
		"tx_cache",
		metrics,
		&cache.LRU[ids.ID, *txs.Tx]{Size: txCacheSize},
	)
	if err != nil {
		return nil, err
	}

	accountCache, err := metercacher.New[name.Name, *account.Account](
		"account_cache",
		metrics,
		&cache.LRU[name.Name, *account.Account]{Size: accountCacheSize},
	)
	if err != nil {
		return nil, err
	}

	permissionCache, err := metercacher.New[ids.ID, *authority.Permission](
		"permission_cache",
		metrics,
		&cache.LRU[ids.ID, *authority.Permission]{Size: accountCacheSize}, // TODO: Change this
	)
	if err != nil {
		return nil, err
	}

	codeCache, err := metercacher.New[ids.ID, *contract.Code](
		"code_cache",
		metrics,
		&cache.LRU[ids.ID, *contract.Code]{Size: accountCacheSize}, // TODO: Change this
	)
	if err != nil {
		return nil, err
	}

	s := &state{
		parser: parser,
		db:     db,

		addedBlockIDs: make(map[uint64]ids.ID),
		blockIDCache:  blockIDCache,
		blockIDDB:     prefixdb.New(BlockIDPrefix, db),

		addedBlocks: make(map[ids.ID]block.Block),
		blockCache:  blockCache,
		blockDB:     prefixdb.New(BlockPrefix, db),

		addedTxs: make(map[ids.ID]*txs.Tx),
		txDB:     prefixdb.New(TxPrefix, db),
		txCache:  txCache,

		modifiedAccounts: make(map[name.Name]*account.Account),
		accountCache:     accountCache,
		accountDB:        prefixdb.New(AccountPrefix, db),

		modifiedPermissions: make(map[ids.ID]*authority.Permission),
		permissionCache:     permissionCache,
		permissionDB:        prefixdb.New(PermissionPrefix, db),

		modifiedCodes: make(map[ids.ID]*contract.Code),
		codeCache:     codeCache,
		codeDB:        prefixdb.New(CodePrefix, db),

		singletonDB: prefixdb.New(SingletonPrefix, db),
	}

	return s, nil
}

func (s *state) Initialize(genesisTimestamp time.Time) error {
	lastAccepted, err := database.GetID(s.singletonDB, lastAcceptedKey)
	if err == database.ErrNotFound {
		return s.initializeChainState(genesisTimestamp)
	} else if err != nil {
		return err
	}

	s.lastAccepted = lastAccepted
	s.persistedLastAccepted = lastAccepted
	s.timestamp, err = database.GetTimestamp(s.singletonDB, timestampKey)
	s.persistedTimestamp = s.timestamp
	return err
}

func (s *state) initializeChainState(genesisTimestamp time.Time) error {
	genesis, err := block.NewStandardBlock(
		ids.Empty,
		0,
		genesisTimestamp,
		nil,
	)
	if err != nil {
		return err
	}

	activePermissionID, err := authority.GetPermissionID(name.NewNameFromString("pulse"), name.NewNameFromString("active"))
	if err != nil {
		return err
	}

	keyBytes, _ := hex.DecodeString("583c0d52964a8faae88969c33e1cbc4a96f8ac9c5ca89e1e97aff3190d9b397d")
	key, _ := secp256k1.ToPrivateKey(keyBytes)
	s.ModifyAccount(&account.Account{
		Name:       name.NewNameFromString("pulse"),
		Priviliged: true,
	})
	s.AddPermission(&authority.Permission{
		ID:     activePermissionID,
		Parent: ids.Empty,
		Owner:  name.NewNameFromString("pulse"),
		Name:   name.NewNameFromString("active"),
		Auth: authority.Authority{
			Threshold: 1,
			Keys: []authority.KeyWeight{
				{
					Key:    *key.PublicKey(),
					Weight: 1,
				},
			},
		},
	})
	s.SetLastAccepted(genesis.ID())
	s.SetTimestamp(genesis.Timestamp())
	s.AddBlock(genesis)
	return s.Commit()
}

func (s *state) IsInitialized() (bool, error) {
	return s.singletonDB.Has(isInitializedKey)
}

func (s *state) SetInitialized() error {
	return s.singletonDB.Put(isInitializedKey, nil)
}

func (s *state) GetLastAccepted() ids.ID {
	return s.lastAccepted
}

func (s *state) SetLastAccepted(lastAccepted ids.ID) {
	s.lastAccepted = lastAccepted
}

func (s *state) GetTimestamp() time.Time {
	return s.timestamp
}

func (s *state) SetTimestamp(t time.Time) {
	s.timestamp = t
}

func (s *state) AddBlock(block block.Block) {
	blkID := block.ID()
	s.addedBlockIDs[block.Height()] = blkID
	s.addedBlocks[blkID] = block
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

func (s *state) GetBlock(blkID ids.ID) (block.Block, error) {
	if blk, exists := s.addedBlocks[blkID]; exists {
		return blk, nil
	}
	if blk, cached := s.blockCache.Get(blkID); cached {
		if blk == nil {
			return nil, database.ErrNotFound
		}

		return blk, nil
	}

	blkBytes, err := s.blockDB.Get(blkID[:])
	if err == database.ErrNotFound {
		s.blockCache.Put(blkID, nil)
		return nil, database.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	blk, err := s.parser.ParseBlock(blkBytes)
	if err != nil {
		return nil, err
	}

	s.blockCache.Put(blkID, blk)
	return blk, nil
}

func (s *state) AddTx(tx *txs.Tx) {
	txID := tx.ID()
	s.addedTxs[txID] = tx
}

func (s *state) GetTx(txID ids.ID) (*txs.Tx, error) {
	if tx, exists := s.addedTxs[txID]; exists {
		return tx, nil
	}
	if tx, exists := s.txCache.Get(txID); exists {
		if tx == nil {
			return nil, database.ErrNotFound
		}
		return tx, nil
	}

	txBytes, err := s.txDB.Get(txID[:])
	if err == database.ErrNotFound {
		s.txCache.Put(txID, nil)
		return nil, database.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	// The key was in the database
	tx, err := s.parser.ParseGenesisTx(txBytes)
	if err != nil {
		return nil, err
	}

	s.txCache.Put(txID, tx)
	return tx, nil
}

func (s *state) ModifyAccount(account *account.Account) {
	s.modifiedAccounts[account.Name] = account
}

func (s *state) GetAccount(name name.Name) (*account.Account, error) {
	if acc, exists := s.modifiedAccounts[name]; exists {
		return acc, nil
	}
	if acc, exists := s.accountCache.Get(name); exists {
		if acc == nil {
			return nil, database.ErrNotFound
		}
		return acc, nil
	}

	accBytes, err := s.accountDB.Get(name.Bytes())
	if err == database.ErrNotFound {
		s.accountCache.Put(name, nil)
		return nil, database.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	// The key was in the database
	var acc account.Account
	if err := acc.Unmarshal(&wrappers.Packer{
		Bytes: accBytes,
	}); err != nil {
		return nil, err
	}

	s.accountCache.Put(name, &acc)
	return &acc, nil
}

func (s *state) AddPermission(permission *authority.Permission) {
	s.modifiedPermissions[permission.ID] = permission
}

func (s *state) GetPermission(owner name.Name, name name.Name) (*authority.Permission, error) {
	id, err := authority.GetPermissionID(owner, name)
	if err != nil {
		return nil, err
	}

	if perm, exists := s.modifiedPermissions[id]; exists {
		return perm, nil
	}
	if perm, exists := s.permissionCache.Get(id); exists {
		return perm, nil
	}

	permBytes, err := s.permissionDB.Get(id[:])
	if err == database.ErrNotFound {
		s.permissionCache.Put(id, nil)
		return nil, database.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	// The key was in the database
	var perm authority.Permission
	err = perm.Unmarshal(&wrappers.Packer{
		Bytes: permBytes,
	})
	if err != nil {
		return nil, err
	}

	s.permissionCache.Put(id, &perm)
	return &perm, nil
}

func (s *state) GetCode(codeHash ids.ID) (*contract.Code, error) {
	if code, exists := s.modifiedCodes[codeHash]; exists {
		return code, nil
	}
	if code, exists := s.codeCache.Get(codeHash); exists {
		return code, nil
	}

	codeBytes, err := s.codeDB.Get(codeHash[:])
	if err == database.ErrNotFound {
		s.codeCache.Put(codeHash, nil)
		return nil, database.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	// The key was in the database
	var code contract.Code
	err = code.Unmarshal(&wrappers.Packer{
		Bytes: codeBytes,
	})
	if err != nil {
		return nil, err
	}

	s.codeCache.Put(codeHash, &code)
	return &code, nil
}

func (s *state) ModifyCode(code *contract.Code) {
	s.modifiedCodes[code.Hash] = code
}

func (s *state) Abort() {
	s.db.Abort()
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
	if err := s.write(); err != nil {
		return nil, err
	}
	return s.db.CommitBatch()
}

func (s *state) Close() error {
	return errors.Join(
		s.txDB.Close(),
		s.blockIDDB.Close(),
		s.blockDB.Close(),
		s.singletonDB.Close(),
		s.accountDB.Close(),
		s.permissionDB.Close(),
		s.codeDB.Close(),
		s.db.Close(),
	)
}

func (s *state) write() error {
	return errors.Join(
		s.writeTxs(),
		s.writeBlockIDs(),
		s.writeBlocks(),
		s.writeAccounts(),
		s.writeMetadata(),
		s.writePermissions(),
		s.writeCodes(),
	)
}

func (s *state) writeTxs() error {
	for txID, tx := range s.addedTxs {
		txID := txID
		txBytes := tx.Bytes()

		delete(s.addedTxs, txID)
		s.txCache.Put(txID, tx)
		if err := s.txDB.Put(txID[:], txBytes); err != nil {
			return fmt.Errorf("failed to add tx: %w", err)
		}
	}
	return nil
}

func (s *state) writeBlockIDs() error {
	for height, blkID := range s.addedBlockIDs {
		heightKey := database.PackUInt64(height)

		delete(s.addedBlockIDs, height)
		s.blockIDCache.Put(height, blkID)
		if err := database.PutID(s.blockIDDB, heightKey, blkID); err != nil {
			return fmt.Errorf("failed to add blockID: %w", err)
		}
	}
	return nil
}

func (s *state) writeBlocks() error {
	for blkID, blk := range s.addedBlocks {
		blkID := blkID
		blkBytes := blk.Bytes()

		delete(s.addedBlocks, blkID)
		s.blockCache.Put(blkID, blk)
		if err := s.blockDB.Put(blkID[:], blkBytes); err != nil {
			return fmt.Errorf("failed to add block: %w", err)
		}
	}
	return nil
}

func (s *state) writeAccounts() error {
	for name, account := range s.modifiedAccounts {
		delete(s.modifiedAccounts, name)
		s.accountCache.Put(name, account)
		accountBytes, err := account.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
		if err != nil {
			return err
		}
		if err := s.accountDB.Put(name.Bytes(), accountBytes); err != nil {
			return fmt.Errorf("failed to add account: %w", err)
		}
	}
	return nil
}

func (s *state) writePermissions() error {
	for id, perm := range s.modifiedPermissions {
		delete(s.modifiedPermissions, id)
		s.permissionCache.Put(id, perm)
		permBytes, err := perm.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
		if err != nil {
			return err
		}
		if err := s.permissionDB.Put(id[:], permBytes); err != nil {
			return fmt.Errorf("failed to add permission: %w", err)
		}
	}
	return nil
}

func (s *state) writeCodes() error {
	for id, code := range s.modifiedCodes {
		delete(s.modifiedCodes, id)
		s.codeCache.Put(id, code)
		codeBytes, err := code.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
		if err != nil {
			return err
		}
		if err := s.codeDB.Put(id[:], codeBytes); err != nil {
			return fmt.Errorf("failed to add code: %w", err)
		}
	}
	return nil
}

func (s *state) writeMetadata() error {
	if !s.persistedTimestamp.Equal(s.timestamp) {
		if err := database.PutTimestamp(s.singletonDB, timestampKey, s.timestamp); err != nil {
			return fmt.Errorf("failed to write timestamp: %w", err)
		}
		s.persistedTimestamp = s.timestamp
	}
	if s.persistedLastAccepted != s.lastAccepted {
		if err := database.PutID(s.singletonDB, lastAcceptedKey, s.lastAccepted); err != nil {
			return fmt.Errorf("failed to write last accepted: %w", err)
		}
		s.persistedLastAccepted = s.lastAccepted
	}
	return nil
}
