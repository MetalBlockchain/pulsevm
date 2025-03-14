package state

import (
	"fmt"
	"time"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/pulsevm/chain/account"
	"github.com/MetalBlockchain/pulsevm/chain/authority"
	"github.com/MetalBlockchain/pulsevm/chain/block"
	"github.com/MetalBlockchain/pulsevm/chain/contract"
	"github.com/MetalBlockchain/pulsevm/chain/name"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
)

var (
	_ Diff     = (*diff)(nil)
	_ Versions = stateGetter{}
)

type Diff interface {
	Chain

	Apply(Chain) error
}

type diff struct {
	parentID      ids.ID
	stateVersions Versions

	addedTxs            map[ids.ID]*txs.Tx               // map of txID -> tx
	addedBlockIDs       map[uint64]ids.ID                // map of height -> blockID
	addedBlocks         map[ids.ID]block.Block           // map of blockID -> block
	modifiedAccounts    map[name.Name]*account.Account   // map of name -> account
	modifiedPermissions map[ids.ID]*authority.Permission // map of ID -> permission
	modifiedCodes       map[ids.ID]*contract.Code        // map of ID -> code

	lastAccepted ids.ID
	timestamp    time.Time
}

func NewDiff(
	parentID ids.ID,
	stateVersions Versions,
) (Diff, error) {
	parentState, ok := stateVersions.GetState(parentID)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMissingParentState, parentID)
	}
	return &diff{
		parentID:      parentID,
		stateVersions: stateVersions,

		addedTxs:            make(map[ids.ID]*txs.Tx),
		addedBlockIDs:       make(map[uint64]ids.ID),
		addedBlocks:         make(map[ids.ID]block.Block),
		modifiedAccounts:    make(map[name.Name]*account.Account),
		modifiedPermissions: make(map[ids.ID]*authority.Permission),
		modifiedCodes:       make(map[ids.ID]*contract.Code),

		lastAccepted: parentState.GetLastAccepted(),
		timestamp:    parentState.GetTimestamp(),
	}, nil
}

type stateGetter struct {
	state Chain
}

func (s stateGetter) GetState(ids.ID) (Chain, bool) {
	return s.state, true
}

func NewDiffOn(parentState Chain) (Diff, error) {
	return NewDiff(ids.Empty, stateGetter{
		state: parentState,
	})
}

func (d *diff) GetTx(txID ids.ID) (*txs.Tx, error) {
	if tx, exists := d.addedTxs[txID]; exists {
		return tx, nil
	}

	parentState, ok := d.stateVersions.GetState(d.parentID)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMissingParentState, d.parentID)
	}
	return parentState.GetTx(txID)
}

func (d *diff) AddTx(tx *txs.Tx) {
	d.addedTxs[tx.ID()] = tx
}

func (d *diff) GetAccount(name name.Name) (*account.Account, error) {
	if account, exists := d.modifiedAccounts[name]; exists {
		return account, nil
	}

	parentState, ok := d.stateVersions.GetState(d.parentID)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMissingParentState, d.parentID)
	}
	return parentState.GetAccount(name)
}

func (d *diff) ModifyAccount(account *account.Account) {
	d.modifiedAccounts[account.Name] = account
}

func (d *diff) AddPermission(permission *authority.Permission) {
	d.modifiedPermissions[permission.ID] = permission
}

func (d *diff) GetPermission(owner name.Name, name name.Name) (*authority.Permission, error) {
	id, err := authority.GetPermissionID(owner, name)
	if err != nil {
		return nil, err
	}

	if perm, exists := d.modifiedPermissions[id]; exists {
		return perm, nil
	}

	parentState, ok := d.stateVersions.GetState(d.parentID)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMissingParentState, d.parentID)
	}
	return parentState.GetPermission(owner, name)
}

func (d *diff) GetCode(codeHash ids.ID) (*contract.Code, error) {
	if code, exists := d.modifiedCodes[codeHash]; exists {
		return code, nil
	}

	parentState, ok := d.stateVersions.GetState(d.parentID)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMissingParentState, d.parentID)
	}
	return parentState.GetCode(codeHash)
}

func (d *diff) ModifyCode(code *contract.Code) {
	d.modifiedCodes[code.Hash] = code
}

func (d *diff) GetBlockIDAtHeight(height uint64) (ids.ID, error) {
	if blkID, exists := d.addedBlockIDs[height]; exists {
		return blkID, nil
	}

	parentState, ok := d.stateVersions.GetState(d.parentID)
	if !ok {
		return ids.Empty, fmt.Errorf("%w: %s", ErrMissingParentState, d.parentID)
	}
	return parentState.GetBlockIDAtHeight(height)
}

func (d *diff) GetBlock(blkID ids.ID) (block.Block, error) {
	if blk, exists := d.addedBlocks[blkID]; exists {
		return blk, nil
	}

	parentState, ok := d.stateVersions.GetState(d.parentID)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMissingParentState, d.parentID)
	}
	return parentState.GetBlock(blkID)
}

func (d *diff) AddBlock(blk block.Block) {
	blkID := blk.ID()
	d.addedBlockIDs[blk.Height()] = blkID
	d.addedBlocks[blkID] = blk
}

func (d *diff) GetLastAccepted() ids.ID {
	return d.lastAccepted
}

func (d *diff) SetLastAccepted(lastAccepted ids.ID) {
	d.lastAccepted = lastAccepted
}

func (d *diff) GetTimestamp() time.Time {
	return d.timestamp
}

func (d *diff) SetTimestamp(t time.Time) {
	d.timestamp = t
}

func (d *diff) Apply(baseState Chain) error {
	for _, tx := range d.addedTxs {
		baseState.AddTx(tx)
	}
	for _, account := range d.modifiedAccounts {
		baseState.ModifyAccount(account)
	}
	for _, permission := range d.modifiedPermissions {
		baseState.AddPermission(permission)
	}
	for _, code := range d.modifiedCodes {
		baseState.ModifyCode(code)
	}
	for _, blk := range d.addedBlocks {
		baseState.AddBlock(blk)
	}
	baseState.SetLastAccepted(d.lastAccepted)
	baseState.SetTimestamp(d.timestamp)
	return nil
}
