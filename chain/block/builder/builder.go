package builder

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/MetalBlockchain/metalgo/snow/consensus/snowman"
	smblock "github.com/MetalBlockchain/metalgo/snow/engine/snowman/block"
	"github.com/MetalBlockchain/pulsevm/chain/txs/mempool"
	"github.com/MetalBlockchain/pulsevm/state"
	"go.uber.org/zap"

	blockexecutor "github.com/MetalBlockchain/pulsevm/chain/block/executor"
	txexecutor "github.com/MetalBlockchain/pulsevm/chain/txs/executor"
)

var (
	_ Builder = (*builder)(nil)

	errMissingPreferredState = errors.New("missing preferred block state")
)

type Builder interface {
	// StartBlockTimer starts to issue block creation requests to advance the
	// chain timestamp.
	StartBlockTimer()

	// BuildBlock can be called to attempt to create a new block
	BuildBlock(context.Context) (snowman.Block, error)
}

// builder implements a simple builder to convert txs into valid blocks
type builder struct {
	mempool.Mempool

	txExecutorBackend *txexecutor.Backend
	blkManager        blockexecutor.Manager

	// resetTimer is used to signal that the block builder timer should update
	// when it will trigger building of a block.
	resetTimer chan struct{}
	closed     chan struct{}
	closeOnce  sync.Once
}

func New(
	mempool mempool.Mempool,
) Builder {
	return &builder{
		Mempool:    mempool,
		resetTimer: make(chan struct{}, 1),
		closed:     make(chan struct{}),
	}
}

func (b *builder) StartBlockTimer() {
	go func() {
		timer := time.NewTimer(0)
		defer timer.Stop()

		for {
			// Invariant: The [timer] is not stopped.
			select {
			case <-timer.C:
			case <-b.resetTimer:
				if !timer.Stop() {
					<-timer.C
				}
			case <-b.closed:
				return
			}

			// Note: Because the context lock is not held here, it is possible
			// that [ShutdownBlockTimer] is called concurrently with this
			// execution.
			for {
				duration, err := b.durationToSleep()
				if err != nil {
					b.txExecutorBackend.Ctx.Log.Error("block builder encountered a fatal error",
						zap.Error(err),
					)
					return
				}

				if duration > 0 {
					timer.Reset(duration)
					break
				}

				// Block needs to be issued to advance time.
				b.Mempool.RequestBuildBlock(true /*=emptyBlockPermitted*/)

				// Invariant: ResetBlockTimer is guaranteed to be called after
				// [durationToSleep] returns a value <= 0. This is because we
				// are guaranteed to attempt to build block. After building a
				// valid block, the chain will have its preference updated which
				// may change the duration to sleep and trigger a timer reset.
				select {
				case <-b.resetTimer:
				case <-b.closed:
					return
				}
			}
		}
	}()
}

func (b *builder) durationToSleep() (time.Duration, error) {
	// Grabbing the lock here enforces that this function is not called mid-way
	// through modifying of the state.
	b.txExecutorBackend.Ctx.Lock.Lock()
	defer b.txExecutorBackend.Ctx.Lock.Unlock()

	// If [ShutdownBlockTimer] was called, we want to exit the block timer
	// goroutine. We check this with the context lock held because
	// [ShutdownBlockTimer] is expected to only be called with the context lock
	// held.
	select {
	case <-b.closed:
		return 0, nil
	default:
	}

	preferredID := b.blkManager.Preferred()
	_, ok := b.blkManager.GetState(preferredID)
	if !ok {
		return 0, fmt.Errorf("%w: %s", errMissingPreferredState, preferredID)
	}

	return time.Millisecond * 500, nil
}

func (b *builder) ResetBlockTimer() {
	// Ensure that the timer will be reset at least once.
	select {
	case b.resetTimer <- struct{}{}:
	default:
	}
}

func (b *builder) ShutdownBlockTimer() {
	b.closeOnce.Do(func() {
		close(b.closed)
	})
}

func (b *builder) BuildBlock(ctx context.Context) (snowman.Block, error) {
	return b.BuildBlockWithContext(
		ctx,
		&smblock.Context{
			PChainHeight: 0,
		},
	)
}

func (b *builder) BuildBlockWithContext(
	ctx context.Context,
	blockContext *smblock.Context,
) (snowman.Block, error) {
	// If there are still transactions in the mempool, then we need to
	// re-trigger block building.
	defer b.Mempool.RequestBuildBlock(false /*=emptyBlockPermitted*/)

	b.txExecutorBackend.Ctx.Log.Debug("starting to attempt to build a block")

	// Get the block to build on top of and retrieve the new block's context.
	preferredID := b.blkManager.Preferred()
	preferred, err := b.blkManager.GetBlock(preferredID)
	if err != nil {
		return nil, err
	}
	nextHeight := preferred.Height() + 1
	preferredState, ok := b.blkManager.GetState(preferredID)
	if !ok {
		return nil, fmt.Errorf("%w: %s", state.ErrMissingParentState, preferredID)
	}

	timestamp, timeWasCapped, err := state.NextBlockTime(
		b.txExecutorBackend.Config.ValidatorFeeConfig,
		preferredState,
		b.txExecutorBackend.Clk,
	)
	if err != nil {
		return nil, fmt.Errorf("could not calculate next staker change time: %w", err)
	}

	statelessBlk, err := buildBlock(
		ctx,
		b,
		preferredID,
		nextHeight,
		timestamp,
		timeWasCapped,
		preferredState,
		blockContext.PChainHeight,
	)
	if err != nil {
		return nil, err
	}

	return b.blkManager.NewBlock(statelessBlk), nil
}
